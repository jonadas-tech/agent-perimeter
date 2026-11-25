"""100% passive, read-only in-memory static package analyzer for npm tarballs and PyPI wheels/sdists.

Strictly non-executing: fetches public registry metadata and archive bytes into io.BytesIO
(with strict byte caps), inspects package.json / pyproject.toml / source text in memory,
and flags strictly factual, verifiable supply-chain risk patterns.
"""

from __future__ import annotations

import io
import json
import re
import tarfile
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
import zipfile

from .http_client import PoliteHttpClient

MAX_TARBALL_BYTES = 5 * 1024 * 1024  # 5 MB strict cap per archive
MAX_TEXT_FILE_BYTES = 262144         # 256 KB per inspected source file
MAX_FILES_INSPECTED = 60

# Strictly factual static indicators
LIFECYCLE_HOOK_KEYS = ("preinstall", "install", "postinstall", "prepare")

REMOTE_FETCH_RE = re.compile(
    r"(https?://(?:github\.com/[^\s\"'`]+/releases/download|raw\.githubusercontent\.com|[^\s\"'`]+\.(?:tar\.gz|tgz|zip|exe|bin|sh)))"
    r"|\b(curl|wget|Invoke-WebRequest|urllib\.request|axios\.get|fetch\()\b",
    re.IGNORECASE,
)

INTEGRITY_CHECK_RE = re.compile(
    r"\b(sha256|sha512|createHash|hashlib|checksum|shasum|verifySignature|cosign|gpg)\b",
    re.IGNORECASE,
)

DORMANT_STUB_RE = re.compile(
    r"(status\s*:\s*['\"]coming[-_\s]?soon['\"]|coming\s+soon|placeholder\s+package|reserved\s+for\s+future)",
    re.IGNORECASE,
)

SESSION_COOKIE_EVASION_RE = re.compile(
    r"(SLACK_MCP_XOX[CD]_TOKEN|xoxc-|xoxd-|browser\s+session\s+cookie|without\s+(?:admin|workspace)\s+approval)",
    re.IGNORECASE,
)

ANTIBOT_EVASION_RE = re.compile(
    r"\b(patchright|playwright-extra|puppeteer-extra-plugin-stealth|undetected[_-]chromedriver|curl_cffi|impersonate\s*=\s*['\"]chrome|akamai\s+bot\s+manager)\b",
    re.IGNORECASE,
)

SHELL_EXEC_RE = re.compile(
    r"\b(child_process|execSync|execFileSync|spawnSync|os\.system|subprocess\.(?:Popen|run|call|check_output))\b",
    re.IGNORECASE,
)

SUSPICIOUS_TOOL_PROMPT_RE = re.compile(
    r"(<\s*IMPORTANT\s*>|ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions"
    r"|do\s+not\s+(?:tell|inform|mention\s+to)\s+the\s+user"
    r"|before\s+(?:calling|using|running)\s+this\s+tool.{0,80}(?:read|send|exfiltrate|pass|include)\s+(?:~|ssh|env|token|secret|key|credential))",
    re.IGNORECASE | re.DOTALL,
)

UNICODE_TAG_RE = re.compile(r"[\U000E0000-\U000E007F]")

TEXT_EXTENSIONS = (".js", ".mjs", ".cjs", ".ts", ".py", ".json", ".toml", ".md", ".txt", ".sh")

# Benign build-only lifecycle scripts (TypeScript / standard build steps, not remote downloaders)
BENIGN_HOOK_RE = re.compile(
    r"^(?:tsc|npm run build|pnpm build|yarn build|tsup|esbuild|rollup|vite build|chmod \+x [^\s;&|]+)$",
    re.IGNORECASE,
)


def _extract_npm_repo_url(repo: Any) -> str:
    if isinstance(repo, dict):
        return str(repo.get("url") or "").strip()
    if isinstance(repo, str):
        return repo.strip()
    return ""


def _read_tarball_bytes(client: PoliteHttpClient, url: str) -> Tuple[Optional[bytes], Optional[str]]:
    """Fetch binary archive passively into memory with strict 5 MB byte cap."""
    import socket
    import ssl
    import time
    import urllib.error
    import urllib.request

    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower()
    client._wait_rate_limit(host, min_interval_override=0.10)
    client._record_stat(host, "tarball_requests")

    req = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": client.user_agent, "Accept": "*/*"},
    )
    deadline = time.monotonic() + 12.0
    try:
        with urllib.request.urlopen(req, timeout=8.0) as resp:
            cl = resp.headers.get("Content-Length")
            if cl and cl.isdigit() and int(cl) > MAX_TARBALL_BYTES:
                return None, f"exceeds_max_bytes ({int(cl)})"
            chunks: List[bytes] = []
            total = 0
            while total <= MAX_TARBALL_BYTES:
                if time.monotonic() > deadline:
                    return None, "tarball_deadline_exceeded"
                chunk = resp.read(32768)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            if total > MAX_TARBALL_BYTES:
                return None, f"exceeds_max_bytes (>{MAX_TARBALL_BYTES})"
            return b"".join(chunks), None
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, TimeoutError, ssl.SSLError, OSError) as e:
        return None, f"{type(e).__name__}: {e}"


def _inspect_text_files(
    files: List[Tuple[str, str]],
    pkg_name: str,
    target_brand: str,
    lifecycle_scripts: Dict[str, str],
    bin_names: List[str],
    repo_url: str,
) -> Dict[str, Any]:
    """Run deterministic static pattern extraction across in-memory file contents."""
    total_code_bytes = 0
    code_files = 0
    dormant_stub = False
    stub_evidence: Optional[str] = None
    unverified_remote_postinstall = False
    postinstall_evidence: List[str] = []
    session_evasion: List[str] = []
    antibot_evasion: List[str] = []
    shell_exec_files: List[str] = []
    suspicious_prompt_hits: List[Dict[str, str]] = []
    unicode_tag_files: List[str] = []
    opaque_minified_bundle = False
    modifies_agent_config: List[str] = []

    agent_cfg_re = re.compile(
        r"(\.codex/config\.toml|claude_desktop_config\.json|\.cursor/mcp\.json|\.vscode/mcp\.json|CODEX_HOME)",
        re.IGNORECASE,
    )

    # Check non-benign lifecycle hooks
    non_benign_hooks: Dict[str, str] = {}
    for hk, cmd in lifecycle_scripts.items():
        c = cmd.strip()
        if c and not BENIGN_HOOK_RE.match(c):
            non_benign_hooks[hk] = c

    install_script_targets: List[str] = []
    for hk, cmd in non_benign_hooks.items():
        if hk in ("preinstall", "install", "postinstall"):
            if REMOTE_FETCH_RE.search(cmd) and not INTEGRITY_CHECK_RE.search(cmd):
                unverified_remote_postinstall = True
                postinstall_evidence.append(f"{hk}: {cmd[:140]}")
            # Track referenced script filenames (e.g. `node scripts/install.js`)
            for m in re.finditer(r"([a-z0-9_./-]+\.(?:js|mjs|cjs|sh|py))", cmd, re.IGNORECASE):
                install_script_targets.append(m.group(1).lstrip("./").lower())

    for rel_path, content in files:
        low_path = rel_path.lower()
        is_code = low_path.endswith((".js", ".mjs", ".cjs", ".ts", ".py", ".sh"))
        if is_code:
            code_files += 1
            total_code_bytes += len(content.encode("utf-8", errors="ignore"))
            # Detect large single-line / opaque minified bundle (>200KB with very long lines)
            if len(content) > 200_000:
                lines = content.splitlines()
                if lines and max(len(ln) for ln in lines[:50]) > 4000:
                    opaque_minified_bundle = True

        # Check dormant placeholder stub
        if is_code and len(content) <= 600 and DORMANT_STUB_RE.search(content):
            dormant_stub = True
            stub_evidence = f"{rel_path}: {content.strip()[:140]}"

        # Check postinstall script bodies for unverified remote downloads
        if install_script_targets and any(low_path.endswith(t) for t in install_script_targets):
            if REMOTE_FETCH_RE.search(content) and not INTEGRITY_CHECK_RE.search(content):
                unverified_remote_postinstall = True
                m = REMOTE_FETCH_RE.search(content)
                postinstall_evidence.append(f"{rel_path}: {m.group(0)[:140] if m else 'remote_fetch_without_hash'}")

        if SESSION_COOKIE_EVASION_RE.search(content):
            m = SESSION_COOKIE_EVASION_RE.search(content)
            if len(session_evasion) < 3:
                session_evasion.append(f"{rel_path}: {m.group(0)[:100] if m else ''}")

        if ANTIBOT_EVASION_RE.search(content):
            m = ANTIBOT_EVASION_RE.search(content)
            if len(antibot_evasion) < 3:
                antibot_evasion.append(f"{rel_path}: {m.group(0)[:100] if m else ''}")

        if is_code and SHELL_EXEC_RE.search(content) and len(shell_exec_files) < 5:
            shell_exec_files.append(rel_path)

        if is_code and agent_cfg_re.search(content) and len(modifies_agent_config) < 4:
            m = agent_cfg_re.search(content)
            modifies_agent_config.append(f"{rel_path}: {m.group(0) if m else ''}")

        if is_code and SUSPICIOUS_TOOL_PROMPT_RE.search(content):
            m = SUSPICIOUS_TOOL_PROMPT_RE.search(content)
            if len(suspicious_prompt_hits) < 3:
                suspicious_prompt_hits.append({"file": rel_path, "match": (m.group(0) if m else "")[:160]})

        if UNICODE_TAG_RE.search(content):
            unicode_tag_files.append(rel_path)

    # Check if CLI bin name shadows a different well-known brand/tool name
    brand_low = target_brand.lower()
    unrelated_bins: List[str] = []
    common_benign_bins = {"mcp", "server", "cli", "start", "index", "main", "mcp-server"}
    for b in bin_names:
        bl = b.lower().strip()
        if not bl or bl in common_benign_bins:
            continue
        if brand_low and brand_low not in bl and not bl.startswith(("mcp-", "mcp_")) and not bl.endswith(("-mcp", "_mcp")):
            unrelated_bins.append(bl)

    return {
        "files_inspected": len(files),
        "code_files": code_files,
        "total_code_bytes": total_code_bytes,
        "missing_repository_url": not bool(repo_url),
        "lifecycle_hooks": lifecycle_scripts,
        "non_benign_lifecycle_hooks": non_benign_hooks,
        "unverified_remote_postinstall": unverified_remote_postinstall,
        "postinstall_evidence": postinstall_evidence[:4],
        "dormant_placeholder_stub": dormant_stub,
        "stub_evidence": stub_evidence,
        "bin_names": bin_names[:10],
        "unrelated_cli_bin_shadowing": unrelated_bins[:5],
        "session_cookie_evasion": session_evasion,
        "antibot_evasion": antibot_evasion,
        "shell_exec_files": shell_exec_files,
        "modifies_agent_config": modifies_agent_config,
        "opaque_minified_bundle": opaque_minified_bundle,
        "suspicious_tool_prompt_hits": suspicious_prompt_hits,
        "unicode_tag_files": unicode_tag_files,
    }


def inspect_npm_package_static(
    client: PoliteHttpClient,
    pkg_name: str,
    target_brand: str,
) -> Dict[str, Any]:
    """Passively inspect an npm package's latest version metadata + tarball strictly in memory."""
    encoded = urllib.parse.quote(pkg_name, safe="@")
    meta_resp = client.get(f"https://registry.npmjs.org/{encoded}", timeout=8.0, retries=1)
    if meta_resp.status != 200:
        return {"registry": "npm", "name": pkg_name, "ok": False, "error": meta_resp.error or f"http_{meta_resp.status}"}
    try:
        meta = json.loads(meta_resp.body_text)
    except Exception as e:
        return {"registry": "npm", "name": pkg_name, "ok": False, "error": f"json_error: {e}"}

    latest = (meta.get("dist-tags") or {}).get("latest")
    if not latest or "unpublished" in (meta.get("time") or {}):
        return {"registry": "npm", "name": pkg_name, "ok": False, "error": "unpublished_tombstone"}
    ver_obj = (meta.get("versions") or {}).get(latest) or {}
    dist = ver_obj.get("dist") or {}
    tarball_url = str(dist.get("tarball") or "")
    integrity = dist.get("integrity") or dist.get("shasum")
    maintainers = [
        {"name": m.get("name"), "email": m.get("email")}
        for m in (meta.get("maintainers") or [])
        if isinstance(m, dict)
    ]
    scripts = {
        k: str(v)
        for k, v in (ver_obj.get("scripts") or {}).items()
        if k in LIFECYCLE_HOOK_KEYS and v
    }
    raw_bin = ver_obj.get("bin")
    bin_names: List[str] = []
    if isinstance(raw_bin, dict):
        bin_names = [str(k) for k in raw_bin.keys()]
    elif isinstance(raw_bin, str) and raw_bin:
        bin_names = [pkg_name.split("/")[-1]]
    repo_url = _extract_npm_repo_url(ver_obj.get("repository") or meta.get("repository"))

    if not tarball_url:
        return {"registry": "npm", "name": pkg_name, "version": latest, "ok": False, "error": "no_tarball_url"}

    raw_bytes, err = _read_tarball_bytes(client, tarball_url)
    if err or raw_bytes is None:
        return {
            "registry": "npm",
            "name": pkg_name,
            "version": latest,
            "ok": False,
            "error": err or "empty_tarball",
            "tarball_url": tarball_url,
            "maintainers": maintainers,
            "repository_url": repo_url,
            "lifecycle_hooks": scripts,
        }

    text_files: List[Tuple[str, str]] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode="r:*") as tf:
            for member in tf.getmembers():
                if len(text_files) >= MAX_FILES_INSPECTED:
                    break
                if not member.isfile() or member.size > MAX_TEXT_FILE_BYTES:
                    continue
                if not member.name.lower().endswith(TEXT_EXTENSIONS):
                    continue
                fobj = tf.extractfile(member)
                if fobj is None:
                    continue
                data = fobj.read(MAX_TEXT_FILE_BYTES)
                text_files.append((member.name, data.decode("utf-8", errors="replace")))
    except Exception as e:
        return {"registry": "npm", "name": pkg_name, "version": latest, "ok": False, "error": f"tar_error: {e}"}

    signals = _inspect_text_files(text_files, pkg_name, target_brand, scripts, bin_names, repo_url)
    return {
        "registry": "npm",
        "name": pkg_name,
        "version": latest,
        "ok": True,
        "tarball_url": tarball_url,
        "tarball_bytes": len(raw_bytes),
        "integrity": integrity,
        "maintainers": maintainers,
        "repository_url": repo_url,
        "signals": signals,
    }


def inspect_pypi_package_static(
    client: PoliteHttpClient,
    pkg_name: str,
    target_brand: str,
) -> Dict[str, Any]:
    """Passively inspect a PyPI package's latest wheel/sdist strictly in memory."""
    meta_resp = client.get(f"https://pypi.org/pypi/{urllib.parse.quote(pkg_name)}/json", timeout=8.0, retries=1)
    if meta_resp.status != 200:
        return {"registry": "pypi", "name": pkg_name, "ok": False, "error": meta_resp.error or f"http_{meta_resp.status}"}
    try:
        payload = json.loads(meta_resp.body_text)
    except Exception as e:
        return {"registry": "pypi", "name": pkg_name, "ok": False, "error": f"json_error: {e}"}

    info = payload.get("info") or {}
    version = str(info.get("version") or "")
    proj_urls = info.get("project_urls") or {}
    repo_url = ""
    for k, v in proj_urls.items():
        if v and any(tok in str(k).lower() for tok in ("source", "repo", "github", "code", "home")):
            repo_url = str(v)
            break
    if not repo_url:
        repo_url = str(info.get("home_page") or "")

    urls = payload.get("urls") or []
    chosen = None
    # Prefer universal wheel (zip) then sdist (tar.gz)
    for u in urls:
        if u.get("packagetype") == "bdist_wheel":
            chosen = u
            break
    if chosen is None:
        for u in urls:
            if u.get("packagetype") == "sdist":
                chosen = u
                break
    if not chosen or not chosen.get("url"):
        return {"registry": "pypi", "name": pkg_name, "version": version, "ok": False, "error": "no_download_artifact"}

    art_url = str(chosen["url"])
    sha256 = (chosen.get("digests") or {}).get("sha256")
    raw_bytes, err = _read_tarball_bytes(client, art_url)
    if err or raw_bytes is None:
        return {
            "registry": "pypi",
            "name": pkg_name,
            "version": version,
            "ok": False,
            "error": err or "empty_artifact",
            "artifact_url": art_url,
            "repository_url": repo_url,
        }

    text_files: List[Tuple[str, str]] = []
    bin_names: List[str] = []
    lifecycle_hooks: Dict[str, str] = {}
    try:
        if chosen.get("packagetype") == "bdist_wheel" or art_url.endswith(".whl") or art_url.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                for zi in zf.infolist():
                    if len(text_files) >= MAX_FILES_INSPECTED:
                        break
                    if zi.is_dir() or zi.file_size > MAX_TEXT_FILE_BYTES:
                        continue
                    if zi.filename.endswith("entry_points.txt"):
                        ep_txt = zf.read(zi).decode("utf-8", errors="replace")
                        in_scripts = False
                        for ln in ep_txt.splitlines():
                            s = ln.strip()
                            if s.startswith("["):
                                in_scripts = s.lower() == "[console_scripts]"
                            elif in_scripts and "=" in s:
                                bin_names.append(s.split("=", 1)[0].strip())
                    if not zi.filename.lower().endswith(TEXT_EXTENSIONS):
                        continue
                    text_files.append((zi.filename, zf.read(zi).decode("utf-8", errors="replace")))
        else:
            with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode="r:*") as tf:
                for member in tf.getmembers():
                    if len(text_files) >= MAX_FILES_INSPECTED:
                        break
                    if not member.isfile() or member.size > MAX_TEXT_FILE_BYTES:
                        continue
                    if not member.name.lower().endswith(TEXT_EXTENSIONS):
                        continue
                    fobj = tf.extractfile(member)
                    if fobj is None:
                        continue
                    data = fobj.read(MAX_TEXT_FILE_BYTES).decode("utf-8", errors="replace")
                    if member.name.lower().endswith("setup.py") and ("cmdclass" in data or "install" in data):
                        if REMOTE_FETCH_RE.search(data):
                            lifecycle_hooks["setup.py"] = "custom_setup_remote_fetch"
                    text_files.append((member.name, data))
    except Exception as e:
        return {"registry": "pypi", "name": pkg_name, "version": version, "ok": False, "error": f"archive_error: {e}"}

    signals = _inspect_text_files(text_files, pkg_name, target_brand, lifecycle_hooks, bin_names, repo_url)
    return {
        "registry": "pypi",
        "name": pkg_name,
        "version": version,
        "ok": True,
        "artifact_url": art_url,
        "artifact_bytes": len(raw_bytes),
        "sha256": sha256,
        "author": info.get("author"),
        "author_email": info.get("author_email") or info.get("maintainer_email"),
        "repository_url": repo_url,
        "signals": signals,
    }
