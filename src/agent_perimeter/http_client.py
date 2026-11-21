"""Thread-safe, dependency-free, polite passive HTTP client for agent-perimeter."""

from __future__ import annotations

from dataclasses import dataclass, field
import gzip
from html.parser import HTMLParser
import json
import os
import random
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request
import zlib

from . import __version__

USER_AGENT = f"agent-perimeter/{__version__} (+passive-external-audit; read-only)"


class _TitleExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_title = False
        self._parts: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag.lower() == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._parts.append(data)

    @property
    def title(self) -> str:
        return " ".join("".join(self._parts).split())[:200]


def extract_html_title(html: str) -> str:
    parser = _TitleExtractor()
    try:
        parser.feed(html[:32768])
        return parser.title
    except Exception:
        return ""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


@dataclass
class HttpResponse:
    url: str
    final_url: str
    status: int
    headers: Dict[str, str]
    body_text: str
    redirect_chain: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    elapsed_ms: int = 0


class PoliteHttpClient:
    """Thread-safe passive GET client with per-host rate limiting, hard deadlines, and circuit breakers."""

    HOST_INTERVALS: Dict[str, float] = {
        "registry.modelcontextprotocol.io": 0.15,
        "registry.npmjs.org": 0.12,
        "pypi.org": 0.12,
        "dns.google": 0.03,
        "cloudflare-dns.com": 0.05,
        "api.certspotter.com": 0.45,
        "crt.sh": 1.2,
        "api.github.com": 0.18,
    }

    def __init__(
        self,
        user_agent: str = USER_AGENT,
        github_token: Optional[str] = None,
        certspotter_token: Optional[str] = None,
        enable_github_search: bool = True,
    ) -> None:
        self.user_agent = user_agent
        self.enable_github_search = enable_github_search
        self._last_host_ts: Dict[str, float] = {}
        self._host_locks: Dict[str, threading.Lock] = {}
        self._meta_lock = threading.Lock()
        self.stats: Dict[str, Dict[str, int]] = {}
        self._opener = urllib.request.build_opener(_NoRedirectHandler())
        self.github_token = github_token or self._discover_github_token()
        self.certspotter_token = certspotter_token or os.environ.get("CERTSPOTTER_API_KEY")

        # Circuit breaker states
        self._cb_lock = threading.Lock()
        self._cb_state: Dict[str, Dict[str, float]] = {
            "crt.sh": {"failures": 0, "cooldown_until": 0.0},
            "api.certspotter.com": {"failures": 0, "cooldown_until": 0.0},
        }

    @staticmethod
    def _discover_github_token() -> Optional[str]:
        env_tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if env_tok and env_tok.strip():
            return env_tok.strip()
        gh_bin = shutil.which("gh") or (
            "/opt/homebrew/bin/gh" if os.path.exists("/opt/homebrew/bin/gh") else None
        )
        if not gh_bin:
            return None
        try:
            res = subprocess.run(
                [gh_bin, "auth", "token"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception:
            pass
        return None

    def circuit_is_open(self, key: str) -> bool:
        with self._cb_lock:
            st = self._cb_state.get(key)
            if not st:
                return False
            return time.monotonic() < st["cooldown_until"]

    def circuit_record_failure(self, key: str, threshold: int = 3, cooldown_s: float = 60.0) -> None:
        with self._cb_lock:
            st = self._cb_state.setdefault(key, {"failures": 0, "cooldown_until": 0.0})
            st["failures"] += 1
            if st["failures"] >= threshold:
                st["cooldown_until"] = time.monotonic() + cooldown_s
                st["failures"] = 0

    def circuit_trip(self, key: str, cooldown_s: float = 120.0) -> None:
        with self._cb_lock:
            st = self._cb_state.setdefault(key, {"failures": 0, "cooldown_until": 0.0})
            st["cooldown_until"] = time.monotonic() + cooldown_s
            st["failures"] = 0

    def circuit_record_success(self, key: str) -> None:
        with self._cb_lock:
            st = self._cb_state.get(key)
            if st:
                st["failures"] = 0

    def _get_host_lock(self, key: str) -> threading.Lock:
        with self._meta_lock:
            lk = self._host_locks.get(key)
            if lk is None:
                lk = threading.Lock()
                self._host_locks[key] = lk
            return lk

    def _record_stat(self, bucket: str, metric: str) -> None:
        with self._meta_lock:
            b = self.stats.setdefault(bucket, {})
            b[metric] = b.get(metric, 0) + 1

    def _wait_rate_limit(self, key: str, min_interval_override: Optional[float] = None) -> None:
        min_interval = (
            min_interval_override
            if min_interval_override is not None
            else self.HOST_INTERVALS.get(key, 0.20)
        )
        lk = self._get_host_lock(key)
        with lk:
            now = time.monotonic()
            last = self._last_host_ts.get(key)
            if last is not None:
                wait = min_interval - (now - last)
                if wait > 0:
                    time.sleep(wait)
            self._last_host_ts[key] = time.monotonic()

    @staticmethod
    def _read_bounded(resp: Any, max_bytes: int, deadline: float) -> bytes:
        chunks: List[bytes] = []
        total = 0
        while total < max_bytes:
            if time.monotonic() > deadline:
                raise TimeoutError("overall_request_deadline_exceeded")
            chunk = resp.read(min(16384, max_bytes - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)

    @staticmethod
    def _decode_body(raw: bytes, headers: Dict[str, str]) -> str:
        encoding = headers.get("content-encoding", "").lower()
        data = raw
        if "gzip" in encoding:
            try:
                data = gzip.decompress(raw)
            except Exception:
                pass
        elif "deflate" in encoding:
            try:
                data = zlib.decompress(raw)
            except Exception:
                pass
        ct = headers.get("content-type", "")
        m = re.search(r"charset=([^\s;]+)", ct, re.IGNORECASE)
        charset = m.group(1).strip("\"'") if m else "utf-8"
        try:
            return data.decode(charset, errors="replace")
        except Exception:
            return data.decode("utf-8", errors="replace")

    def get(
        self,
        url: str,
        timeout: float = 7.0,
        max_bytes: int = 262144,
        max_redirects: int = 4,
        retries: int = 1,
        accept: str = "application/json, text/plain, text/html;q=0.8, */*;q=0.5",
        bucket: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        min_interval_override: Optional[float] = None,
    ) -> HttpResponse:
        parsed_init = urllib.parse.urlparse(url)
        host_bucket = bucket or parsed_init.netloc.lower()
        current_url = url
        redirect_chain: List[Dict[str, Any]] = []
        last_err: Optional[str] = None

        for attempt in range(retries + 1):
            current_url = url
            redirect_chain = []
            t0 = time.monotonic()
            attempt_deadline = t0 + max(timeout * 1.7, timeout + 3.5)
            retry_needed = False
            last_err = None

            for hop in range(max_redirects + 1):
                if attempt_deadline - time.monotonic() <= 0.2:
                    last_err = "overall_attempt_deadline_exceeded"
                    self._record_stat(host_bucket, "network_errors")
                    break

                parsed = urllib.parse.urlparse(current_url)
                host = parsed.netloc.lower()
                rate_key = bucket if (bucket and min_interval_override is not None) else host
                self._wait_rate_limit(rate_key, min_interval_override=min_interval_override)
                self._record_stat(host_bucket, "requests")

                headers_map = {
                    "User-Agent": self.user_agent,
                    "Accept": accept,
                    "Accept-Encoding": "gzip, deflate",
                }
                if extra_headers:
                    headers_map.update(extra_headers)

                req = urllib.request.Request(current_url, method="GET", headers=headers_map)
                hop_timeout = min(timeout, max(1.0, attempt_deadline - time.monotonic()))
                try:
                    with self._opener.open(req, timeout=hop_timeout) as resp:
                        status = int(resp.getcode())
                        headers = {k.lower(): v for k, v in resp.headers.items()}
                        if status in (301, 302, 303, 307, 308) and "location" in headers and hop < max_redirects:
                            next_url = urllib.parse.urljoin(current_url, headers["location"])
                            redirect_chain.append({"from": current_url, "status": status, "to": next_url})
                            current_url = next_url
                            continue
                        raw = self._read_bounded(resp, max_bytes, attempt_deadline)
                        body_text = self._decode_body(raw, headers)
                        self._record_stat(host_bucket, f"http_{status}")
                        return HttpResponse(
                            url=url,
                            final_url=current_url,
                            status=status,
                            headers=headers,
                            body_text=body_text,
                            redirect_chain=redirect_chain,
                            elapsed_ms=int((time.monotonic() - t0) * 1000),
                        )
                except urllib.error.HTTPError as e:
                    status = int(e.code)
                    headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
                    if status in (301, 302, 303, 307, 308) and "location" in headers and hop < max_redirects:
                        next_url = urllib.parse.urljoin(current_url, headers["location"])
                        redirect_chain.append({"from": current_url, "status": status, "to": next_url})
                        current_url = next_url
                        continue
                    try:
                        raw = self._read_bounded(e, min(max_bytes, 32768), attempt_deadline)
                        body_text = self._decode_body(raw, headers)
                    except Exception:
                        body_text = ""
                    self._record_stat(host_bucket, f"http_{status}")
                    if status in (429, 502, 503, 504) and attempt < retries:
                        retry_after = headers.get("retry-after")
                        delay = (
                            float(retry_after)
                            if (retry_after and retry_after.isdigit())
                            else (0.9 * (attempt + 1) + random.uniform(0.15, 0.45))
                        )
                        time.sleep(min(delay, 4.0))
                        retry_needed = True
                        break
                    return HttpResponse(
                        url=url,
                        final_url=current_url,
                        status=status,
                        headers=headers,
                        body_text=body_text,
                        redirect_chain=redirect_chain,
                        elapsed_ms=int((time.monotonic() - t0) * 1000),
                    )
                except (
                    urllib.error.URLError,
                    socket.timeout,
                    TimeoutError,
                    ssl.SSLError,
                    ConnectionError,
                    OSError,
                ) as e:
                    last_err = f"{type(e).__name__}: {e}"
                    self._record_stat(host_bucket, "network_errors")
                    if attempt < retries:
                        time.sleep(0.4 * (attempt + 1) + random.uniform(0.1, 0.25))
                        retry_needed = True
                        break
                    return HttpResponse(
                        url=url,
                        final_url=current_url,
                        status=0,
                        headers={},
                        body_text="",
                        redirect_chain=redirect_chain,
                        error=last_err,
                        elapsed_ms=int((time.monotonic() - t0) * 1000),
                    )
            if not retry_needed:
                break

        return HttpResponse(
            url=url,
            final_url=current_url,
            status=0,
            headers={},
            body_text="",
            redirect_chain=redirect_chain,
            error=last_err or "max_retries_exceeded",
        )

    def github_api_json(
        self, endpoint: str, is_search: bool = False
    ) -> Tuple[int, Any, Optional[str]]:
        if is_search and not self.enable_github_search:
            return 0, None, "github_search_disabled"
        bucket = "github_search" if is_search else "github_core"
        # GitHub authenticated search limit is 30 req/min -> 2.15s interval
        min_gap = 2.15 if is_search else 0.18
        headers: Dict[str, str] = {"X-GitHub-Api-Version": "2022-11-28"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        url = f"https://api.github.com/{endpoint.lstrip('/')}"
        resp = self.get(
            url,
            timeout=7.5,
            max_bytes=524288,
            retries=1,
            accept="application/vnd.github+json",
            bucket=bucket,
            extra_headers=headers,
            min_interval_override=min_gap,
        )
        if resp.status == 200:
            try:
                return 200, json.loads(resp.body_text), None
            except Exception as e:
                return 200, None, f"json_error: {e}"
        return resp.status, None, resp.error or f"http_{resp.status}"
