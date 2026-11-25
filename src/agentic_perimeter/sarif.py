"""SARIF 2.1.0 exporter for CI/CD and GitHub Code Scanning integration."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from . import __version__
from .models import AuditReport
from .taxonomy import FINDING_DEFINITIONS

_SARIF_LEVEL: Dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_SECURITY_SEVERITY: Dict[str, str] = {
    "critical": "9.0",
    "high": "7.5",
    "medium": "5.0",
    "low": "3.0",
    "info": "1.0",
}


def render_sarif(report: AuditReport | Dict[str, Any]) -> Dict[str, Any]:
    """Convert an AuditReport (or dict) into a GitHub Code Scanning-compatible SARIF 2.1.0 document."""
    data = report.to_dict() if isinstance(report, AuditReport) else report
    target = data.get("target") or {}
    domain = str(target.get("domain") or "unknown")
    findings = data.get("findings") or []

    rules: List[Dict[str, Any]] = []
    seen_rules = set()
    for rule_id, defn in FINDING_DEFINITIONS.items():
        if rule_id in seen_rules:
            continue
        seen_rules.add(rule_id)
        sev = str(defn.get("default_severity") or "info").lower()
        owasp_tags = [o.code for o in defn.get("owasp", [])]  # type: ignore[attr-defined]
        rules.append(
            {
                "id": rule_id,
                "name": str(defn.get("label") or rule_id),
                "shortDescription": {"text": str(defn.get("label") or rule_id)},
                "fullDescription": {"text": str(defn.get("recommendation") or "")},
                "help": {
                    "text": str(defn.get("recommendation") or ""),
                    "markdown": f"**Recommended Action:** {defn.get('recommendation', '')}",
                },
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(sev, "note")},
                "properties": {
                    "tags": ["security", "external-attack-surface", "mcp", str(defn.get("vector", "")), *owasp_tags],
                    "precision": "high",
                    "security-severity": _SECURITY_SEVERITY.get(sev, "1.0"),
                    "axis": str(defn.get("axis") or ""),
                },
            }
        )

    results: List[Dict[str, Any]] = []
    for f in findings:
        rule_id = str(f.get("rule_id") or "unknown")
        sev = str(f.get("severity") or "info").lower()
        evs = f.get("evidence") or []
        locators = [str(e.get("locator") or "") for e in evs if e.get("locator")]
        ev_summary = "; ".join(f"{e.get('source')}: {e.get('detail')}" for e in evs[:5])
        msg_text = f"[{f.get('label')}] {f.get('title')}. {f.get('summary')}"
        if ev_summary:
            msg_text += f" Evidence: {ev_summary}"

        fp_src = f"{domain}|{rule_id}|{','.join(sorted(locators[:3]))}"
        fp = hashlib.sha256(fp_src.encode("utf-8")).hexdigest()[:32]

        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL.get(sev, "note"),
                "message": {"text": msg_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"agentic-perimeter/{domain}",
                            },
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [
                            {
                                "name": domain,
                                "fullyQualifiedName": f"{domain}:{f.get('vector')}:{rule_id}",
                                "kind": "module",
                            }
                        ],
                    }
                ],
                "partialFingerprints": {"primaryLocationLineHash": fp},
                "properties": {
                    "domain": domain,
                    "vector": f.get("vector"),
                    "axis": f.get("axis"),
                    "severity": sev,
                    "owasp": [o.get("code") for o in (f.get("owasp") or [])],
                    "evidence_locators": locators[:10],
                },
            }
        )

    sc = data.get("score") or {}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agentic-perimeter",
                        "version": str(data.get("tool_version") or __version__),
                        "informationUri": "https://github.com/jonadas-tech/agentic-perimeter",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "target_domain": domain,
                            "scanned_at": data.get("scanned_at"),
                            "control_posture_grade": sc.get("control_posture_grade"),
                            "control_posture_score": sc.get("control_posture_score"),
                            "threat_pressure_level": sc.get("threat_pressure_level"),
                            "threat_pressure_score": sc.get("threat_pressure_score"),
                            "action_posture": sc.get("action_posture"),
                        },
                    }
                ],
                "results": results,
            }
        ],
    }
