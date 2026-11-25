"""Core data models for agentic-perimeter audits and empirical studies."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .taxonomy import OwaspRef, axis_for


@dataclass
class BrandTarget:
    domain: str
    brand: str
    aliases: List[str] = field(default_factory=list)
    sector: str = "Unknown"
    cohort: str = "custom"  # e.g., "fortune_traditional" | "saas_ai_fintech" | "custom"
    exclude_terms: List[str] = field(default_factory=list)
    known_sibling_domains: List[str] = field(default_factory=list)

    def normalized_aliases(self) -> List[str]:
        seen: List[str] = []
        for a in [self.brand, *self.aliases]:
            tok = a.strip().lower()
            if tok and tok not in seen:
                seen.append(tok)
        return seen


@dataclass
class Evidence:
    source: str  # e.g., "mcp_registry", "npm", "pypi", "dns_doh", "certspotter", "tls_san", "http_well_known"
    locator: str  # exact verifiable URL, package identifier, DNS qname, or CT cert ID
    detail: str
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "locator": self.locator,
            "detail": self.detail,
            "raw": self.raw,
        }


@dataclass
class Finding:
    rule_id: str
    vector: str  # "V1" | "V2" | "V3"
    label: str  # Strictly factual, neutral label
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    title: str
    summary: str
    owasp: List[OwaspRef]
    evidence: List[Evidence]
    recommendation: str
    axis: str = ""  # "first_party_control" | "external_threat"

    def __post_init__(self) -> None:
        if not self.axis:
            self.axis = axis_for(self.rule_id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "vector": self.vector,
            "axis": self.axis,
            "label": self.label,
            "severity": self.severity,
            "title": self.title,
            "summary": self.summary,
            "owasp": [o.to_dict() for o in self.owasp],
            "evidence": [e.to_dict() for e in self.evidence],
            "recommendation": self.recommendation,
        }


@dataclass
class ScoreSummary:
    scoring_model: str  # "2-axis-v1"
    # Axis 1: First-Party Control Posture (higher = better; None when Baseline/N/A)
    control_posture_score: Optional[int]
    control_posture_grade: str  # "A" | "B" | "C" | "D" | "F" | "N/A"
    control_posture_label: str  # "Exemplary" | "Strong" | "Developing" | "Weak" | "Critical Gap" | "Baseline (No Agentic Footprint)"
    control_posture_applicable: bool
    control_breakdown: List[Dict[str, Any]]  # [{id, name, status, earned, max_points, detail}]
    # Axis 2: External Ecosystem Threat Pressure (higher = heavier pressure; NO letter grade)
    threat_pressure_score: int  # 0..100
    threat_pressure_level: str  # "None" | "Low" | "Moderate" | "High" | "Critical"
    threat_breakdown: List[Dict[str, Any]]  # [{id, name, points, count, detail}]
    # 2D Executive Synthesis
    action_posture: str
    action_posture_summary: str
    # Counts & Briefs
    counts_by_severity: Dict[str, int]
    counts_by_vector: Dict[str, int]
    counts_by_axis: Dict[str, int]  # {"first_party_control": int, "external_threat": int}
    ciso_takeaways: List[str]
    first_party_priorities: List[str]
    external_defense_priorities: List[str]
    top_priorities: List[str]  # merged top 3 for concise CLI/backward readability

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    schema_version: str
    tool_version: str
    scanned_at: str
    duration_seconds: float
    target: BrandTarget
    verified_sibling_domains: List[str]
    score: ScoreSummary
    findings: List[Finding]
    vector1: Dict[str, Any]
    vector2: Dict[str, Any]
    vector3: Dict[str, Any]
    telemetry: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool_version": self.tool_version,
            "scanned_at": self.scanned_at,
            "duration_seconds": round(self.duration_seconds, 2),
            "target": asdict(self.target),
            "verified_sibling_domains": self.verified_sibling_domains,
            "score": self.score.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "vector1": self.vector1,
            "vector2": self.vector2,
            "vector3": self.vector3,
            "telemetry": self.telemetry,
        }
