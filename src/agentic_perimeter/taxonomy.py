"""Canonical OWASP Agentic Top 10 (2026 v1.0), OWASP MCP Top 10 (2025 v0.1 Beta),
and strictly factual, neutral finding taxonomy for agentic-perimeter.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class OwaspRef:
    framework: str
    code: str
    title: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "framework": self.framework,
            "code": self.code,
            "title": self.title,
        }


# Verbatim canonical titles from OWASP Top 10 for Agentic Applications 2026 (v1.0)
OWASP_ASI: Dict[str, OwaspRef] = {
    "ASI01": OwaspRef("OWASP Agentic Top 10 (2026)", "ASI01", "Agent Goal Hijack"),
    "ASI02": OwaspRef("OWASP Agentic Top 10 (2026)", "ASI02", "Tool Misuse and Exploitation"),
    "ASI03": OwaspRef("OWASP Agentic Top 10 (2026)", "ASI03", "Identity and Privilege Abuse"),
    "ASI04": OwaspRef("OWASP Agentic Top 10 (2026)", "ASI04", "Agentic Supply Chain Vulnerabilities"),
    "ASI05": OwaspRef("OWASP Agentic Top 10 (2026)", "ASI05", "Unexpected Code Execution (RCE)"),
    "ASI06": OwaspRef("OWASP Agentic Top 10 (2026)", "ASI06", "Memory & Context Poisoning"),
    "ASI07": OwaspRef("OWASP Agentic Top 10 (2026)", "ASI07", "Insecure Inter-Agent Communication"),
    "ASI08": OwaspRef("OWASP Agentic Top 10 (2026)", "ASI08", "Cascading Failures"),
    "ASI09": OwaspRef("OWASP Agentic Top 10 (2026)", "ASI09", "Human-Agent Trust Exploitation"),
    "ASI10": OwaspRef("OWASP Agentic Top 10 (2026)", "ASI10", "Rogue Agents"),
}

# Verbatim canonical titles from OWASP MCP Top 10 (2025 v0.1 Beta)
OWASP_MCP: Dict[str, OwaspRef] = {
    "MCP01:2025": OwaspRef("OWASP MCP Top 10 (2025)", "MCP01:2025", "Token Mismanagement & Secret Exposure"),
    "MCP02:2025": OwaspRef("OWASP MCP Top 10 (2025)", "MCP02:2025", "Privilege Escalation via Scope Creep"),
    "MCP03:2025": OwaspRef("OWASP MCP Top 10 (2025)", "MCP03:2025", "Tool Poisoning"),
    "MCP04:2025": OwaspRef("OWASP MCP Top 10 (2025)", "MCP04:2025", "Software Supply Chain Attacks & Dependency Tampering"),
    "MCP05:2025": OwaspRef("OWASP MCP Top 10 (2025)", "MCP05:2025", "Command Injection & Execution"),
    "MCP06:2025": OwaspRef("OWASP MCP Top 10 (2025)", "MCP06:2025", "Intent Flow Subversion"),
    "MCP07:2025": OwaspRef("OWASP MCP Top 10 (2025)", "MCP07:2025", "Insufficient Authentication & Authorization"),
    "MCP08:2025": OwaspRef("OWASP MCP Top 10 (2025)", "MCP08:2025", "Lack of Audit and Telemetry"),
    "MCP09:2025": OwaspRef("OWASP MCP Top 10 (2025)", "MCP09:2025", "Shadow MCP Servers"),
    "MCP10:2025": OwaspRef("OWASP MCP Top 10 (2025)", "MCP10:2025", "Context Injection & Over-Sharing"),
}


# Strictly factual, neutral finding labels (never attributing intent or calling aggregators "malicious").
# Strict MECE axis assignment: 6 "first_party_control" rules + 6 "external_threat" rules.
FINDING_DEFINITIONS: Dict[str, Dict[str, object]] = {
    "v1_url_path_token_exposure": {
        "vector": "V1",
        "axis": "external_threat",
        "label": "URL-Path Token Exposure",
        "default_severity": "critical",
        "owasp": [OWASP_ASI["ASI03"], OWASP_ASI["ASI04"], OWASP_MCP["MCP01:2025"], OWASP_MCP["MCP04:2025"]],
        "recommendation": (
            "Claim your official reverse-DNS namespace in registry.modelcontextprotocol.io (or publish an "
            "official policy statement), enforce internal MCP allowlists, and instruct developers/agents "
            "to reject remote MCP endpoints that pass bearer tokens or API keys in URL path templates."
        ),
    },
    "v1_unverified_3p_hosted_proxy": {
        "vector": "V1",
        "axis": "external_threat",
        "label": "Unverified 3rd-Party Hosted Proxy",
        "default_severity": "high",
        "owasp": [OWASP_ASI["ASI04"], OWASP_ASI["ASI07"], OWASP_MCP["MCP04:2025"], OWASP_MCP["MCP09:2025"]],
        "recommendation": (
            "Claim your official reverse-DNS namespace in registry.modelcontextprotocol.io (or publish an "
            "official policy statement) and enforce internal MCP allowlists pinned to verified first-party endpoints."
        ),
    },
    "v1_unscoped_free_email_collision": {
        "vector": "V1",
        "axis": "external_threat",
        "label": "Unverified Package / Free-Email Maintainer",
        "default_severity": "high",
        "owasp": [OWASP_ASI["ASI04"], OWASP_ASI["ASI05"], OWASP_MCP["MCP04:2025"], OWASP_MCP["MCP05:2025"]],
        "recommendation": (
            "Publish official scoped MCP packages with verified domain provenance (npm Trusted Publishers / "
            "PyPI Trusted Publishers) and enforce allowlisted package scopes in developer agent policies."
        ),
    },
    "v1_unverified_package_collision": {
        "vector": "V1",
        "axis": "external_threat",
        "label": "Unverified Package Namespace Collision",
        "default_severity": "medium",
        "owasp": [OWASP_ASI["ASI04"], OWASP_ASI["ASI09"], OWASP_MCP["MCP04:2025"]],
        "recommendation": (
            "Document canonical install commands (`npx` / `uvx`) tied to officially anchored scopes and "
            "monitor public package registries for high-traffic unverified collisions."
        ),
    },
    "v1_official_registry_vacuum": {
        "vector": "V1",
        "axis": "first_party_control",
        "label": "Official Registry Vacuum",
        "default_severity": "high",
        "owasp": [OWASP_ASI["ASI04"], OWASP_MCP["MCP04:2025"], OWASP_MCP["MCP09:2025"]],
        "recommendation": (
            "Register a domain-anchored official entry in registry.modelcontextprotocol.io (or publish an "
            "official statement/policy) so autonomous agents do not default to unverified third-party entries."
        ),
    },
    "v2_missing_rfc9728_metadata": {
        "vector": "V2",
        "axis": "first_party_control",
        "label": "Missing RFC 9728 OAuth Protected Resource Metadata",
        "default_severity": "medium",
        "owasp": [OWASP_ASI["ASI03"], OWASP_ASI["ASI07"], OWASP_MCP["MCP07:2025"]],
        "recommendation": (
            "Serve RFC 9728 metadata at /.well-known/oauth-protected-resource (and emit WWW-Authenticate "
            "resource_metadata headers on 401 responses) on all active external MCP endpoints."
        ),
    },
    "v2_broad_oauth_scope_declaration": {
        "vector": "V2",
        "axis": "first_party_control",
        "label": "Broad OAuth Scope Declaration",
        "default_severity": "medium",
        "owasp": [OWASP_ASI["ASI03"], OWASP_MCP["MCP02:2025"]],
        "recommendation": (
            "Apply least-privilege scope partitioning in OAuth Protected Resource metadata: separate "
            "read-only agent scopes from administrative, wildcard, or destructive write scopes."
        ),
    },
    "v2_cross_domain_perimeter_drift": {
        "vector": "V2",
        "axis": "first_party_control",
        "label": "Cross-Domain Perimeter Drift",
        "default_severity": "low",
        "owasp": [OWASP_ASI["ASI07"], OWASP_MCP["MCP09:2025"]],
        "recommendation": (
            "Align MCP discovery endpoints, OAuth authorization servers, and DNS-AID records under a "
            "documented first-party domain boundary (or explicitly document verified sibling domains)."
        ),
    },
    "v2_cross_domain_3p_delegation": {
        "vector": "V2",
        "axis": "first_party_control",
        "label": "Unverified Cross-Domain External Delegation",
        "default_severity": "medium",
        "owasp": [OWASP_ASI["ASI04"], OWASP_ASI["ASI07"], OWASP_MCP["MCP09:2025"]],
        "recommendation": (
            "Verify whether external discovery endpoints intentionally delegate to a third-party domain "
            "and establish strict trust boundaries and TLS/DNS-AID verification."
        ),
    },
    "v2_missing_dns_aid_dnssec": {
        "vector": "V2",
        "axis": "first_party_control",
        "label": "Unprotected Agent Discovery Surface (No DNS-AID / DNSSEC)",
        "default_severity": "info",
        "owasp": [OWASP_ASI["ASI07"], OWASP_MCP["MCP09:2025"]],
        "recommendation": (
            "Enable DNSSEC on zones serving external MCP/agent endpoints and evaluate IETF DNS-AID "
            "(_agent / _mcp SVCB records) to establish cryptographically verifiable agent discovery."
        ),
    },
    "v3_active_lookalike_agent_endpoint": {
        "vector": "V3",
        "axis": "external_threat",
        "label": "Active Lookalike Agent Endpoint",
        "default_severity": "critical",
        "owasp": [OWASP_ASI["ASI04"], OWASP_ASI["ASI07"], OWASP_MCP["MCP09:2025"]],
        "recommendation": (
            "Investigate third-party lookalike infrastructure serving live MCP or agent discovery "
            "endpoints, block it in corporate egress controls, and initiate brand protection review. "
            "Verify domain ownership before taking takedown action in case an unlisted subsidiary or "
            "partner operates the host."
        ),
    },
    "v3_active_phishing_lookalike": {
        "vector": "V3",
        "axis": "external_threat",
        "label": "Phishing-Warning Lookalike Domain",
        "default_severity": "high",
        "owasp": [OWASP_ASI["ASI04"], OWASP_ASI["ASI09"], OWASP_MCP["MCP04:2025"]],
        "recommendation": (
            "Verify the domain's status, consider blocking it in corporate DNS/egress controls, and "
            "initiate registrar/abuse review through standard brand protection channels if confirmed "
            "unauthorized."
        ),
    },
}


# v0.3.0 wire-level DNS-AID & ANS v2 protocol finding definitions (kept separate from the
# 6+6 core FINDING_DEFINITIONS MECE matrix for backward compatibility, merged in ALL_FINDING_DEFINITIONS).
PROTOCOL_FINDING_DEFINITIONS: Dict[str, Dict[str, object]] = {
    "v2_dns_aid_card_hash_mismatch": {
        "vector": "V2",
        "axis": "first_party_control",
        "label": "DNS-AID Agent Card Digest Mismatch",
        "default_severity": "high",
        "owasp": [OWASP_ASI["ASI04"], OWASP_ASI["ASI07"], OWASP_MCP["MCP03:2025"], OWASP_MCP["MCP04:2025"]],
        "recommendation": (
            "Verify the agent card served at the DNS-AID `cap` (`key65400`) URL against your signed "
            "deployment artifact and update the DNS `cap-sha256` (`key65401`) SVCB parameter atomically "
            "during releases so clients can detect card tampering."
        ),
    },
    "v2_ans_badge_host_mismatch": {
        "vector": "V2",
        "axis": "first_party_control",
        "label": "ANS Badge Host-Binding Mismatch",
        "default_severity": "high",
        "owasp": [OWASP_ASI["ASI03"], OWASP_ASI["ASI07"], OWASP_MCP["MCP07:2025"]],
        "recommendation": (
            "Publish an `_ans-badge` TXT record whose transparency log receipt `ansName` and `agent.host` "
            "strictly match the host serving the agent; investigate any badge copied from another domain."
        ),
    },
    "v2_dane_tlsa_without_dnssec": {
        "vector": "V2",
        "axis": "first_party_control",
        "label": "DANE TLSA Published Without DNSSEC",
        "default_severity": "medium",
        "owasp": [OWASP_ASI["ASI07"], OWASP_MCP["MCP07:2025"]],
        "recommendation": (
            "Enable and validate DNSSEC (`AD=true`) on zones publishing `_443._tcp` DANE TLSA records; "
            "unsigned TLSA records cannot provide cryptographic TLS certificate binding per RFC 6698."
        ),
    },
    "v3_spoofed_ans_badge_lookalike": {
        "vector": "V3",
        "axis": "external_threat",
        "label": "Lookalike Domain With Spoofed ANS Badge",
        "default_severity": "critical",
        "owasp": [OWASP_ASI["ASI04"], OWASP_ASI["ASI07"], OWASP_ASI["ASI09"], OWASP_MCP["MCP09:2025"]],
        "recommendation": (
            "Investigate third-party lookalike infrastructure publishing a copied `_ans-badge` record "
            "bound to another host's transparency log receipt, block the lookalike host in protective "
            "DNS/egress policies, and initiate brand protection review after confirming ownership."
        ),
    },
}

ALL_FINDING_DEFINITIONS: Dict[str, Dict[str, object]] = {
    **FINDING_DEFINITIONS,
    **PROTOCOL_FINDING_DEFINITIONS,
}


def get_finding_definition(rule_id: str) -> Dict[str, object]:
    return ALL_FINDING_DEFINITIONS[rule_id]


def owasp_list_for(rule_id: str) -> List[OwaspRef]:
    defn = ALL_FINDING_DEFINITIONS[rule_id]
    return list(defn["owasp"])  # type: ignore[arg-type]


def axis_for(rule_id: str) -> str:
    defn = ALL_FINDING_DEFINITIONS.get(rule_id)
    if defn and defn.get("axis"):
        return str(defn["axis"])
    return "external_threat"
