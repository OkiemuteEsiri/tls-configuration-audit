from collections import Counter
from typing import Iterable

from .models import Finding, TLSEndpoint


def posture_metrics(endpoints: Iterable[TLSEndpoint], findings: Iterable[Finding]) -> dict:
    endpoint_list = list(endpoints)
    finding_list = list(findings)
    affected = {f.endpoint_id for f in finding_list}
    severity = Counter(f.severity for f in finding_list)
    highest = max((f.score for f in finding_list), default=0)
    return {
        "endpoints": len(endpoint_list),
        "affected_endpoints": len(affected),
        "findings": len(finding_list),
        "critical": severity.get("critical", 0),
        "high": severity.get("high", 0),
        "medium": severity.get("medium", 0),
        "low": severity.get("low", 0),
        "highest_score": highest,
    }


def markdown_report(endpoints: Iterable[TLSEndpoint], findings: Iterable[Finding]) -> str:
    endpoints = list(endpoints)
    findings = list(findings)
    metrics = posture_metrics(endpoints, findings)
    lines = [
        "# TLS Configuration Audit Report",
        "",
        "## Executive summary",
        f"- Endpoints assessed: {metrics['endpoints']}",
        f"- Affected endpoints: {metrics['affected_endpoints']}",
        f"- Findings: {metrics['findings']}",
        f"- Critical / High: {metrics['critical']} / {metrics['high']}",
        f"- Highest contextual score: {metrics['highest_score']}/100",
        "",
        "## Findings",
    ]
    if not findings:
        lines.append("No findings were identified in the supplied configuration baseline.")
    for finding in findings:
        lines += [
            "",
            f"### {finding.endpoint_id} — {finding.control}",
            f"- Severity: **{finding.severity.upper()}**",
            f"- Contextual score: **{finding.score}/100**",
            f"- Evidence: {finding.evidence}",
            f"- MITRE ATT&CK context: {', '.join(finding.attack_context)}",
            f"- Remediation: {finding.remediation}",
            f"- Validation: {finding.validation}",
        ]
    lines += [
        "",
        "## Interpretation",
        "ATT&CK mappings provide threat context only. A configuration finding is not proof of interception, exploitation, or compromise.",
    ]
    return "\n".join(lines) + "\n"
