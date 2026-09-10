import hashlib
from datetime import datetime, timezone
from typing import Iterable, List

from .models import Finding, TLSEndpoint

ATTACK_NETWORK_CONTEXT = ("T1040", "T1557")


def _finding_id(endpoint_id: str, control: str) -> str:
    return hashlib.sha256(f"{endpoint_id}:{control}".encode()).hexdigest()[:16]


def _score(base: int, endpoint: TLSEndpoint) -> int:
    exposure = 15 if endpoint.internet_exposed else 0
    owner_gap = 5 if not endpoint.owner.strip() else 0
    return min(100, base + exposure + owner_gap)


def audit_endpoint(endpoint: TLSEndpoint, as_of: datetime) -> List[Finding]:
    if as_of.tzinfo is None:
        raise ValueError("as_of must be timezone-aware")
    findings: List[Finding] = []

    def add(control: str, severity: str, base: int, evidence: str, remediation: str, validation: str) -> None:
        findings.append(Finding(
            finding_id=_finding_id(endpoint.endpoint_id, control),
            endpoint_id=endpoint.endpoint_id,
            control=control,
            severity=severity,
            score=_score(base, endpoint),
            evidence=evidence,
            remediation=remediation,
            validation=validation,
            attack_context=ATTACK_NETWORK_CONTEXT,
        ))

    legacy = sorted(set(endpoint.protocols) & {"TLS1.0", "TLS1.1"})
    if legacy:
        add("legacy-protocols", "high", 70, f"Enabled legacy protocols: {', '.join(legacy)}", "Disable TLS 1.0/1.1 and retain approved modern protocol versions.", "Reassess configuration and confirm legacy protocol negotiation is unavailable.")
    if endpoint.supports_weak_ciphers:
        add("weak-cipher-suites", "high", 72, "Endpoint configuration permits weak or deprecated cipher suites.", "Remove deprecated cipher suites and prefer modern authenticated encryption suites.", "Reassess the approved cipher list and confirm weak suites are rejected.")
    if endpoint.key_bits and endpoint.key_bits < 2048:
        add("weak-public-key", "high", 70, f"Certificate public key is {endpoint.key_bits} bits.", "Replace certificate/key material with an approved key size and algorithm.", "Confirm the replacement certificate meets the approved cryptographic baseline.")

    days_remaining = int((endpoint.certificate_expires_at - as_of).total_seconds() // 86400)
    if days_remaining < 0:
        add("certificate-expired", "critical", 90, f"Certificate expired {-days_remaining} days ago.", "Replace the expired certificate and review renewal controls.", "Confirm the new certificate is valid, trusted, and within the approved lifetime.")
    elif days_remaining <= 30:
        add("certificate-expiry", "high", 65, f"Certificate expires in {days_remaining} days.", "Renew or rotate the certificate before expiry using the approved lifecycle process.", "Confirm the replacement is deployed and expiry monitoring is active.")
    elif days_remaining <= 60:
        add("certificate-expiry", "medium", 45, f"Certificate expires in {days_remaining} days.", "Plan renewal and validate the responsible owner and renewal path.", "Confirm a renewal change is scheduled and monitored.")

    if endpoint.port == 443 and not endpoint.hsts_enabled:
        add("hsts-missing", "medium", 42, "HTTPS service does not declare HSTS in the supplied configuration baseline.", "Enable an appropriate Strict-Transport-Security policy after compatibility validation.", "Confirm browsers receive the intended HSTS header over HTTPS.")
    if endpoint.internet_exposed and not endpoint.ocsp_stapling:
        add("ocsp-stapling-disabled", "low", 25, "Internet-facing endpoint does not use OCSP stapling in the supplied baseline.", "Evaluate and enable OCSP stapling where supported by the service stack.", "Confirm stapled certificate status responses are presented by the service.")
    if not endpoint.owner.strip():
        add("missing-owner", "medium", 40, "No accountable service owner is recorded.", "Assign an accountable owner for certificate and TLS configuration lifecycle governance.", "Confirm ownership is recorded in the authoritative inventory.")
    return findings


def audit(endpoints: Iterable[TLSEndpoint], as_of: datetime) -> List[Finding]:
    output: List[Finding] = []
    for endpoint in endpoints:
        output.extend(audit_endpoint(endpoint, as_of))
    return sorted(output, key=lambda f: (-f.score, f.endpoint_id, f.control))
