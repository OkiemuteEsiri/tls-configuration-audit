# TLS Configuration Audit

Defensive network security and cryptographic posture assessment project focused on TLS hardening, certificate lifecycle governance, explainable prioritization, remediation, and revalidation.

## Problem statement

TLS weaknesses are often managed as isolated scanner findings. In practice, remediation priority depends on service exposure, protocol posture, cipher policy, certificate state, cryptographic strength, ownership, and the ability to validate closure. This project demonstrates how those signals can be normalized into a repeatable security-engineering workflow.

## What this project demonstrates

- Defensive TLS configuration assessment using synthetic input data.
- Immutable validated endpoint and finding models.
- Detection of legacy TLS protocol support.
- Weak/deprecated cipher-suite policy checks.
- Certificate-expiry prioritization.
- Public-key-strength checks.
- HSTS and OCSP-stapling governance checks.
- Missing-owner detection.
- Internet-exposure-aware contextual scoring.
- Deterministic finding identifiers.
- Evidence, remediation and validation guidance per finding.
- Portfolio-level posture metrics and Markdown reporting.
- Unit tests and least-privilege CI.

## Architecture

```text
Synthetic endpoint inventory
        |
        v
Validated TLSEndpoint models
        |
        v
TLS control assessment engine
        |
        +--> protocol controls
        +--> cipher controls
        +--> certificate lifecycle
        +--> key-strength controls
        +--> HTTPS hardening
        +--> ownership governance
        |
        v
Contextual 0-100 prioritization
        |
        v
Findings + posture metrics + Markdown reporting
        |
        v
Remediation -> reassessment -> evidence-backed closure
```

## Repository structure

```text
.github/workflows/ci.yml       Least-privilege Python CI
data/synthetic_endpoints.json  Safe synthetic endpoint inventory
docs/architecture-methodology.md
reports/example-assessment.md
src/models.py                  Validated immutable domain models
src/analyzer.py                TLS assessment and contextual scoring
src/reporting.py               Metrics and Markdown reporting
tests/test_audit.py            Unit tests
```

## Risk model

The engine uses bounded contextual scoring rather than presenting configuration findings as exploit probabilities.

Examples of higher-priority conditions include:

- TLS 1.0 or TLS 1.1 enabled.
- Weak/deprecated cipher suites permitted.
- Expired or near-expiry certificates.
- Public keys below the project baseline.
- Missing HSTS on HTTPS services.
- Missing accountable ownership.
- Internet exposure, which raises remediation urgency.

A failed TLS control is not treated as evidence that interception, exploitation, or compromise occurred.

## MITRE ATT&CK context

Relevant threat context includes:

- **T1040 — Network Sniffing**
- **T1557 — Adversary-in-the-Middle**

These mappings explain why transport-security posture matters. They are not proof of malicious activity.

## Example usage

```python
from datetime import datetime, timezone
from src.analyzer import audit
from src.models import TLSEndpoint
from src.reporting import markdown_report

endpoint = TLSEndpoint(
    endpoint_id="edge-01",
    hostname="portal.synthetic.example",
    port=443,
    environment="production",
    internet_exposed=True,
    owner="web-platform",
    protocols=("TLS1.0", "TLS1.2"),
    certificate_expires_at=datetime(2026, 9, 25, tzinfo=timezone.utc),
    key_bits=2048,
    supports_weak_ciphers=True,
    hsts_enabled=False,
    ocsp_stapling=False,
)

findings = audit([endpoint], datetime(2026, 9, 10, tzinfo=timezone.utc))
print(markdown_report([endpoint], findings))
```

## Remediation workflow

1. Confirm the authoritative endpoint and service owner.
2. Validate business/application compatibility.
3. Disable legacy protocol versions.
4. Remove weak cipher suites.
5. Renew or rotate certificate/key material through approved PKI processes.
6. Apply HTTPS hardening controls where appropriate.
7. Reassess the service using an approved scanner or configuration source.
8. Close only after evidence demonstrates the intended secure state.
9. Govern unavoidable exceptions with owner, rationale, compensating controls and expiry.

## Validation philosophy

A remediation ticket or configuration-change request is not closure evidence. Revalidation should demonstrate that the weak protocol, cipher, certificate, ownership or hardening condition is no longer present in the authoritative assessment source.

## Testing

The repository includes unit tests covering:

- clean modern TLS baseline
- legacy protocol detection
- exposure-aware scoring
- expired certificates
- near-expiry certificates
- weak public keys
- missing ownership
- missing HSTS
- invalid ports
- timezone validation

The CI workflow compiles the Python modules and runs unittest discovery using Python 3.12 with read-only repository permissions.

## Security and safety boundaries

This repository intentionally does **not** contain:

- live network scanning
- certificate harvesting
- packet interception
- downgrade tooling
- adversary-in-the-middle automation
- credential capture
- exploit payloads
- production endpoints or credentials
- confidential employer/client data

The synthetic cipher and certificate metadata represents normalized output that could come from an approved enterprise scanner or configuration-management source.

## Skills demonstrated

- Network security engineering
- TLS/PKI posture governance
- Vulnerability management
- Exposure-aware prioritization
- Python security automation
- Data validation
- Risk communication
- Remediation and revalidation design
- MITRE ATT&CK contextual mapping
- Unit testing
- CI/CD security hygiene

## Limitations

This is an offline portfolio lab, not a replacement for a production TLS scanner or full PKI platform. Policy thresholds should be aligned with current organizational, regulatory, vendor and compatibility requirements before operational use.

## Roadmap

- Add configurable policy profiles for internal and internet-facing services.
- Add normalized import adapters for scanner-export formats.
- Add certificate-chain and hostname-validation metadata.
- Add exception-register support with expiry governance.
- Add trend reporting for certificate lifecycle and legacy-protocol reduction.
- Add machine-readable JSON output alongside Markdown reporting.

## Portfolio purpose

The project is designed to demonstrate how a security engineer can translate TLS configuration telemetry into validated findings, contextual risk, accountable remediation, and evidence-backed closure rather than treating scanner output as the end of the workflow.
