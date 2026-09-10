# Architecture and Methodology

## Purpose

This project demonstrates a defensive TLS configuration assessment workflow using synthetic configuration data. It is designed for security engineering, network security, vulnerability management and remediation-governance portfolio review.

## Architecture

1. **Domain models** validate endpoint inventory and cryptographic metadata before assessment.
2. **Assessment engine** evaluates TLS protocol, cipher, key-strength, certificate-lifecycle and HTTPS hardening controls.
3. **Contextual scoring** raises priority for internet-exposed services and missing ownership while keeping the score bounded to 0–100.
4. **Reporting layer** aggregates posture metrics and renders evidence, remediation and revalidation criteria.
5. **Tests** exercise clean baselines, legacy protocols, certificate expiry, weak keys, ownership gaps and schema validation.

## Control methodology

The engine evaluates the supplied configuration baseline rather than actively probing remote systems. This keeps the lab safe, deterministic and suitable for CI.

### Legacy protocol control
TLS 1.0 and TLS 1.1 are treated as legacy configuration that should be removed unless a formally approved compatibility exception exists.

### Cipher-suite control
The synthetic input exposes a boolean weak-cipher signal representing results from an upstream approved scanner or configuration-management source. This project does not implement active cipher enumeration.

### Certificate lifecycle
Expired certificates are prioritized as critical configuration failures. Certificates approaching expiry are escalated so renewal can occur before service interruption or emergency change activity.

### Key strength
Public keys below the project baseline of 2048 bits are flagged for replacement. The implementation intentionally avoids claiming that key length alone determines complete cryptographic assurance.

### HTTPS hardening
For port 443 services, the engine checks the supplied HSTS state. Internet-facing services also include an OCSP-stapling governance check where supported.

### Ownership
Missing ownership is a governance defect because remediation, renewal and exception accountability cannot be reliably assigned.

## Risk interpretation

Contextual scores are prioritization aids, not exploit probabilities. Internet exposure increases remediation urgency because affected services are reachable from less-trusted networks. MITRE ATT&CK mappings T1040 and T1557 provide network interception/adversary-in-the-middle threat context only; a failed TLS control does not prove exploitation or compromise.

## Remediation and validation workflow

1. Confirm the authoritative endpoint and service owner.
2. Validate business compatibility before changing protocol or cipher configuration.
3. Apply the least-disruptive hardening change through normal change control.
4. Renew or rotate certificate material through the approved PKI lifecycle.
5. Re-run the approved configuration assessment or scanner.
6. Close the finding only when evidence shows the control is satisfied.
7. Record exceptions with owner, rationale, expiry date and compensating controls.

## Limitations

- Synthetic data only.
- No network scanning, packet capture, certificate retrieval or live endpoint interaction.
- No claim of compromise from configuration weakness alone.
- Cipher policy is represented as upstream normalized metadata rather than a full cryptographic library.
- Production policy thresholds should be aligned to organizational standards and current regulatory requirements.
