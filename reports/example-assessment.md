# Example TLS Configuration Assessment

> Synthetic demonstration output. No production systems were assessed.

## Executive view

Three synthetic endpoints were reviewed against the project TLS baseline. The internet-facing portal represents the highest remediation priority because it combines legacy protocol support, weak cipher allowance, short certificate lifetime, missing HSTS and absent OCSP stapling. The legacy internal administration service demonstrates a different risk pattern: legacy protocol support, a weak public key, an expired certificate and missing ownership.

## Prioritized observations

| Endpoint | Observation | Priority rationale |
|---|---|---|
| `edge-web-01` | Legacy TLS protocol enabled | Internet-facing reachability raises remediation urgency |
| `edge-web-01` | Weak cipher suites permitted | Cryptographic policy does not meet the project baseline |
| `edge-web-01` | Certificate near expiry | Renewal should occur before service continuity becomes dependent on emergency change |
| `legacy-admin-03` | Certificate expired | Trust and service reliability control failure |
| `legacy-admin-03` | 1024-bit public key | Below the project cryptographic baseline |
| `legacy-admin-03` | Missing accountable owner | Remediation and lifecycle accountability are unclear |

## Remediation sequence

1. Replace expired certificate material and assign accountable ownership for `legacy-admin-03`.
2. Disable TLS 1.0/1.1 after application compatibility validation.
3. Remove weak cipher suites from the approved configuration.
4. Renew `edge-web-01` before certificate expiry.
5. Enable HSTS on the HTTPS portal after compatibility testing.
6. Evaluate OCSP stapling support for the internet-facing service.
7. Reassess each endpoint and retain evidence before closure.

## Validation standard

A finding is considered remediated only when the approved configuration or re-assessment evidence demonstrates the intended control state. Configuration intent alone is insufficient closure evidence.

## Threat context

MITRE ATT&CK mappings such as T1040 and T1557 describe relevant network interception/adversary-in-the-middle context. They are not evidence that an attack occurred.
