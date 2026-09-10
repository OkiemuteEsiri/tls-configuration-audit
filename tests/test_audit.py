import unittest
from datetime import datetime, timezone

from src.analyzer import audit_endpoint
from src.models import TLSEndpoint


def endpoint(**overrides):
    base = dict(
        endpoint_id="e1",
        hostname="service.synthetic.example",
        port=443,
        environment="test",
        internet_exposed=True,
        owner="platform",
        protocols=("TLS1.2", "TLS1.3"),
        certificate_expires_at=datetime(2027, 1, 1, tzinfo=timezone.utc),
        key_bits=2048,
        supports_weak_ciphers=False,
        hsts_enabled=True,
        ocsp_stapling=True,
    )
    base.update(overrides)
    return TLSEndpoint(**base)


class TLSAuditTests(unittest.TestCase):
    def setUp(self):
        self.as_of = datetime(2026, 9, 10, tzinfo=timezone.utc)

    def test_clean_endpoint_has_no_findings(self):
        self.assertEqual(audit_endpoint(endpoint(), self.as_of), [])

    def test_legacy_protocol_is_high(self):
        findings = audit_endpoint(endpoint(protocols=("TLS1.0", "TLS1.2")), self.as_of)
        match = next(f for f in findings if f.control == "legacy-protocols")
        self.assertEqual(match.severity, "high")

    def test_internet_exposure_increases_score(self):
        exposed = next(f for f in audit_endpoint(endpoint(protocols=("TLS1.0",), internet_exposed=True), self.as_of) if f.control == "legacy-protocols")
        internal = next(f for f in audit_endpoint(endpoint(protocols=("TLS1.0",), internet_exposed=False), self.as_of) if f.control == "legacy-protocols")
        self.assertGreater(exposed.score, internal.score)

    def test_expired_certificate_is_critical(self):
        findings = audit_endpoint(endpoint(certificate_expires_at=datetime(2026, 8, 1, tzinfo=timezone.utc)), self.as_of)
        match = next(f for f in findings if f.control == "certificate-expired")
        self.assertEqual(match.severity, "critical")

    def test_near_expiry_certificate_is_high(self):
        findings = audit_endpoint(endpoint(certificate_expires_at=datetime(2026, 9, 25, tzinfo=timezone.utc)), self.as_of)
        self.assertTrue(any(f.control == "certificate-expiry" and f.severity == "high" for f in findings))

    def test_weak_key_is_detected(self):
        findings = audit_endpoint(endpoint(key_bits=1024), self.as_of)
        self.assertTrue(any(f.control == "weak-public-key" for f in findings))

    def test_missing_owner_is_detected(self):
        findings = audit_endpoint(endpoint(owner=""), self.as_of)
        self.assertTrue(any(f.control == "missing-owner" for f in findings))

    def test_missing_hsts_on_443_is_detected(self):
        findings = audit_endpoint(endpoint(hsts_enabled=False), self.as_of)
        self.assertTrue(any(f.control == "hsts-missing" for f in findings))

    def test_invalid_port_rejected(self):
        with self.assertRaises(ValueError):
            endpoint(port=70000)

    def test_naive_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            endpoint(certificate_expires_at=datetime(2027, 1, 1))


if __name__ == "__main__":
    unittest.main()
