from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Tuple

ALLOWED_PROTOCOLS = {"TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"}
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}

@dataclass(frozen=True)
class TLSEndpoint:
    endpoint_id: str
    hostname: str
    port: int
    environment: str
    internet_exposed: bool
    owner: str
    protocols: Tuple[str, ...]
    certificate_expires_at: datetime
    key_bits: int
    supports_weak_ciphers: bool
    hsts_enabled: bool
    ocsp_stapling: bool

    def __post_init__(self) -> None:
        if not self.endpoint_id.strip() or not self.hostname.strip():
            raise ValueError("endpoint_id and hostname are required")
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        unknown = set(self.protocols) - ALLOWED_PROTOCOLS
        if unknown:
            raise ValueError(f"unsupported protocols: {sorted(unknown)}")
        if not self.protocols:
            raise ValueError("at least one TLS protocol must be supplied")
        if self.certificate_expires_at.tzinfo is None:
            raise ValueError("certificate expiry must be timezone-aware")
        if self.key_bits < 0:
            raise ValueError("key_bits cannot be negative")

@dataclass(frozen=True)
class Finding:
    finding_id: str
    endpoint_id: str
    control: str
    severity: str
    score: int
    evidence: str
    remediation: str
    validation: str
    attack_context: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.severity not in ALLOWED_SEVERITIES:
            raise ValueError("invalid severity")
        if not 0 <= self.score <= 100:
            raise ValueError("score must be between 0 and 100")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
