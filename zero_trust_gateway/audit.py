"""Allow-listed structured audit events that never accept credentials."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Protocol


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event: str
    outcome: str
    request_id: str
    client_ip: str
    reason: str
    method: str
    route: str
    status: int
    subject: str | None = None
    role: str | None = None


class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...


class StructuredAuditLogger:
    """Write one compact JSON object per security decision."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger("zero_trust_gateway.audit")

    def emit(self, event: AuditEvent) -> None:
        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            **{key: value for key, value in asdict(event).items() if value is not None},
        }
        self._logger.info(json.dumps(record, sort_keys=True, separators=(",", ":")))
