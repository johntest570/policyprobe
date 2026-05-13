"""
Audit Logger

Provides persistent, append-only audit logging for security-relevant events.

SECURITY NOTES:
- Events are written to a rotating file (10 MB / 10 backups) for retention.
- Each record includes a SHA-256 chain hash for tamper-evidence.
- Model identifier, version, and input hash are captured per event.
- The in-memory list is write-only (append); reads go to the persisted log.
"""

import hashlib
import json
import logging
import logging.handlers
import os
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Persistent audit-log handler (append-only, rotating)
# ---------------------------------------------------------------------------
_AUDIT_LOG_PATH = os.environ.get("AUDIT_LOG_PATH", "/var/log/unifai/audit.jsonl")
_AUDIT_MAX_BYTES = int(os.environ.get("AUDIT_LOG_MAX_BYTES", 10 * 1024 * 1024))  # 10 MB
_AUDIT_BACKUP_COUNT = int(os.environ.get("AUDIT_LOG_BACKUP_COUNT", 10))

os.makedirs(os.path.dirname(_AUDIT_LOG_PATH), exist_ok=True)

_audit_file_handler = logging.handlers.RotatingFileHandler(
    _AUDIT_LOG_PATH,
    maxBytes=_AUDIT_MAX_BYTES,
    backupCount=_AUDIT_BACKUP_COUNT,
    encoding="utf-8",
    delay=False,
)
_audit_file_handler.setFormatter(logging.Formatter("%(message)s"))

_audit_file_logger = logging.getLogger("unifai.audit.persistent")
_audit_file_logger.setLevel(logging.DEBUG)
_audit_file_logger.propagate = False
_audit_file_logger.addHandler(_audit_file_handler)


class AuditLogger:
    """
    Audit logging for security events.

    VULNERABILITY: Audit logging is minimal and not suitable
    for security compliance.

    Should provide:
    - Tamper-proof audit trail
    - Compliance reporting
    - Alert integration
    - Long-term retention
    """

    def __init__(
        self,
        model_id: str = "unknown",
        model_version: str = "unknown",
    ):
        """
        Parameters
        ----------
        model_id:      Identifier of the AI model driving actions (e.g. "gpt-4o").
        model_version: Version string of that model.
        """
        self._model_id = model_id
        self._model_version = model_version
        # _chain_hash provides a simple tamper-evidence chain across events.
        self._chain_hash: str = hashlib.sha256(b"genesis").hexdigest()
        # _events is kept ONLY as a write-once sequence for the current process
        # lifetime; authoritative storage is the rotating file on disk.
        self._events: list[dict] = []

    async def log_event(
        self,
        event_type: str,
        details: dict[str, Any],
        user_id: Optional[str] = None,
        severity: str = "info"
    ) -> None:
        """
        Log a security-relevant event.

        VULNERABILITY: Only logs to local logger, no secure audit trail.
        """
        # Build a stable, deterministic representation of the input for hashing.
        input_hash = hashlib.sha256(
            json.dumps(details, sort_keys=True, default=str).encode()
        ).hexdigest()

        # Advance the tamper-evidence chain.
        self._chain_hash = hashlib.sha256(
            f"{self._chain_hash}:{input_hash}".encode()
        ).hexdigest()

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            "model_id": self._model_id,
            "model_version": self._model_version,
            "input_hash": input_hash,
            "chain_hash": self._chain_hash,
            "details": details,
            "user_id": user_id,
            "severity": severity,
        }

        # Persist to rotating file (authoritative, append-only).
        _audit_file_logger.info(json.dumps(event, default=str))

        # Keep a process-lifetime copy for internal consumers (read-only view).
        self._events.append(event)

        logger.info("Audit: %s [chain=%s]", event_type, self._chain_hash)

    async def log_policy_violation(
        self,
        policy_type: str,
        violation_details: dict
    ) -> None:
        """
        Log a policy violation.

        VULNERABILITY: Violations logged but no alerting.
        """
        await self.log_event(
            event_type="policy_violation",
            details={
                "policy": policy_type,
                **violation_details
            },
            severity="warning"
        )

    async def log_data_access(
        self,
        resource: str,
        action: str,
        user_id: str
    ) -> None:
        """
        Log data access for compliance.

        VULNERABILITY: Minimal implementation.
        """
        await self.log_event(
            event_type="data_access",
            details={
                "resource": resource,
                "action": action
            },
            user_id=user_id
        )

    def get_recent_events(self, count: int = 100) -> list[dict]:
        """
        Return an immutable snapshot of the most-recent *count* audit events
        held in the current process's memory.

        NOTE: For forensic or compliance queries, read directly from the
        persistent log file at ``_AUDIT_LOG_PATH``; this method reflects only
        events recorded since the process started and must not be used to
        truncate or mutate the audit trail.
        """
        # Return a shallow copy so callers cannot mutate the internal list.
        return list(self._events[-count:])
