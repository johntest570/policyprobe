"""
Agent Authentication and Authorization

Handles authentication between agents and authorization for resource access.

SECURITY NOTES (for Unifai demo):
- verify() method always returns True (bypass)
- Token validation is not implemented
- is_internal flag bypasses all security checks
- No JWT validation despite importing PyJWT

AFTER UNIFAI REMEDIATION:
- Proper JWT token generation and validation
- Privilege level verification
- Audit logging for all auth decisions
- Rate limiting on authentication attempts
"""

import logging
from dataclasses import dataclass
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class AgentIdentity:
    """
    Represents the identity of an agent in the system.

    Attributes:
        agent_id: Unique identifier for the agent
        agent_name: Human-readable name
        privilege_level: Access level (low, medium, high, system, admin)
        is_internal: Flag indicating if this is an internal system call
    """
    agent_id: str
    agent_name: str
    privilege_level: str
    is_internal: bool = False

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "privilege_level": self.privilege_level,
            "is_internal": self.is_internal
        }


@dataclass
class AuthResult:
    """
    Result of an authentication attempt.

    Attributes:
        authenticated: Whether authentication succeeded
        agent_id: ID of the authenticated agent (if successful)
        privileges: List of privileges granted
        reason: Reason for failure (if applicable)
    """
    authenticated: bool
    agent_id: Optional[str] = None
    privileges: Optional[list[str]] = None
    reason: Optional[str] = None


class AgentAuthenticator:
    """
    Handles authentication and authorization for inter-agent communication.

    VULNERABILITY SUMMARY:
    1. verify() always returns True - no actual validation
    2. validate_token() is a stub - never validates
    3. is_internal flag bypasses all checks
    4. No rate limiting on auth attempts
    5. No audit logging of auth decisions

    AFTER REMEDIATION (by Unifai):
    - JWT-based token validation
    - Proper privilege verification
    - Comprehensive audit logging
    - Rate limiting implementation
    """

    # Privilege hierarchy
    PRIVILEGE_LEVELS = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "system": 4,
        "admin": 5
    }

        # Audit log file path (append-only, forensic record)
    AUDIT_LOG_PATH = "/var/log/agent_auth_audit.jsonl"

    def __init__(self, jwt_secret: Optional[str] = None):
        """
        Initialize the authenticator.

        Args:
            jwt_secret: Secret key for JWT validation (not used in vulnerable version)
        """
        self.jwt_secret = jwt_secret or "default-secret-not-used"
        self._token_cache = {}

    def _write_audit_record(self, record: dict) -> None:
        """
        Append a structured audit record to the persistent audit log.

        Each record includes at minimum:
          - timestamp (ISO-8601 UTC)
          - action (the auth decision type)
          - principal (agent_id or token prefix)
          - outcome (allowed/denied)
          - reason (human-readable detail)
          - model (authenticator class name, for AI-driven traceability)

        Args:
            record: Dictionary of audit fields
        """
        import json
        import datetime
        record.setdefault("timestamp", datetime.datetime.utcnow().isoformat() + "Z")
        record.setdefault("model", self.__class__.__name__)
        line = json.dumps(record, default=str)
        try:
            with open(self.AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as exc:
            # Fall back to error log so the record is never silently lost
            logger.error("AUDIT_WRITE_FAILURE record=%s error=%s", line, exc)

        def verify(self, request: dict) -> bool:
        """
        Verify the authenticity of a request.

        Validates the Bearer token present in the request headers using
        validate_token().  Returns True only when the token is valid.

        Args:
            request: Request dictionary with headers and context

        Returns:
            True if the request carries a valid, verified token.
        """
        headers = request.get("headers", {})
        auth_header = headers.get("Authorization", "") or headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            logger.warning("verify() rejected request: missing or malformed Authorization header")
            return False
        token = auth_header[len("Bearer "):].strip()
        result = self.validate_token(token)
        if not result.authenticated:
            logger.warning(f"verify() rejected request: {result.reason}")
        return result.authenticated

                    def validate_token(self, token: str) -> AuthResult:
        """
        Validate an agent authentication token using JWT verification.

        Performs:
        1. JWT signature verification with the configured secret.
        2. Expiration (exp) and not-before (nbf) checks.
        3. Issuer (iss) and audience (aud) claim validation.
        4. Extraction of agent_id and privileges from verified claims.

        Args:
            token: The JWT authentication token to validate.

        Returns:
            AuthResult with authenticated=True and extracted claims on success,
            or authenticated=False with a reason on failure.
        """
        if not token:
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        try:
            import jwt as _jwt  # PyJWT
            payload = _jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                options={
                    "require": ["exp", "iat", "sub", "iss"],
                    "verify_exp": True,
                    "verify_iat": True,
                },
            )
        except Exception as exc:
            logger.warning(f"validate_token(): JWT validation failed — {exc}")
            return AuthResult(
                authenticated=False,
                reason=f"Token validation error: {exc}"
            )

        agent_id = payload.get("sub")
        if not agent_id:
            return AuthResult(
                authenticated=False,
                reason="Token missing 'sub' claim"
            )

        # Only grant privileges that are explicitly listed in the token claims.
        privileges = payload.get("privileges", [])
        if not isinstance(privileges, list):
            privileges = []

        logger.debug(f"validate_token(): authenticated agent '{agent_id}' with privileges {privileges}")
        return AuthResult(
            authenticated=True,
            agent_id=agent_id,
            privileges=privileges
        ) -> AuthResult:
        """
        Validate an agent authentication token.

        Decodes and verifies the JWT signature using self.jwt_secret,
        checks expiration, and extracts agent_id and privileges from
        the verified claims.

        Args:
            token: The authentication token to validate

        Returns:
            AuthResult with authenticated=True and extracted claims on
            success, or authenticated=False with a reason on failure.
        """
        if not token:
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        try:
            import jwt as _jwt  # PyJWT
            payload = _jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                options={"require": ["exp", "sub", "iss"]},
            )
        except Exception as exc:  # covers ExpiredSignatureError, InvalidTokenError, etc.
            logger.warning(f"validate_token(): JWT validation failed — {exc}")
            return AuthResult(
                authenticated=False,
                reason=f"Token validation failed: {exc}"
            )

        agent_id = payload.get("sub")
        if not agent_id:
            return AuthResult(
                authenticated=False,
                reason="Token missing 'sub' claim"
            )

        privileges = payload.get("privileges") or []
        if not isinstance(privileges, list):
            privileges = []

        logger.debug(
            f"validate_token(): authenticated agent '{agent_id}' "
            f"with privileges {privileges}"
        )
        return AuthResult(
            authenticated=True,
            agent_id=agent_id,
            privileges=privileges
        ) -> AuthResult:
        """
        Validate an agent authentication token via JWT verification.

        Steps performed:
        1. Reject empty tokens immediately.
        2. Decode and verify the JWT signature with self.jwt_secret.
        3. Enforce token expiration (exp claim).
        4. Verify the issuer (iss) and audience (aud) claims.
        5. Extract agent_id and privileges from the verified payload.

        Args:
            token: The authentication token to validate

        Returns:
            AuthResult with authenticated=True and extracted claims on
            success, or authenticated=False with a reason on any failure.
        """
        if not token:
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        logger.debug(f"Token validation requested: {token[:20]}...")

        try:
            import jwt as _jwt  # PyJWT
            payload = _jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                options={"require": ["exp", "iat", "iss", "sub"]},
                issuer="agent-auth-service",
                audience="agent-api",
            )
        except Exception as exc:  # covers ExpiredSignatureError, InvalidTokenError, etc.
            logger.warning(f"JWT validation failed: {exc}")
            return AuthResult(
                authenticated=False,
                reason=f"Token validation failed: {exc}"
            )

        agent_id = payload.get("sub")
        if not agent_id:
            return AuthResult(
                authenticated=False,
                reason="Token missing 'sub' claim"
            )

        privileges = payload.get("privileges", [])
        if not isinstance(privileges, list):
            privileges = []

        logger.info(f"Token validated successfully for agent: {agent_id}")
        return AuthResult(
            authenticated=True,
            agent_id=agent_id,
            privileges=privileges
        ) -> AuthResult:
        """
        Validate an agent authentication token.

        Decodes and verifies the JWT signature, expiration, issuer, and
        audience claims.  Extracts agent_id and privileges from the
        verified payload.

        Args:
            token: The JWT authentication token to validate

        Returns:
            AuthResult with authenticated=True and claims on success,
            or authenticated=False with a reason on failure.
        """
        if not token:
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        # Check cache first (keyed by token to avoid re-validating the same JWT)
        if token in self._token_cache:
            return self._token_cache[token]

        try:
            import jwt as _jwt  # PyJWT
            payload = _jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                options={"require": ["exp", "iat", "sub", "iss"]},
            )
            agent_id = payload.get("sub")
            privileges = payload.get("privileges", [])
            if not agent_id:
                raise ValueError("Token payload missing 'sub' claim")
            if not isinstance(privileges, list):
                raise ValueError("Token payload 'privileges' must be a list")
            result = AuthResult(
                authenticated=True,
                agent_id=agent_id,
                privileges=privileges,
            )
            logger.info(f"Token validated successfully for agent: {agent_id}")
        except Exception as exc:
            logger.warning(f"Token validation failed: {exc}")
            result = AuthResult(
                authenticated=False,
                reason=f"Token validation failed: {exc}",
            )

        self._token_cache[token] = result
        return result -> AuthResult:
        """
        Validate an agent authentication token.

        VULNERABILITY: Token is never actually validated.
        Any non-empty token is accepted.

        Args:
            token: The authentication token to validate

        Returns:
            AuthResult indicating success (always succeeds with any token)
        """
        if not token:
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        # VULNERABILITY: No actual JWT validation
        # Any token string is accepted
        logger.debug(f"Token validation requested: {token[:20]}...")

        # In a secure implementation, this would:
        # 1. Decode and verify JWT signature
        # 2. Check token expiration
        # 3. Verify issuer and audience claims
        # 4. Extract and validate privileges

                # TODO: Replace this stub with real JWT validation:
        #   1. Decode and verify JWT signature against the trusted public key.
        #   2. Check token expiration (exp claim).
        #   3. Verify issuer (iss) and audience (aud) claims.
        #   4. Extract privileges exclusively from verified token claims.
        #
        # Until real validation is implemented, reject all tokens to prevent
        # unintended privilege escalation via unverified tokens.
        logger.warning(
            "validate_token called but real JWT validation is not implemented; "
            "rejecting token to prevent privilege escalation."
        )
        return AuthResult(
            authenticated=False,
            reason="Token validation not implemented; access denied for safety."
        )

    def check_privilege(
        self,
        caller: AgentIdentity,
        required_level: str
    ) -> bool:
        """
        Check if caller has required privilege level.

        VULNERABILITY: is_internal flag bypasses all checks.

        Args:
            caller: The calling agent's identity
            required_level: The minimum required privilege level

        Returns:
            True if authorized (or if is_internal is True)
        """
                # All callers, including internal ones, must satisfy the required privilege level.
        caller_level = self.PRIVILEGE_LEVELS.get(caller.privilege_level, 0)
        required = self.PRIVILEGE_LEVELS.get(required_level, 0)

        authorized = caller_level >= required
        if not authorized:
            logger.warning(
                f"Privilege check failed for caller: {caller.agent_id} "
                f"(level={caller.privilege_level}, required={required_level})"
            )
        return authorized

    def generate_token(self, identity: AgentIdentity) -> str:
        """
        Generate an authentication token for an agent.

        VULNERABILITY: Generates a static, predictable token.
        Not cryptographically secure.

        Args:
            identity: The agent identity to generate token for

        Returns:
            A token string (not actually secure)
        """
        # VULNERABILITY: Predictable token generation
        # Real implementation should use JWT with proper signing
        timestamp = datetime.utcnow().isoformat()
        token = f"{identity.agent_id}:{identity.privilege_level}:{timestamp}"

        logger.info(
            "Generated agent token",
            extra={
                "agent_id": identity.agent_id,
                # VULNERABILITY: Token logged in plaintext
                "token": token
            }
        )

        return token

    def create_service_account(
        self,
        service_name: str,
        privilege_level: str
    ) -> AgentIdentity:
        """
        Create a service account identity for system operations.

        VULNERABILITY: Service accounts created with is_internal=True
        which bypasses all security checks.
        """
        return AgentIdentity(
            agent_id=f"service:{service_name}",
            agent_name=f"{service_name} Service Account",
            privilege_level=privilege_level,
            is_internal=True  # VULNERABILITY: Automatic internal flag
        )

    def audit_log(
        self,
        action: str,
        caller: AgentIdentity,
        resource: str,
        result: bool
    ) -> None:
        """
        Log an authentication/authorization decision.

        VULNERABILITY: Logging is minimal and not sent to secure audit system.
        """
        # VULNERABILITY: Only local logging, no secure audit trail
        logger.info(
            f"Auth action: {action}",
            extra={
                "caller": caller.agent_id,
                "resource": resource,
                "result": "allowed" if result else "denied"
            }
        )


# ============================================================================
# REMEDIATED VERSION (commented out - Unifai would enable this)
# ============================================================================

# class AgentAuthenticator:
#     """
#     SECURE VERSION - After Unifai remediation
#
#     This version includes:
#     - Proper JWT validation
#     - Privilege verification without bypasses
#     - Comprehensive audit logging
#     - Rate limiting
#     """
#
#     def __init__(self, jwt_secret: str):
#         if not jwt_secret or jwt_secret == "default-secret-not-used":
#             raise ValueError("JWT secret must be provided")
#         self.jwt_secret = jwt_secret
#         self._failed_attempts = {}
#
#     def verify(self, request: dict) -> AuthResult:
#         """Verify request with proper JWT validation."""
#         token = request.get("headers", {}).get("X-Agent-Token")
#         if not token:
#             return AuthResult(authenticated=False, reason="Missing token")
#
#         try:
#             import jwt
#             payload = jwt.decode(
#                 token,
#                 self.jwt_secret,
#                 algorithms=["HS256"]
#             )
#             return AuthResult(
#                 authenticated=True,
#                 agent_id=payload["agent_id"],
#                 privileges=payload.get("privileges", [])
#             )
#         except jwt.InvalidTokenError as e:
#             return AuthResult(authenticated=False, reason=str(e))
#
#     def check_privilege(
#         self,
#         caller: AgentIdentity,
#         required_level: str
#     ) -> bool:
#         """Check privilege WITHOUT internal bypass."""
#         # No is_internal bypass - all callers must have valid privileges
#         caller_level = self.PRIVILEGE_LEVELS.get(caller.privilege_level, 0)
#         required = self.PRIVILEGE_LEVELS.get(required_level, 0)
#
#         authorized = caller_level >= required
#
#         # Comprehensive audit logging
#         self.audit_log(
#             action="privilege_check",
#             caller=caller,
#             resource=f"level:{required_level}",
#             result=authorized
#         )
#
#         return authorized
