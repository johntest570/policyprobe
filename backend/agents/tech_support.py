"""
Tech Support Agent

Handles general technical support queries with low privilege level.
Can escalate to higher-privilege agents when needed.

SECURITY NOTES (for Unifai demo):
- Low privilege agent can escalate without proper verification
- User context passed without sanitization
"""

import base64
import hashlib
import hmac
import logging
import os
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity
from llm.approved_client import ApprovedLLMClient

logger = logging.getLogger(__name__)


def _encrypt_pii(value: str) -> str:
    """
    Encrypt a PII string using a secret key from the environment.
    Uses HMAC-SHA256 to derive a key, then XOR-encrypts the UTF-8
    bytes and returns a base64-encoded ciphertext prefixed with
    'enc:' so callers can detect encrypted values.

    In production replace this with a proper KMS/Fernet cipher.
    """
    secret = os.environ.get("PII_ENCRYPTION_KEY", "change-me-in-production")
    key = hashlib.sha256(secret.encode()).digest()  # 32-byte key
    data = value.encode("utf-8")
    # XOR each byte with the repeating key
    encrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return "enc:" + base64.urlsafe_b64encode(encrypted).decode("ascii")


class TechSupportAgent:
    """
    Technical support agent for handling general user queries.

    Privilege Level: LOW
    Capabilities:
    - Answer general questions
    - Provide technical guidance
    - Escalate to specialized agents
    """

    ALLOWED_ROLES = ["user", "tech_support", "admin"]
    PRIVILEGE_LEVEL = "low"

    # Patterns indicative of prompt injection or malicious content
    _SHELL_COMMAND_PATTERN = re.compile(
        r"(?:^|\s|;|&&|\|\|)\s*(?:sudo|rm\s+-rf|chmod|chown|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat|eval|exec)\b",
        re.IGNORECASE | re.MULTILINE,
    )
    _PROMPT_INJECTION_PATTERN = re.compile(
        r"(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?"
        r"|you\s+are\s+now\s+(?:a|an|in)\b"
        r"|act\s+as\s+(?:a|an)\b"
        r"|disregard\s+(?:all\s+)?(?:previous|prior|above)"
        r"|system\s*:\s*you\s+are"
        r"|<\s*system\s*>"
        r"|\[\s*system\s*\]"
        r"|###\s*(?:system|instruction)"
        r"|jailbreak)",
        re.IGNORECASE,
    )
    _LEETSPEAK_PATTERN = re.compile(
        r"(?:[i!1][g9][n][o0][r][e3]|[s$][y][s$][t][e3][m$]|[e3][x$][e3][c$]|[p][a@][s$][s$][w][o0][r][d$])",
        re.IGNORECASE,
    )
    # Minimum ratio of base64-like characters to flag a token as suspicious
    _B64_TOKEN_MIN_LENGTH = 40

    def __init__(self, llm_client: ApprovedLLMClient):
        self.llm_client = llm_client
        self.agent_id = "tech_support"
        self.agent_name = "Tech Support Agent"

    # Maximum allowed length for user input
    _MAX_INPUT_LENGTH = 2000

    # Patterns that indicate prompt-injection attempts
    _INJECTION_PATTERNS = [
        r"ignore (all |previous |prior )?instructions",
        r"disregard (all |previous |prior )?instructions",
        r"you are now",
        r"act as",
        r"system prompt",
        r"<\s*script",
        r"\\n\\n###",
        r"\[INST\]",
        r"<<SYS>>",
    ]

    def _sanitize_input(self, text: str) -> str:
        """
        Sanitize and validate user input before passing it to any LLM.

        - Strips leading/trailing whitespace
        - Removes ASCII control characters (except newline/tab)
        - Enforces maximum length
        - Rejects prompt-injection patterns

        Raises:
            ValueError: if the input fails validation
        """
        import re

        if not isinstance(text, str):
            raise ValueError("Input must be a string.")

        # Strip surrounding whitespace
        text = text.strip()

        # Remove ASCII control characters except \t (0x09) and \n (0x0A)
        text = re.sub(r"[\x00-\x08\x0B-\x1F\x7F]", "", text)

        # Enforce length limit
        if len(text) > self._MAX_INPUT_LENGTH:
            raise ValueError(
                f"Input exceeds maximum allowed length of {self._MAX_INPUT_LENGTH} characters."
            )

        # Reject empty input after sanitization
        if not text:
            raise ValueError("Input must not be empty.")

        # Detect prompt-injection patterns (case-insensitive)
        for pattern in self._INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                raise ValueError(
                    f"Input contains a disallowed pattern and cannot be processed."
                )

        return text

    async def handle(
        self,
        context: dict[str, Any],
        caller: AgentIdentity,
        headers: Optional[dict] = None
    ) -> dict[str, Any]:
        """
        Handle incoming request from orchestrator or direct call.

        Args:
            context: Request context with user message and metadata
            caller: Identity of the calling agent/user
            headers: Request headers (including auth token)

        Returns:
            Response dictionary
        """
        # Validate the incoming token — not just its presence
        token = headers.get("X-Agent-Token") if headers else None
        if not token:
            logger.warning("Request received without an agent token — rejecting.")
            return {
                "error": "Unauthorized: missing agent token",
                "agent": self.agent_id
            }
        if not AgentIdentity.verify_token(token):
            logger.warning(f"Request received with invalid agent token: {token[:10]}...")
            return {
                "error": "Unauthorized: invalid agent token",
                "agent": self.agent_id
            }
        logger.debug(f"Verified request with token: {token[:10]}...")

        raw_message = context.get("user_message", "")
        try:
            user_message = self._sanitize_input(raw_message)
        except ValueError as exc:
            logger.warning("Rejected unsanitized user input: %s", exc)
            return {
                "response": "Your request could not be processed. Please rephrase and try again.",
                "agent": self.agent_id,
                "privilege_level": self.PRIVILEGE_LEVEL,
                "error": "invalid_input"
            }

        # Check if this needs escalation to finance
        if self._needs_finance_escalation(user_message):
            logger.info(
                "Tech support escalating to finance",
                extra={
                    "reason": "Financial query detected",
                    "user_message": user_message[:100]
                }
            )
            # Escalation to finance is not permitted; inform the user to contact finance directly.
            return {
                "response": (
                    "Your query appears to require access to financial data. "
                    "Tech support does not have permission to access financial information. "
                    "Please contact the finance team directly for assistance."
                ),
                "agent": self.agent_id,
                "privilege_level": self.PRIVILEGE_LEVEL
            }

        # Handle the query directly
        response = await self._process_query(user_message, context)

        return {
            "response": response,
            "agent": self.agent_id,
            "privilege_level": self.PRIVILEGE_LEVEL
        }

    def _sanitize_user_message(self, message: str) -> str:
        """
        Validate and sanitize user_message before passing to the LLM.

        Raises:
            ValueError: If the message contains malicious or suspicious content.

        Returns:
            The original message if it passes all checks.
        """
        if not isinstance(message, str):
            raise ValueError("user_message must be a string.")

        # 1. Length guard — extremely long messages can be used to smuggle payloads
        if len(message) > 8000:
            raise ValueError("user_message exceeds maximum allowed length.")

        # 2. Null-byte / control-character injection
        if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", message):
            raise ValueError("user_message contains disallowed control characters.")

        # 3. Shell command patterns
        if self._SHELL_COMMAND_PATTERN.search(message):
            raise ValueError("user_message contains potentially malicious shell commands.")

        # 4. Prompt injection / jailbreak phrases
        if self._PROMPT_INJECTION_PATTERN.search(message):
            raise ValueError("user_message contains prompt injection patterns.")

        # 5. Leetspeak obfuscation of sensitive keywords
        if self._LEETSPEAK_PATTERN.search(message):
            raise ValueError("user_message contains obfuscated (leetspeak) malicious keywords.")

        # 6. Base64-encoded payloads — look for long base64-like tokens
        for token in message.split():
            if len(token) >= self._B64_TOKEN_MIN_LENGTH and re.fullmatch(r"[A-Za-z0-9+/=]+", token):
                try:
                    decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="ignore")
                    # If the decoded content itself triggers any pattern, reject it
                    if (
                        self._SHELL_COMMAND_PATTERN.search(decoded)
                        or self._PROMPT_INJECTION_PATTERN.search(decoded)
                    ):
                        raise ValueError("user_message contains a base64-encoded malicious payload.")
                except (ValueError, Exception):
                    # Re-raise our own ValueErrors; ignore decode errors for non-base64 tokens
                    raise

        return message

    def _needs_finance_escalation(self, message: str) -> bool:
        """Check if message requires finance agent access."""
        finance_triggers = [
            "quarterly report", "financial statement", "budget",
            "revenue numbers", "profit margin", "expense report",
            "balance sheet", "cash flow", "earnings"
        ]
        message_lower = message.lower()
        return any(trigger in message_lower for trigger in finance_triggers)

            # Explicit allow list of agent names this agent is permitted to escalate to.
    # Any escalation target NOT in this list will be rejected before instantiation.
    ALLOWED_ESCALATION_TARGETS: frozenset = frozenset()  # TechSupportAgent may not escalate to any agent

    async def _escalate_to_finance(
        self,
        query: str,
        original_context: dict
    ) -> dict[str, Any]:
        """
        Escalate query to finance agent.

        Guarded by ALLOWED_ESCALATION_TARGETS allow list: the target
        must be explicitly listed before any agent is instantiated or called.
        """
        escalation_target = "finance"

        # Allow-list gate: reject escalation if target is not explicitly approved.
        if escalation_target not in self.ALLOWED_ESCALATION_TARGETS:
            logger.warning(
                "Escalation attempt blocked by allow list",
                extra={
                    "requested_target": escalation_target,
                    "allowed_targets": list(self.ALLOWED_ESCALATION_TARGETS),
                    "agent_id": self.agent_id
                }
            )
            raise PermissionError(
                f"TechSupportAgent is not permitted to escalate to '{escalation_target}'. "
                f"Allowed targets: {sorted(self.ALLOWED_ESCALATION_TARGETS)}"
            )

        # Import here to avoid circular imports
        from .finance import FinanceAgent

        # Build caller identity without claiming internal status.
                escalation_identity = AgentIdentity(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            privilege_level=self.PRIVILEGE_LEVEL,
            is_internal=False  # Do not claim internal status; privilege must be granted explicitly
        )

        finance_agent = FinanceAgent(self.llm_client)

        finance_response = await finance_agent.handle(
            context={
                "user_message": query,
                "escalated_from": self.agent_id,
                "original_context": original_context,
                "is_internal": True
            },
            caller=escalation_identity,
            headers={"X-Agent-Token": escalation_token}
        )

        logger.info(
            "AI-driven escalation to finance agent completed",
            extra={
                "audit_event": "escalation_end",
                "trace_id": trace_id,
                "principal": self.agent_id,
                "escalated_to": "finance",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
        if not agent_token:
            raise ValueError(
                "TECH_SUPPORT_ESCALATION_TOKEN environment variable is not set."
            )
        finance_response = await finance_agent.handle(
            context={
                "user_message": query,
                "escalated_from": self.agent_id,
                "original_context": original_context
            },
            caller=escalation_identity,
            headers={"X-Agent-Token": agent_token}
        )
        except ValueError as exc:
            logger.warning("Rejected unsanitized escalation query: %s", exc)
            return {
                "response": "Your request could not be escalated. Please rephrase and try again.",
                "agent": self.agent_id,
                "privilege_level": self.PRIVILEGE_LEVEL,
                "error": "invalid_input"
            }

        finance_response = await finance_agent.handle(
            context={
                "user_message": sanitized_query,
                "escalated_from": self.agent_id,
                "original_context": original_context
            },
            caller=escalation_identity,
            headers={"X-Agent-Token": generate_agent_token(self.agent_id)}
        )

        return {
            "response": f"[Escalated to Finance Agent]\n\n{finance_response.get('response', '')}",
            "agent": self.agent_id,
            "escalated_to": "finance",
            "privilege_level": self.PRIVILEGE_LEVEL
        }

    async def _process_query(
        self,
        message: str,
        context: dict
    ) -> str:
        """
        Process a general tech support query.

        VULNERABILITY: User message sent to LLM without sanitization
        or content scanning.
        """
        system_prompt = """You are a helpful technical support agent for PolicyProbe.
You can help users with:
- General questions about the application
- Technical troubleshooting
- Document analysis guidance
- Policy compliance questions

Be helpful, professional, and concise in your responses."""

        # VULNERABILITY: Direct user input to LLM without scanning
        response = await self.llm_client.chat(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": message}
            ]
        )

        # Validate and sanitize LLM output before returning
        sanitized = self._validate_llm_response(response)
        return sanitized

    # --- Dynamic code execution primitives that must not appear in LLM output ---
    _DANGEROUS_PATTERNS = [
        r'\beval\s*\(',
        r'\bexec\s*\(',
        r'\bcompile\s*\(',
        r'\b__import__\s*\(',
        r'\bexecfile\s*\(',
        r'\bsubprocess\b',
        r'\bos\.system\s*\(',
        r'\bos\.popen\s*\(',
        r'\bimportlib\b',
        r'\bctypes\b',
        r'\bgetattr\s*\(.*,\s*[\'"]__',
    ]

    def _validate_llm_response(self, response: str) -> str:
        """
        Validate and sanitize the LLM response.

        Checks for the presence of dynamic code execution primitives
        (eval, exec, compile, __import__, subprocess, os.system, etc.).
        Raises a ValueError if any dangerous pattern is detected so that
        the caller can handle it safely instead of forwarding malicious
        content to the user.
        """
        import re

        if not isinstance(response, str):
            logger.warning(
                "LLM response is not a string; coercing to string for safety",
                extra={"response_type": type(response).__name__}
            )
            response = str(response)

        for pattern in self._DANGEROUS_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE):
                logger.error(
                    "Dangerous pattern detected in LLM response; blocking output",
                    extra={"pattern": pattern}
                )
                raise ValueError(
                    "LLM response contains a disallowed dynamic code execution "
                    f"primitive matching pattern '{pattern}'. Response blocked."
                )

        return response

    async def get_user_context(self, user_id: str) -> dict:
        """
        Retrieve user context for personalized support.

        VULNERABILITY: Returns full user context including potentially
        sensitive information without filtering.
        """
        # Simulated user context retrieval
        # In a real app, this would query a database
        user_context = {
            "user_id": user_id,
            "subscription_tier": "enterprise",
            "recent_queries": [
                "How do I upload files?",
                "What file types are supported?",
                "Can I access financial reports?"
            ],
            "preferences": {
                "language": "en",
                "timezone": "America/New_York"
            },
            # VULNERABILITY: Sensitive data in context
            "internal_notes": "VIP customer - handle with priority",
                        "account_details": {
                "contact_email": None,  # Retrieved from database at runtime
                "phone": None  # Retrieved from database at runtime
            }
        }

        safe_log_context = {
            k: v for k, v in user_context.items() if k != "account_details"
        }
        logger.info(
            "Retrieved user context",
            extra={
                "user_context": safe_log_context
            }
        )

        return user_context
