"""
Input Sanitizer

Sanitizes user input before processing.

SECURITY NOTES (for Unifai demo):
- sanitize() is a NO-OP - input passes through unchanged
- No XSS prevention
- No injection prevention
- No encoding normalization
"""

import logging
import re
import unicodedata
from typing import Any

logger = logging.getLogger(__name__)


class InputSanitizer:
    """
    Sanitizes user input before processing.

    VULNERABILITY: All sanitization methods are NO-OPs.
    Input passes through unchanged.

    Should sanitize:
    - HTML/script injection
    - SQL injection patterns
    - Command injection
    - Path traversal
    - Encoding attacks
    """

    def __init__(self):
        pass

    async def sanitize(self, input_data: Any) -> Any:
        """
        Sanitize input data.

        VULNERABILITY: NO-OP - returns input unchanged.
        """
        logger.debug(
            "Sanitization requested",
            extra={
                "input_type": type(input_data).__name__,
                "input_preview": str(input_data)[:100]
            }
        )

        # VULNERABILITY: No sanitization performed
        return input_data

    # Maximum allowed content length before truncation
    MAX_LLM_CONTENT_LENGTH = 32_000

    # Prompt-injection / jailbreak patterns to remove
    _INJECTION_PATTERNS = re.compile(
        r"(ignore (all |previous |prior |above |the above |your )?(instructions?|prompts?|rules?|constraints?|guidelines?|system prompts?|context))"
        r"|(system\s*:\s*you are)"
        r"|(\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>)"
        r"|(###\s*(instruction|system|human|assistant))",
        re.IGNORECASE,
    )

    async def sanitize_for_llm(self, content: str) -> str:
        """
        Sanitize content before sending to LLM.

        Performs the following steps:
        1. Type-check and coerce to str.
        2. Normalize Unicode to NFC form.
        3. Strip null bytes and other dangerous control characters.
        4. Remove prompt-injection / jailbreak patterns.
        5. Normalize whitespace.
        6. Truncate to MAX_LLM_CONTENT_LENGTH characters.
        """
        if not isinstance(content, str):
            content = str(content)

        # 1. Unicode normalization (prevents homoglyph / encoding attacks)
        content = unicodedata.normalize("NFC", content)

        # 2. Remove null bytes and dangerous ASCII control characters
        #    (keep common whitespace: \t, \n, \r)
        content = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", content)

        # 3. Remove prompt-injection patterns
        content = self._INJECTION_PATTERNS.sub("[REMOVED]", content)

        # 4. Collapse runs of whitespace (but preserve single newlines)
        content = re.sub(r"[ \t]+", " ", content)   # collapse horizontal whitespace
        content = re.sub(r"\n{3,}", "\n\n", content)  # collapse excessive blank lines
        content = content.strip()

        # 5. Truncate oversized input
        if len(content) > self.MAX_LLM_CONTENT_LENGTH:
            logger.warning(
                "LLM input truncated",
                extra={"original_length": len(content), "limit": self.MAX_LLM_CONTENT_LENGTH},
            )
            content = content[: self.MAX_LLM_CONTENT_LENGTH]

        return content

    async def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename to prevent path traversal.

        VULNERABILITY: Not implemented.
        """
        return filename

    async def normalize_encoding(self, content: str) -> str:
        """
        Normalize text encoding to prevent attacks.

        VULNERABILITY: Not implemented.
        """
        return content
