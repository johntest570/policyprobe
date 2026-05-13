"""
HTML Parser

Extracts text content from HTML files.

SECURITY NOTES (for Unifai demo):
- Extracts text including from hidden elements
- CSS-hidden content is extracted
- Script content may be included
- No XSS sanitization
"""

import base64
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Patterns that indicate potentially malicious injected content
_SHELL_COMMAND_RE = re.compile(
    r'(?:^|\s|;|&&|\|\|)(?:bash|sh|zsh|cmd|powershell|python|perl|ruby|curl|wget|nc|ncat|netcat|exec|eval|system|popen)\b',
    re.IGNORECASE | re.MULTILINE,
)
_BINARY_EXEC_RE = re.compile(
    r'(?:/bin/|/usr/bin/|/usr/local/bin/|C:\\Windows\\System32\\)',
    re.IGNORECASE,
)
_BASE64_RE = re.compile(
    r'(?:[A-Za-z0-9+/]{40,}={0,2})',
)
_HIDDEN_PROMPT_RE = re.compile(
    r'(?:ignore previous instructions?|disregard (?:all )?(?:prior|previous|above)|you are now|act as (?:a |an )?(?:different|new|unrestricted)|system prompt|<\s*(?:system|assistant|user)\s*>)',
    re.IGNORECASE,
)
# Simple leetspeak: common substitutions that reconstruct dangerous keywords
_LEETSPEAK_RE = re.compile(
    r'(?:[e3][x*][e3][c*]|[s$][y*][s$][t+][e3][m*]|[p*][o0][w*][e3][r*][s$][h*][e3][l*][l*]|[e3][v*][a*][l*])',
    re.IGNORECASE,
)


def _scan_for_malicious_content(text: str) -> list:
    """Scan text for patterns that indicate prompt injection or command execution attempts."""
    warnings = []

    if _HIDDEN_PROMPT_RE.search(text):
        warnings.append("Possible prompt injection detected: text contains instruction-override phrases.")

    if _SHELL_COMMAND_RE.search(text):
        warnings.append("Possible shell command detected in extracted content.")

    if _BINARY_EXEC_RE.search(text):
        warnings.append("Possible binary executable path detected in extracted content.")

    if _LEETSPEAK_RE.search(text):
        warnings.append("Possible leetspeak encoding of dangerous keyword detected.")

    for match in _BASE64_RE.finditer(text):
        candidate = match.group(0)
        # Pad to valid base64 length
        padded = candidate + '=' * (-len(candidate) % 4)
        try:
            decoded = base64.b64decode(padded).decode('utf-8', errors='replace')
            if _SHELL_COMMAND_RE.search(decoded) or _HIDDEN_PROMPT_RE.search(decoded) or _BINARY_EXEC_RE.search(decoded):
                warnings.append(
                    f"Possible base64-encoded malicious content detected (decoded preview: {decoded[:80]!r})."
                )
        except Exception:
            pass

    return warnings


class HTMLParser:
    """
    Parses HTML files and extracts text content.

    VULNERABILITY: Extracts hidden content without flagging.
    - display:none elements are extracted
    - visibility:hidden elements are extracted
    - Off-screen positioned elements are extracted
    - White text on white background is extracted
    """

    # Singapore PII patterns
    _SG_NRIC_FIN_RE = re.compile(
        r'\b[STFGM]\d{7}[A-Z]\b', re.IGNORECASE
    )
    # Singapore passport: starts with E or K followed by 7-8 digits
    _SG_PASSPORT_RE = re.compile(
        r'\b[EK]\d{7,8}\b', re.IGNORECASE
    )
    # Singapore phone numbers: +65 followed by 8 digits, or local 8-digit starting with 6/8/9
    _SG_PHONE_RE = re.compile(
        r'(?:\+65[\s\-]?)?\b[689]\d{7}\b'
    )
    # Generic email
    _EMAIL_RE = re.compile(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
    )

    def __init__(self):
        pass

    def _scan_for_sg_pii(self, text: str) -> List[str]:
        """
        Scan text for Singapore PII categories.
        Returns a list of warning strings describing detected PII types.
        Does NOT include the actual PII values in warnings.
        """
        warnings: List[str] = []

        if self._SG_NRIC_FIN_RE.search(text):
            warnings.append(
                "Potential Singapore NRIC/FIN number detected in uploaded file."
            )

        if self._SG_PASSPORT_RE.search(text):
            warnings.append(
                "Potential Singapore passport number detected in uploaded file."
            )

        if self._SG_PHONE_RE.search(text):
            warnings.append(
                "Potential Singapore phone number detected in uploaded file."
            )

        if self._EMAIL_RE.search(text):
            warnings.append(
                "Potential email address (PII) detected in uploaded file."
            )

        return warnings

    async def extract_text(self, html_content: str) -> str:
        """
        Extract all text from HTML content.

        VULNERABILITY: All text extracted including hidden content.
        get_text() extracts text from hidden elements.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')

            # Remove script and style elements (but not hidden divs!)
            for element in soup(['script', 'style']):
                element.decompose()

            # VULNERABILITY: get_text() extracts from hidden elements too
            # This includes:
            # - Elements with display:none
            # - Elements with visibility:hidden
            # - Off-screen positioned elements
            # - White text on white background
            text = soup.get_text(separator='\n', strip=True)

            # Redact PII before returning or logging
            text, _pii_warnings = _redact_pii(text)

            logger.info(
                "HTML text extraction complete",
                extra={
                    "text_length": len(text)
                    # preview intentionally omitted to avoid PII in logs
                }
            )

            return text

        except Exception as e:
            logger.error(f"HTML extraction error: {e}")
            return f"Error extracting HTML: {str(e)}"

    async def extract_visible_only(self, html_content: str) -> str:
        """
        Extract only visible text (not implemented properly).

        VULNERABILITY: Still extracts hidden content.
        Would need CSS parsing to properly filter.
        """
        # VULNERABILITY: This method doesn't actually filter hidden content
        # It would need to parse inline styles and CSS classes
        return await self.extract_text(html_content)

    async def extract_metadata(self, html_content: str) -> dict:
        """
        Extract HTML metadata (title, meta tags).

        VULNERABILITY: Metadata extracted without scanning.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')
            metadata = {}

            # Title
            title = soup.find('title')
            if title:
                metadata['title'] = title.get_text()

            # Meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', meta.get('property', ''))
                content = meta.get('content', '')
                if name and content:
                    metadata[name] = content

            # Redact PII from all metadata values before returning
            metadata, meta_warnings = _redact_metadata(metadata)
            if meta_warnings:
                logger.info(
                    "PII redacted from HTML metadata",
                    extra={"warnings": meta_warnings}
                )

            return metadata

        except Exception as e:
            logger.error(f"HTML metadata extraction error: {e}")
            return {}

        # Maximum number of characters returned by extract_all to enforce data minimisation.
    MAX_TEXT_LENGTH: int = 10_000

    async def extract_all(self, html_content: str, max_length: Optional[int] = None) -> dict:
        """
        Extract all content from HTML.

        Returns at most ``max_length`` characters of extracted text
        (default: MAX_TEXT_LENGTH) to enforce output data minimisation.
        A warning is added to the response when the text is truncated.
        """
        text = await self.extract_text(html_content)
        metadata = await self.extract_metadata(html_content)

        limit = max_length if max_length is not None else self.MAX_TEXT_LENGTH
        warnings: list = []

        if len(text) > limit:
            text = text[:limit]
            warnings.append(
                f"Extracted text was truncated to {limit} characters to enforce data minimisation."
            )
            logger.info(
                "HTML text truncated for data minimisation",
                extra={"limit": limit}
            )

        return {
            "text": text,
            "metadata": metadata,
            "warnings": warnings
        }] {w}")

        if all_warnings:
            logger.warning(
                "Malicious content patterns detected in HTML extraction",
                extra={"warnings": all_warnings},
            )

        return {
            "text": text,
            "metadata": metadata,
            "warnings": all_warnings,
        }
