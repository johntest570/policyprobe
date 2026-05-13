"""
Content Scanner Module

Extracts and analyzes hidden content from various file formats.

SECURITY NOTES (for Unifai demo):
- Extracts hidden content but does NOT flag it as suspicious
- Hidden text extraction works but no threat analysis
- EXIF extraction works but no scanning of contents
- Acts as a utility, not a security control

AFTER UNIFAI REMEDIATION:
- Extracted hidden content is flagged for review
- Automatic threat detection on extracted content
- Integration with prompt injection detector
"""

import hashlib
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

_AUDIT_LOG_PATH = Path("audit_logs/content_scanner_audit.jsonl")
_SCANNER_VERSION = "content_scanner/1.0.0"
_PRINCIPAL = "content_scanner_service"


def _write_audit_record(record: dict) -> None:
    """Append a single audit record as a JSON line to the audit log (append-only)."""
    _AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _AUDIT_LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, default=str) + "\n")

# PII patterns for redaction
_PII_PATTERNS = [
    # Email addresses
    (re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'), '[EMAIL REDACTED]'),
    # US phone numbers (various formats)
    (re.compile(r'(\+?1[\s\-.]?)?(\(?\d{3}\)?[\s\-.]?)\d{3}[\s\-.]?\d{4}'), '[PHONE REDACTED]'),
    # US Social Security Numbers
    (re.compile(r'\b\d{3}[\s\-]\d{2}[\s\-]\d{4}\b'), '[SSN REDACTED]'),
    # Credit card numbers (basic pattern)
    (re.compile(r'\b(?:\d[ \-]?){13,16}\b'), '[CC REDACTED]'),
    # IP addresses
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[IP REDACTED]'),
    # Dates of birth (common formats)
    (re.compile(r'\b(0?[1-9]|1[0-2])[/\-](0?[1-9]|[12]\d|3[01])[/\-](\d{2}|\d{4})\b'), '[DATE REDACTED]'),
    # US ZIP codes
    (re.compile(r'\b\d{5}(?:[\-]\d{4})?\b'), '[ZIP REDACTED]'),
    # Passport / ID numbers (generic alphanumeric 6-9 chars preceded by keyword)
    (re.compile(r'(?i)\b(passport|ssn|sin|id|license)[\s#:]*[A-Z0-9]{6,12}\b'), '[ID REDACTED]'),
]


def _redact_pii(text: str) -> str:
    """Apply all PII redaction patterns to the given text string."""
    if not text:
        return text
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _redact_content(extracted: 'ExtractedContent') -> 'ExtractedContent':
    """Redact PII from all text fields of an ExtractedContent instance."""
    extracted.visible_text = _redact_pii(extracted.visible_text or '')
    if extracted.hidden_text is not None:
        extracted.hidden_text = _redact_pii(extracted.hidden_text)
    if extracted.encoded_content:
        extracted.encoded_content = [_redact_pii(c) for c in extracted.encoded_content]
    if extracted.metadata:
        extracted.metadata = {
            k: _redact_pii(str(v)) if isinstance(v, str) else v
            for k, v in extracted.metadata.items()
        }
    return extracted

logger = logging.getLogger(__name__)


@dataclass
class ExtractedContent:
    """Container for extracted content from files."""
    visible_text: str
    hidden_text: Optional[str] = None
    metadata: Optional[dict] = None
    encoded_content: Optional[list[str]] = None
    warnings: Optional[list[str]] = None


class ContentScanner:
    """
    Scans and extracts content from various file formats.

    This scanner extracts:
    - Visible text content
    - Hidden text (CSS hidden, white-on-white, etc.)
    - File metadata
    - Encoded content (base64, etc.)

    VULNERABILITY: This scanner extracts hidden content but does NOT
    treat it as suspicious. All extracted content is passed through
    to the LLM without security analysis.
    """

    def __init__(self):
        self.extraction_count = 0


# ---------------------------------------------------------------------------
# Security helper: malicious pattern detection
# ---------------------------------------------------------------------------
import re as _re

_MALICIOUS_PATTERNS = [
    # Shell command injection
    (_re.compile(r'(?:^|\s|;|&&|\|\|)\s*(?:bash|sh|zsh|ksh|csh|fish)\s', _re.IGNORECASE | _re.MULTILINE), "shell_interpreter"),
    (_re.compile(r'(?:^|\s|;|&&|\|\|)\s*(?:cmd\.exe|powershell(?:\.exe)?|pwsh)(?:\s|$)', _re.IGNORECASE | _re.MULTILINE), "windows_shell"),
    (_re.compile(r'(?:rm\s+-rf|del\s+/[sqf]|format\s+[a-z]:)', _re.IGNORECASE), "destructive_command"),
    (_re.compile(r'(?:curl|wget)\s+.*(?:http|ftp)s?://', _re.IGNORECASE), "remote_fetch"),
    (_re.compile(r'(?:nc|netcat|ncat)\s+.*-[el]', _re.IGNORECASE), "reverse_shell"),
    (_re.compile(r'(?:python|python3|perl|ruby|node)\s+-[ce]\s+["\']?(?:import|require|exec|eval|os\.)', _re.IGNORECASE), "code_execution"),
    (_re.compile(r'(?:eval|exec)\s*\(', _re.IGNORECASE), "eval_exec"),
    (_re.compile(r'(?:base64\s+-d|base64\s+--decode)', _re.IGNORECASE), "base64_decode_shell"),
    # Prompt injection patterns
    (_re.compile(r'ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?', _re.IGNORECASE), "prompt_injection_ignore"),
    (_re.compile(r'(?:you\s+are\s+now|act\s+as|pretend\s+(?:you\s+are|to\s+be))\s+(?:an?\s+)?(?:evil|malicious|unrestricted|jailbroken|DAN)', _re.IGNORECASE), "prompt_injection_persona"),
    (_re.compile(r'(?:system\s*prompt|system\s*message)\s*[:=]', _re.IGNORECASE), "prompt_injection_system"),
    (_re.compile(r'<\s*(?:system|INST|SYS)\s*>', _re.IGNORECASE), "prompt_injection_tag"),
    # Binary / executable indicators
    (_re.compile(r'\x7fELF'), "elf_binary"),
    (_re.compile(r'MZ\x90\x00'), "pe_binary"),
    (_re.compile(r'#!/(?:bin|usr/bin|usr/local/bin)/', _re.IGNORECASE), "shebang"),
]


def _scan_for_malicious_patterns(text: str, source: str = "unknown") -> list:
    """Scan text for shell commands, binary executables, and prompt injection.

    Returns a list of warning strings describing each detected threat.
    Returns an empty list when no threats are found.
    """
    if not text:
        return []
    warnings = []
    for pattern, label in _MALICIOUS_PATTERNS:
        try:
            if pattern.search(text):
                warnings.append(f"malicious_pattern:{label}:source={source}")
        except Exception:
            pass
    return warnings

    async def _redact_extracted(self, content: ExtractedContent) -> ExtractedContent:
        """Redact PII from all fields of an ExtractedContent before returning."""
        return _redact_content(content)

    async def scan_html(self, html_content: str) -> ExtractedContent:
        """
        Scan HTML content for visible and hidden text.

        VULNERABILITY: Extracts hidden content but doesn't flag it.
        Hidden divs, CSS-hidden text, etc. are extracted and
        concatenated with visible content.
        """
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_content, 'html.parser')

        # Extract visible text
        visible_text = soup.get_text(separator='\n', strip=True)

        # Extract hidden content (CSS hidden elements)
        hidden_elements = []

        # Find elements with hiding styles
        for element in soup.find_all(style=True):
            style = element.get('style', '').lower()
            if any(prop in style for prop in [
                'display:none', 'display: none',
                'visibility:hidden', 'visibility: hidden',
                'opacity:0', 'opacity: 0',
                'font-size:0', 'font-size: 0',
                'color:#fff', 'color:white', 'color: white',
            ]):
                text = element.get_text(strip=True)
                if text:
                    hidden_elements.append(text)

        # Find elements with hiding classes (common patterns)
        for element in soup.find_all(class_=re.compile(
            r'(hidden|invisible|sr-only|visually-hidden|d-none)',
            re.IGNORECASE
        )):
            text = element.get_text(strip=True)
            if text:
                hidden_elements.append(text)

        # Sanitize: hidden content is flagged and NOT forwarded to the LLM.
        # Only the count/presence is recorded; the raw text is discarded.
        warnings = []
        if hidden_elements:
            warnings.append(
                f"SECURITY: {len(hidden_elements)} hidden element(s) detected "
                "and removed before LLM processing (possible prompt-injection attempt)."
            )
            logger.warning(
                "Hidden HTML content detected and suppressed",
                extra={
                    "visible_length": len(visible_text),
                    "hidden_elements_found": len(hidden_elements),
                    "action": "hidden_content_redacted",
                }
            )
        else:
            logger.info(
                "HTML content scanned – no hidden elements found",
                extra={"visible_length": len(visible_text)}
            )

                warnings = None
        if hidden_elements:
            warnings = [
                f"Hidden content detected and suppressed: {len(hidden_elements)} element(s) "
                f"with CSS-hiding styles or classes were found and excluded from output "
                f"to prevent prompt injection or data leakage."
            ]
            logger.warning(
                "Hidden content suppressed from output",
                extra={
                    "hidden_elements_count": len(hidden_elements),
                    "action": "suppressed"
                }
            )

                # Security: flag hidden content as potential prompt injection threat
        html_warnings = []
        if hidden_elements:
            html_warnings.append(
                f"SECURITY WARNING: {len(hidden_elements)} hidden element(s) detected in HTML content. "
                "Hidden text may contain prompt injection payloads and has been quarantined."
            )
            logger.warning(
                "Hidden HTML elements detected — potential prompt injection risk",
                extra={
                    "hidden_element_count": len(hidden_elements),
                    "hidden_preview": hidden_text[:100] if hidden_text else None,
                }
            )
            # Do NOT pass hidden_text to downstream LLM components
            hidden_text = None

        return ExtractedContent(
            visible_text=visible_text,
            hidden_text=hidden_text,
            warnings=html_warnings if html_warnings else None
        ) to prevent injection/leakage
            hidden_text=None,
            warnings=warnings
        )

    async def scan_pdf_text(self, text_content: str) -> ExtractedContent:
        """
        Analyze extracted PDF text for hidden content indicators.

        VULNERABILITY: Does not detect:
        - White text on white background
        - Zero-size fonts
        - Off-page content
        - Overlapping text layers
        """
        # Look for suspicious patterns that might indicate hidden content
        suspicious_patterns = []

        # Check for unusual whitespace patterns
        if '\x00' in text_content:
            suspicious_patterns.append("null_bytes")

        # Check for potential invisible characters
        invisible_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']
        for char in invisible_chars:
            if char in text_content:
                suspicious_patterns.append(f"invisible_char_{ord(char)}")

        # Threat analysis: flag and block suspicious PDF patterns
        pdf_warnings = []
        if suspicious_patterns:
            warning_msg = (
                f"SECURITY ALERT: Suspicious patterns detected in PDF content: {suspicious_patterns}. "
                "This may indicate hidden or obfuscated prompt-injection content."
            )
            pdf_warnings.append(warning_msg)
            logger.warning(
                "Suspicious patterns detected in PDF — potential hidden content",
                extra={
                    "patterns": suspicious_patterns,
                    "threat": "pdf_hidden_content",
                }
            )
            raise ValueError(
                "Uploaded PDF rejected: suspicious hidden-content patterns detected "
                f"({suspicious_patterns}). File may contain malicious prompt-injection instructions."
            )

        return ExtractedContent(
            visible_text=text_content,
            hidden_text=None,  # PDF hidden text detection not implemented
            warnings=None  # VULNERABILITY: No warnings returned
        )

    async def scan_image_metadata(self, metadata: dict) -> ExtractedContent:
        """
        Scan image metadata for hidden content.

        VULNERABILITY: Extracts EXIF data but doesn't scan for threats.
        Malicious prompts in EXIF comment fields are passed through.
        """
        # Extract text from relevant metadata fields
        text_fields = []
        # Allowlist of safe, structured metadata fields only — free-text fields are excluded
        SAFE_METADATA_FIELDS = {
            'Make', 'Model', 'DateTime', 'DateTimeOriginal', 'DateTimeDigitized',
            'ExifImageWidth', 'ExifImageHeight', 'Orientation', 'XResolution',
            'YResolution', 'ResolutionUnit', 'ColorSpace', 'Flash',
            'FocalLength', 'ISOSpeedRatings', 'ExposureTime', 'FNumber',
            'Software',
        }
        metadata = {k: v for k, v in metadata.items() if k in SAFE_METADATA_FIELDS}

        dangerous_fields = ['Comment', 'UserComment', 'ImageDescription',
                          'XPComment', 'XPSubject', 'XPTitle']

        for field in dangerous_fields:
            if field in metadata:
                value = metadata[field]
                if value:
                    text_fields.append(f"{field}: {value}")

        # VULNERABILITY: Metadata content extracted without scanning
        # EXIF comments could contain prompt injections
        metadata_text = '\n'.join(text_fields) if text_fields else None

        logger.info(
            "Image metadata extracted",
            extra={
                "fields_found": len(text_fields),
                # VULNERABILITY: Metadata logged without scanning
                "metadata_preview": metadata_text[:100] if metadata_text else None
            }
        )

        return ExtractedContent(
            visible_text="",  # No visible text in metadata
            hidden_text=metadata_text,  # Metadata as "hidden" content
            metadata=metadata,
            warnings=None  # VULNERABILITY: No warnings for suspicious metadata
        )

    async def extract_base64_content(self, content: str) -> list[str]:
        """
        Extract and decode base64 encoded content.

        VULNERABILITY: Decodes base64 but doesn't scan decoded content.
        """
        import base64 as b64

        decoded_contents = []

        # Find base64-like strings (minimum 20 chars)
        b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        potential_b64 = re.findall(b64_pattern, content)

        for match in potential_b64:
            try:
                # Attempt to decode
                decoded = b64.b64decode(match).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 10:  # Filter noise
                    decoded_contents.append(decoded)
                    # VULNERABILITY: Decoded content not scanned for threats
                    logger.debug(
                        "Base64 content decoded",
                        extra={
                            "original_length": len(match),
                            "decoded_length": len(decoded),
                            # VULNERABILITY: Decoded content logged
                            "decoded_preview": decoded[:100]
                        }
                    )
            except:
                continue

        return decoded_contents

# ---------------------------------------------------------------------------
# Singapore PII scanning helper
# ---------------------------------------------------------------------------

_SG_PII_PATTERNS: list[tuple[str, re.Pattern]] = [
    # NRIC / FIN  – S/T/F/G followed by 7 digits and a letter
    ("NRIC/FIN", re.compile(r'\b[STFG]\d{7}[A-Z]\b', re.IGNORECASE)),
    # Singapore passport – starts with E/K followed by 7 digits
    ("Passport", re.compile(r'\b[EK]\d{7}[A-Z]\b', re.IGNORECASE)),
    # Singapore phone numbers – +65 or 65 prefix, 8 digits starting with 6/8/9
    ("SG Phone", re.compile(r'(?:\+65|\b65)[\s-]?[689]\d{7}\b')),
    # Singapore postal code – 6-digit code (common format)
    ("SG Postal Code", re.compile(r'\bSingapore\s+\d{6}\b', re.IGNORECASE)),
    # CPF account number – 9 digits (common representation)
    ("CPF", re.compile(r'\bCPF[:\s#-]*\d{9}\b', re.IGNORECASE)),
]


class SingaporePIIDetectedError(ValueError):
    """Raised when Singapore PII is found in uploaded file content."""


def _scan_for_singapore_pii(text: str) -> None:
    """
    Scan *text* for Singapore-specific PII categories.

    Raises SingaporePIIDetectedError listing every category found.
    Categories checked:
      - NRIC / FIN numbers
      - Singapore passport numbers
      - Singapore phone numbers (+65 prefix)
      - Singapore postal codes
      - CPF account numbers
    """
    found: list[str] = []
    for label, pattern in _SG_PII_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            found.append(f"{label} ({len(matches)} occurrence(s))")
            logger.warning(
                "Singapore PII detected in uploaded content",
                extra={"pii_category": label, "occurrences": len(matches)},
            )

    if found:
        raise SingaporePIIDetectedError(
            "Uploaded file contains Singapore PII and cannot be processed: "
            + ", ".join(found)
        )


    async def combine_for_analysis(
        self,
        extracted: ExtractedContent
    ) -> str:
        """
        Combine all extracted content for LLM analysis.

        VULNERABILITY: Combines visible AND hidden content without
        any security filtering. Hidden malicious content gets sent
        directly to the LLM.
        """
        parts = [extracted.visible_text]

        # VULNERABILITY: Hidden content added without filtering
        if extracted.hidden_text:
            parts.append(f"\n[Additional content]:\n{extracted.hidden_text}")

        # VULNERABILITY: Encoded content added without filtering
        if extracted.encoded_content:
            for i, decoded in enumerate(extracted.encoded_content):
                parts.append(f"\n[Decoded content {i+1}]:\n{decoded}")

        # Combine all parts
        combined = '\n'.join(parts)

        # Singapore PII scan — raise if PII detected
        _scan_for_singapore_pii(combined)

        return combined


# ============================================================================
# REMEDIATED VERSION (commented out - Unifai would enable this)
# ============================================================================

# class ContentScanner:
#     """
#     SECURE VERSION - After Unifai remediation
#
#     This version:
#     - Flags hidden content as suspicious
#     - Integrates with threat detection
#     - Generates security warnings
#     - Blocks content with detected threats
#     """
#
#     async def scan_html(self, html_content: str) -> ExtractedContent:
#         """Scan with security awareness."""
#         # ... extraction code ...
#
#         warnings = []
#         if hidden_elements:
#             warnings.append(f"SECURITY: {len(hidden_elements)} hidden elements detected")
#
#             # Scan hidden content for threats
#             from .prompt_injection import PromptInjectionDetector
#             detector = PromptInjectionDetector()
#             for hidden in hidden_elements:
#                 result = await detector.scan(hidden)
#                 if result.has_violations:
#                     warnings.append(f"THREAT: Malicious content in hidden element")
#
#         return ExtractedContent(
#             visible_text=visible_text,
#             hidden_text=hidden_text,
#             warnings=warnings
#         )
