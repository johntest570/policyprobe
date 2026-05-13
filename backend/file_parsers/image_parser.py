"""
Image Parser

Extracts content from image files including EXIF metadata.

SECURITY NOTES (for Unifai demo):
- EXIF metadata extracted without scanning
- Comments and descriptions could contain prompt injections
- No malware detection
"""

import io
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Maximum length allowed for any single EXIF string field
_MAX_FIELD_LEN = 512

# Patterns commonly used in prompt-injection attacks
_INJECTION_PATTERNS = re.compile(
    r"(ignore (previous|all|above)|disregard|forget (previous|all)|new instruction|"
    r"system prompt|you are now|act as|jailbreak|\\n\\n|<\|im_start\|>|<\|im_end\|>|"
    r"\[INST\]|\[/INST\]|###\s*instruction|###\s*system)",
    re.IGNORECASE,
)


def _sanitize_exif_string(value: str) -> str:
    """Remove control characters, truncate, and strip prompt-injection patterns."""
    # Strip null bytes and non-printable control characters (keep newline/tab for readability)
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    # Truncate to a safe maximum length
    value = value[:_MAX_FIELD_LEN]
    # Blank out the field if it contains injection patterns
    if _INJECTION_PATTERNS.search(value):
        logger.warning("Potential prompt-injection pattern detected in EXIF field; field suppressed.")
        return ""
    return value


class ImageParser:
    """
    Parses image files and extracts metadata.

    VULNERABILITY: Extracts EXIF data without security scanning.
    - Comment fields could contain prompt injections
    - UserComment could contain malicious instructions
    - ImageDescription could contain attacks
    """

    # Maximum allowed length for any single EXIF text field
    _MAX_FIELD_LENGTH = 500

    # Patterns that indicate prompt-injection or command-injection attempts
    _INJECTION_PATTERNS = [
        r'(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions',
        r'(?i)you\s+are\s+now',
        r'(?i)act\s+as\s+(a\s+)?',
        r'(?i)system\s*:\s*',
        r'(?i)assistant\s*:\s*',
        r'(?i)user\s*:\s*',
        r'(?i)<\s*(script|iframe|object|embed|svg)',
        r'(?i)\\n\s*(ignore|forget|disregard)',
        r'(?i)prompt\s*injection',
        r'(?i)jailbreak',
    ]

    def __init__(self):
        import re
        self._compiled_patterns = [
            re.compile(p) for p in self._INJECTION_PATTERNS
        ]

    def _sanitize_text_field(self, value: str) -> Optional[str]:
        """
        Sanitize a single EXIF text field value.

        - Truncates to a safe maximum length.
        - Returns None if the value matches known injection patterns,
          so the caller can skip the field entirely.
        - Strips leading/trailing whitespace.
        """
        if not isinstance(value, str):
            return None

        # Strip surrounding whitespace
        value = value.strip()

        if not value:
            return None

        # Reject values that match injection patterns
        for pattern in self._compiled_patterns:
            if pattern.search(value):
                logger.warning(
                    "Rejected EXIF field value matching injection pattern",
                    extra={"pattern": pattern.pattern}
                )
                return None

        # Truncate to maximum safe length
        if len(value) > self._MAX_FIELD_LENGTH:
            logger.warning(
                "Truncating oversized EXIF field value",
                extra={"original_length": len(value)}
            )
            value = value[: self._MAX_FIELD_LENGTH]

        return value

    async def extract_metadata(self, image_bytes: bytes) -> dict:
        """
        Extract EXIF and other metadata from image.

        VULNERABILITY: Metadata extracted without scanning for threats.
        """
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS

            image = Image.open(io.BytesIO(image_bytes))
            metadata = {}

            # Get basic image info
            metadata['format'] = image.format
            metadata['size'] = image.size
            metadata['mode'] = image.mode

                        # Extract EXIF data — scan every text field for malicious content
            exif_data = image._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    # Convert bytes to string for JSON serialization
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except:
                            value = str(value)
                    # Scan string values for malicious / injected content
                    if isinstance(value, str):
                        try:
                            value = self._scan_for_malicious_content(str(tag), value)
                        except ValueError as scan_err:
                            logger.error(
                                "EXIF field rejected due to malicious content",
                                extra={"tag": str(tag), "error": str(scan_err)}
                            )
                            # Redact the field rather than propagating the threat
                            value = "[REDACTED: malicious content detected]"
                    metadata[tag] = value

            # Redact PII before logging metadata preview
            redacted_preview = self._redact_pii(str(metadata))[:200]
            logger.info(
                "Image metadata extracted",
                extra={
                    "format": image.format,
                    "size": image.size,
                    "exif_fields": len(metadata),
                    "metadata_preview": redacted_preview
                }
            )

            return metadata

        except Exception as e:
            logger.error(f"Image metadata extraction error: {e}")
            return {"error": str(e)}

    # ------------------------------------------------------------------ #
    # Sanitization helpers                                               #
    # ------------------------------------------------------------------ #
    _INVISIBLE_RE = re.compile(
        r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]'
    )
    # Patterns that suggest shell commands or executable content
    _SHELL_RE = re.compile(
        r'(?i)(\b(bash|sh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|`[^`]+`|\$\([^)]+\))|'
        r'(&&|\|\||;\s*\w)|'
        r'(\.exe|\.bat|\.sh|\.ps1|\.cmd)\b)'
    )
    # Detect base64 blobs (≥40 contiguous base64 chars)
    _B64_RE = re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})')
    # Leetspeak substitution map (common chars only)
    _LEET_MAP = str.maketrans('013457@$!', 'oieashasi')
    # Prompt-injection trigger phrases (checked after leet normalisation)
    _INJECTION_PHRASES = re.compile(
        r'(?i)(ignore (previous|all|above)|disregard|new instruction|system prompt|'
        r'you are now|act as|jailbreak|do anything now|dan mode|'
        r'forget (your|all)|override (your|the)|reveal (your|the) (system|prompt|instruction))'
    )
    # Binary executable magic bytes (MZ, ELF, Mach-O, etc.)
    _BINARY_MAGIC = [
        b'MZ', b'\x7fELF', b'\xca\xfe\xba\xbe', b'\xfe\xed\xfa\xce',
        b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',
    ]

    def _sanitize_field(self, field: str, value: str) -> str | None:
        """
        Sanitize a single EXIF text field value.

        Returns the cleaned value, or None if the value should be
        discarded entirely because it contains malicious content.
        """
        # 1. Reject binary executable content embedded as a string
        raw = value.encode('latin-1', errors='replace')
        for magic in self._BINARY_MAGIC:
            if magic in raw:
                logger.warning(
                    "Binary executable magic bytes found in EXIF field – discarding",
                    extra={"field": field}
                )
                return None

        # 2. Strip invisible / control characters
        cleaned = self._INVISIBLE_RE.sub('', value)

        # 3. Reject if a base64 blob is present (potential encoded payload)
        if self._B64_RE.search(cleaned):
            logger.warning(
                "Base64-encoded content detected in EXIF field – discarding",
                extra={"field": field}
            )
            return None

        # 4. Reject shell command patterns
        if self._SHELL_RE.search(cleaned):
            logger.warning(
                "Shell command pattern detected in EXIF field – discarding",
                extra={"field": field}
            )
            return None

        # 5. Normalise leetspeak and check for prompt-injection phrases
        normalised = cleaned.translate(self._LEET_MAP)
        if self._INJECTION_PHRASES.search(normalised):
            logger.warning(
                "Prompt-injection phrase detected in EXIF field – discarding",
                extra={"field": field}
            )
            return None

        # 6. Truncate to a safe length to prevent oversized payloads
        max_len = 256
        if len(cleaned) > max_len:
            logger.debug(
                "EXIF field truncated to %d chars", max_len,
                extra={"field": field}
            )
            cleaned = cleaned[:max_len]

        return cleaned

    async def extract_text_fields(self, metadata: dict) -> str:
        """
        Extract text from relevant metadata fields.

        Each field value is sanitized before being included in the
        output to prevent prompt injection via EXIF data.
        """
        text_fields = []

                # Only expose minimal, non-sensitive descriptive fields
        dangerous_fields = [
            'XPTitle',
            'XPSubject',
        ]

                        for field in dangerous_fields:
            if field in metadata:
                value = metadata[field]
                if value and isinstance(value, str):
                    # Re-sanitize at the point of use as a defence-in-depth measure
                    value = _sanitize_exif_string(value)
                    if not value:
                        continue
                    text_fields.append(f"{field}: {value}")
                    logger.debug(
                            f"Found text in {field}",
                            extra={
                                "field": field,
                                "value_preview": safe_value[:50]
                            }
                        )
                if value and isinstance(value, str):
                    try:
                        value = self._scan_for_malicious_content(field, value)
                    except ValueError as scan_err:
                        logger.error(
                            "Text field rejected in extract_text_fields",
                            extra={"field": field, "error": str(scan_err)}
                        )
                        continue  # Skip this field entirely
                if value and isinstance(value, str):
                    sanitized_value = self._sanitize_text_field(value)
                    if sanitized_value is None:
                        logger.warning(
                            "Skipping EXIF text field due to failed sanitization",
                            extra={"field": field}
                        )
                        continue
                    text_fields.append(f"{field}: {sanitized_value}")
                    logger.debug(
                        f"Found text in {field}",
                        extra={
                            "field": field,
                            "value_preview": sanitized_value[:50]
                        }
                    )

        return '\n'.join(text_fields)

    # ---------------------------------------------------------------------------
    # PII redaction helper
    # ---------------------------------------------------------------------------
    _PII_PATTERNS: list = [
        # E-mail addresses
        (re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+'), '[EMAIL REDACTED]'),
        # Phone numbers (various formats)
        (re.compile(r'(?:\+?\d[\s.-]?){7,15}'), '[PHONE REDACTED]'),
        # GPS decimal coordinates  e.g. 51.5074, -0.1278
        (re.compile(r'-?\d{1,3}\.\d{4,}\s*,\s*-?\d{1,3}\.\d{4,}'), '[GPS REDACTED]'),
        # Social-security-number style  NNN-NN-NNNN
        (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[SSN REDACTED]'),
        # Credit-card style  16 digits (with optional separators)
        (re.compile(r'\b(?:\d[ -]?){13,16}\b'), '[CC REDACTED]'),
        # IPv4 addresses
        (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[IP REDACTED]'),
    ]

    def _redact_pii(self, text: str) -> str:
        """Return *text* with all recognised PII patterns replaced by tokens."""
        if not isinstance(text, str):
            return text
        for pattern, token in self._PII_PATTERNS:
            text = pattern.sub(token, text)
        return text

    def _redact_metadata(self, metadata: dict) -> dict:
        """Return a copy of *metadata* with PII redacted from every string value."""
        redacted: dict = {}
        for key, value in metadata.items():
            if isinstance(value, str):
                redacted[key] = self._redact_pii(value)
            elif isinstance(value, (list, tuple)):
                redacted[key] = type(value)(self._redact_pii(v) if isinstance(v, str) else v for v in value)
            else:
                redacted[key] = value
        return redacted

    # ---------------------------------------------------------------------------

        # Singapore PII patterns
    _SG_PII_PATTERNS = [
        # NRIC / FIN: S/T/F/G followed by 7 digits and a letter
        (r'\b[STFG]\d{7}[A-Z]\b', 'NRIC/FIN'),
        # Singapore phone numbers (+65 or local 8-digit starting with 6/8/9)
        (r'(?:\+65[\s-]?)?[689]\d{7}\b', 'SG phone number'),
        # Singapore postal code (6 digits, optionally preceded by "Singapore")
        (r'\bSingapore\s+\d{6}\b', 'SG postal address'),
        (r'\b\d{6}\b(?=.*Singapore)', 'SG postal code'),
        # Biometric data keywords
        (r'\b(?:fingerprint|iris|retina|biometric|face(?:\s+id)?|thumbprint)\b', 'biometric data'),
        # Common full-name salutation patterns (Mr/Mrs/Ms/Dr + capitalised words)
        (r'\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b', 'full name'),
        # Passport number pattern (letter + 7 digits)
        (r'\b[A-Z]\d{7}\b', 'passport number'),
    ]

    def _check_sg_pii(self, text: str) -> list:
        """
        Scan *text* for Singapore PII categories.
        Returns a list of (pattern_label, matched_value) tuples.
        """
        import re
        findings = []
        for pattern, label in self._SG_PII_PATTERNS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                findings.append((label, match.group()))
        return findings

    async def extract_all(self, image_bytes: bytes) -> str:
        """
        Extract all content from image for analysis.

        Singapore PII (NRIC, full name, biometric data, address, etc.) is
        detected in extracted metadata/text and blocked before the content
        is returned, in compliance with the Singapore PII upload policy.
        """
        metadata = await self.extract_metadata(image_bytes)
        text_content = await self.extract_text_fields(metadata)

        # --- Singapore PII check ---
        combined_for_scan = text_content
        # Also scan string values from the raw metadata dict
        for v in metadata.values():
            if isinstance(v, str):
                combined_for_scan += '\n' + v

        pii_findings = self._check_sg_pii(combined_for_scan)
        if pii_findings:
            labels = list({label for label, _ in pii_findings})
            logger.warning(
                "Singapore PII detected in image metadata – upload blocked",
                extra={"pii_categories": labels}
            )
            raise ValueError(
                f"Image metadata contains Singapore PII ({', '.join(labels)}). "
                "Upload rejected to comply with the Singapore PII policy."
            )
        # --- end PII check ---

        result_parts = []

        if text_content:
            result_parts.append(f"Image Metadata:\n{text_content}")

        result_parts.append(f"Image Info: {metadata.get('format', 'unknown')} {metadata.get('size', 'unknown')}")

        return '\n\n'.join(result_parts)
