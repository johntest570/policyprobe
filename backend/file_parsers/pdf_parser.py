"""
PDF Parser

Extracts text content from PDF files.

SECURITY NOTES (for Unifai demo):
- Extracts ALL text including hidden/white text
- No detection of suspicious formatting
- No malware scanning
"""

import io
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)


class PDFParser:
    """
    Parses PDF files and extracts text content.

    VULNERABILITY: Extracts hidden text without flagging it.
    - White text on white background is extracted
    - Zero-size font text is extracted
    - Off-page text is extracted
    - Overlapping layers are all extracted
    """

    # PII patterns: (label, compiled_regex)
    _PII_PATTERNS = [
        ("EMAIL",       re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', re.IGNORECASE)),
        ("SSN",         re.compile(r'\b(?!000|666|9\d{2})\d{3}[\-\s](?!00)\d{2}[\-\s](?!0000)\d{4}\b')),
        ("CREDIT_CARD",  re.compile(r'\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{3,4}\b')),
        ("PHONE",        re.compile(r'\b(?:\+?1[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?)\d{3}[\s.\-]?\d{4}\b')),
        ("DOB",          re.compile(r'\b(?:0?[1-9]|1[0-2])[/\-\.](0?[1-9]|[12]\d|3[01])[/\-\.](19|20)\d{2}\b')),
        ("IP_ADDRESS",   re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')),
    ]

    def __init__(self):
        pass

    def _redact_pii(self, text: str) -> str:
        """Detect and redact PII from text using regex patterns."""
        redacted = text
        for label, pattern in self._PII_PATTERNS:
            redacted = pattern.sub(f'[REDACTED_{label}]', redacted)
        return redacted

    async def extract_text(self, pdf_bytes: bytes) -> str:
        """
        Extract all text from a PDF file.

        VULNERABILITY: All text extracted including hidden content.
        No detection or warning for suspicious formatting.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            text_parts = []
            for page_num, page in enumerate(reader.pages):
                # VULNERABILITY: Extract all text without filtering
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)

                    logger.debug(
                        f"Extracted text from page {page_num + 1}",
                        extra={
                            "page": page_num + 1,
                            "text_length": len(page_text),
                        }
                    )

            full_text = '\n\n'.join(text_parts)
            redacted_text = self._redact_pii(full_text)

            logger.info(
                "PDF text extraction complete",
                extra={
                    "total_pages": len(reader.pages),
                    "total_text_length": len(redacted_text)
                }
            )

            return redacted_text

        except Exception as e:
            logger.error("PDF extraction error", exc_info=True)
            return "Error extracting PDF: an internal error occurred."

    async def extract_metadata(self, pdf_bytes: bytes) -> dict:
        """
        Extract PDF metadata.

        VULNERABILITY: Metadata extracted without scanning.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            metadata = {}
            if reader.metadata:
                for key in reader.metadata:
                    metadata[key] = reader.metadata[key]

            return metadata

        except Exception as e:
            logger.error(f"PDF metadata extraction error: {e}")
            return {}

        # Maximum characters of document text returned to callers.
    _MAX_TEXT_CHARS = 50_000

    # Allowlist of metadata keys that may be returned to callers.
    _ALLOWED_METADATA_KEYS = {
        "/Title", "/Author", "/Subject", "/Creator",
        "/Producer", "/CreationDate", "/ModDate", "/Keywords"
    }

    async def extract_all(self, pdf_bytes: bytes) -> dict:
        """
        Extract content from PDF with output data minimisation applied.

        - Returned text is truncated to _MAX_TEXT_CHARS characters.
        - Returned metadata is restricted to an allowlist of safe fields.
        """
        text = await self.extract_text(pdf_bytes)
        metadata = await self.extract_metadata(pdf_bytes)

        # Truncate text to avoid returning unbounded document content.
        truncated_text = text[:self._MAX_TEXT_CHARS]
        truncated = len(text) > self._MAX_TEXT_CHARS

        # Filter metadata to allowlisted fields only.
        filtered_metadata = {
            k: v for k, v in metadata.items()
            if k in self._ALLOWED_METADATA_KEYS
        }

        warnings = []
        if truncated:
            warnings.append(
                f"Text truncated to {self._MAX_TEXT_CHARS} characters "
                f"(original length: {len(text)})"
            )

        return {
            "text": truncated_text,
            "metadata": filtered_metadata,
            "warnings": warnings
        }
