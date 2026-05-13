"""
File Processor Agent
  
"""

import base64
import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from file_parsers.pdf_parser import PDFParser
from file_parsers.image_parser import ImageParser
from file_parsers.html_parser import HTMLParser

logger = logging.getLogger(__name__)


class FileProcessorAgent:
    """
    Agent responsible for processing uploaded files.

    Privilege Level: MEDIUM
    Capabilities:
    - Extract text from PDFs
    - Parse HTML content
    - Extract image metadata and text
    - Process Word documents
    """

    PRIVILEGE_LEVEL = "medium"
    SUPPORTED_TYPES = {
        "application/pdf": "pdf",
        "text/html": "html",
        "text/plain": "text",
        "application/json": "json",
        "image/jpeg": "image",
        "image/png": "image",
        "application/msword": "word",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "word",
    }

    def __init__(self):
        self.pdf_parser = PDFParser()
        self.image_parser = ImageParser()
        self.html_parser = HTMLParser()
        self.agent_id = "file_processor"

    async def process(
        self,
        content: Optional[str],
        filename: str,
        content_type: str
    ) -> str:
        """
        Process uploaded file and extract content.

        Args:
            content: File content (text or base64 encoded)
            filename: Original filename
            content_type: MIME type of the file

        Returns:
            Extracted text content from the file

        VULNERABILITY: No security scanning performed on file content.
        Files are processed and content extracted without checking for:
        - PII (SSN, credit cards, phone numbers)
        - Hidden/malicious prompts
        - Malware signatures
        - Sensitive data patterns
        """
        logger.info(
            "Processing file",
            extra={
                "file_name": filename,
                "file_type": content_type,
                "content_length": len(content) if content else 0,
            }
        )

        if not content:
            return f"Empty file: {filename}"

        # Determine file type
        file_type = self._get_file_type(content_type, filename)

        # Process based on file type
        try:
            if file_type == "pdf":
                extracted = await self._process_pdf(content)
            elif file_type == "html":
                extracted = await self._process_html(content)
            elif file_type == "image":
                extracted = await self._process_image(content)
            elif file_type == "json":
                extracted = await self._process_json(content)
            elif file_type == "text":
                extracted = content  # Direct text, no processing needed
            else:
                extracted = f"Unsupported file type: {content_type}"

            # Redact PII from extracted content before returning
            extracted = self._redact_pii(extracted)

            logger.info(
                "File processing complete",
                extra={
                    "file_name": filename,
                    "extracted_length": len(extracted),
                }
            )

            return extracted

        except Exception as e:
            logger.error(
                "Error processing file",
                extra={
                    "file_name": filename,
                    "error": str(e),
                }
            )
            return "An error occurred while processing the file. Please try again."

    def _redact_pii(self, text: str) -> str:
        """
        Detect and redact common PII patterns from text content.

        Redacts:
        - Social Security Numbers (SSN)
        - Credit card numbers
        - Phone numbers
        - Email addresses
        """
        import re

        if not text:
            return text

        # Redact SSNs (e.g. 123-45-6789 or 123 45 6789)
        text = re.sub(
            r'\b(?!000|666|9\d{2})\d{3}[\s\-](?!00)\d{2}[\s\-](?!0000)\d{4}\b',
            '[REDACTED-SSN]',
            text
        )

        # Redact credit card numbers (13–16 digit groups separated by spaces or dashes)
        text = re.sub(
            r'\b(?:\d[ \-]?){13,16}\b',
            '[REDACTED-CC]',
            text
        )

        # Redact phone numbers (various formats)
        text = re.sub(
            r'\b(?:\+?1[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?)\d{3}[\s.\-]?\d{4}\b',
            '[REDACTED-PHONE]',
            text
        )

        # Redact email addresses
        text = re.sub(
            r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
            '[REDACTED-EMAIL]',
            text
        )

        return text

    def _get_file_type(self, content_type: str, filename: str) -> str:
        """Determine file type from MIME type or extension."""
        # Check MIME type first
        if content_type in self.SUPPORTED_TYPES:
            return self.SUPPORTED_TYPES[content_type]

        # Fall back to extension
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        extension_map = {
            'pdf': 'pdf',
            'html': 'html',
            'htm': 'html',
            'txt': 'text',
            'json': 'json',
            'jpg': 'image',
            'jpeg': 'image',
            'png': 'image',
            'doc': 'word',
            'docx': 'word',
        }

        return extension_map.get(ext, 'unknown')

    async def _process_pdf(self, content: str) -> str:
        """
        Process PDF file content.

        VULNERABILITY: PDF processing extracts all text including
        hidden/white text that could contain prompt injections.
        """
        # Content is base64 encoded for PDFs
        try:
            pdf_bytes = base64.b64decode(content)
            extracted_text = await self.pdf_parser.extract_text(pdf_bytes)

            # VULNERABILITY: No hidden text detection
            # Invisible text (white on white, size 0, off-page) is extracted
            # and passed to LLM without filtering

            return extracted_text
        except Exception as e:
            logger.error(f"PDF processing error: {e}")
            return f"Error processing PDF: {str(e)}"

    async def _process_html(self, content: str) -> str:
        """
        Process HTML content.

        VULNERABILITY: HTML processing may not detect all hidden content:
        - CSS-hidden elements (display:none, visibility:hidden)
        - White text on white background
        - Off-screen positioned elements
        - Base64 encoded content in data attributes
        """
        try:
            extracted_text = await self.html_parser.extract_text(content)

            # VULNERABILITY: get_text() extracts content from hidden elements
            # Malicious prompts in hidden divs will be extracted

            return extracted_text
        except Exception as e:
            logger.error(f"HTML processing error: {e}")
            return f"Error processing HTML: {str(e)}"

    async def _process_image(self, content: str) -> str:
        """
        Process image file.

        VULNERABILITY: Image processing extracts EXIF metadata which
        could contain malicious prompts in comment/description fields.
        """
        try:
            image_bytes = base64.b64decode(content)

            # Extract both visual text (OCR) and metadata
            extracted = await self.image_parser.extract_all(image_bytes)

            # VULNERABILITY: EXIF data extracted and included without scanning
            # Comment, UserComment, ImageDescription fields could contain injections

            return extracted
        except Exception as e:
            logger.error(f"Image processing error: {e}")
            return f"Error processing image: {str(e)}"

    async def _process_json(self, content: str) -> str:
        """
        Process JSON content.

        VULNERABILITY: JSON content processed without PII scanning.
        Nested objects containing sensitive data are passed through.
        """
        import json

        try:
            # Parse to validate JSON
            data = json.loads(content)

            # VULNERABILITY: No PII detection in nested objects
            # Data like user.profile.contact.ssn passes through
            # No recursive scanning for sensitive patterns

            # Convert back to formatted string for analysis
            formatted = json.dumps(data, indent=2)

            return f"JSON Content:\n{formatted}"
        except json.JSONDecodeError as e:
            return f"Invalid JSON: {str(e)}\n\nRaw content:\n{content}"

    async def validate_file(self, content: str, filename: str) -> dict:
        """
        Validate file before processing.

        VULNERABILITY: Validation only checks format, not content.
        No security scanning performed.
        """
        # Basic validation only
        validation_result = {
            "valid": True,
            "filename": filename,
            "size": len(content) if content else 0,
            "warnings": []
        }

        # Size check (but no PII/threat check)
        if len(content) > 10 * 1024 * 1024:  # 10MB
            validation_result["warnings"].append("Large file - processing may be slow")

        # Singapore PII content scanning
        pii_findings = self._scan_for_sg_pii(content)
        if pii_findings:
            validation_result["valid"] = False
            validation_result["warnings"].append(
                f"File rejected: Singapore PII detected ({', '.join(pii_findings)}). "
                "Remove all personal data before uploading."
            )

        return validation_result

    def _scan_for_sg_pii(self, content: str) -> list:
        """
        Scan content for Singapore PII categories.

        Checks for:
        - NRIC / FIN numbers  (S/T/F/G + 7 digits + letter)
        - Singapore passport numbers
        - Singapore phone numbers (+65 or local 8-digit starting with 6/8/9)
        - Singapore postal codes (6-digit starting with valid sector)
        - Email addresses
        - Credit / debit card numbers
        """
        import re

        findings = []

        patterns = {
            "NRIC/FIN": r'\b[STFG]\d{7}[A-Z]\b',
            "Singapore passport": r'\bE\d{7}[A-Z]\b',
            "Singapore phone": (
                r'(?:\+65[\s-]?)?'
                r'(?:6|8|9)\d{3}[\s-]?\d{4}\b'
            ),
            "Singapore postal code": r'\b(?:0[1-9]|[1-7]\d|8[0-8])\d{4}\b',
            "email address": r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
            "credit/debit card": (
                r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))'
                r'[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{3,4}\b'
            ),
        }

        for label, pattern in patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(label)

        return findings
