"""
Policy Enforcement Modules

Contains modules for detecting and enforcing security policies:
- PII Detection: Identifies personally identifiable information
- Prompt Injection: Detects hidden/malicious prompts
- Content Scanner: Extracts and analyzes hidden content

SECURITY NOTES:
All policy modules actively enforce security policies.
Content is scanned and validated before being passed to the AI model.
"""

from .pii_detection import PIIDetector, PIIDetectionResult
from .prompt_injection import PromptInjectionDetector, ThreatDetectionResult
from .content_scanner import ContentScanner


class SecurityViolationError(Exception):
    """Raised when uploaded file content fails security scanning."""
    pass


class FileContentGuard:
    """
    Mandatory security gate for all uploaded file content.

    Every piece of content extracted from an uploaded file MUST be passed
    through `FileContentGuard.scan()` before it is used anywhere in the
    application.  The guard runs both the ContentScanner (hidden-content
    extraction) and the PromptInjectionDetector (malicious-prompt detection)
    and raises SecurityViolationError if either check finds a threat.

    Usage::

        guard = FileContentGuard()
        safe_content = guard.scan(raw_file_content, filename="upload.pdf")
    """

    def __init__(self):
        self._content_scanner = ContentScanner()
        self._injection_detector = PromptInjectionDetector()

    def scan(self, content: str, filename: str = "<unknown>") -> str:
        """
        Scan *content* extracted from an uploaded file for malicious prompts
        and hidden instructions.

        Parameters
        ----------
        content:
            Raw text content extracted from the uploaded file.
        filename:
            Original filename, used only for error messages.

        Returns
        -------
        str
            The original *content* string, unchanged, if no threats are found.

        Raises
        ------
        SecurityViolationError
            If the ContentScanner or PromptInjectionDetector identifies
            malicious or hidden prompt content.
        TypeError
            If *content* is not a string.
        """
        if not isinstance(content, str):
            raise TypeError(
                f"FileContentGuard.scan() requires a str, got {type(content).__name__!r}"
            )

        # --- Step 1: hidden-content / steganographic extraction ---
        try:
            scan_result = self._content_scanner.scan(content)
        except Exception as exc:
            raise SecurityViolationError(
                f"ContentScanner raised an unexpected error for '{filename}': {exc}"
            ) from exc

        if scan_result is not None and getattr(scan_result, "has_hidden_content", False):
            details = getattr(scan_result, "details", "no details available")
            raise SecurityViolationError(
                f"Uploaded file '{filename}' contains hidden/malicious content: {details}"
            )

        # --- Step 2: prompt-injection detection ---
        try:
            threat_result = self._injection_detector.detect(content)
        except Exception as exc:
            raise SecurityViolationError(
                f"PromptInjectionDetector raised an unexpected error for '{filename}': {exc}"
            ) from exc

        if threat_result is not None and getattr(threat_result, "is_threat", False):
            threat_type = getattr(threat_result, "threat_type", "unknown")
            raise SecurityViolationError(
                f"Uploaded file '{filename}' contains a prompt-injection threat "
                f"(type={threat_type!r}). Content rejected."
            )

        return content


__all__ = [
    "PIIDetector",
    "PIIDetectionResult",
    "PromptInjectionDetector",
    "ThreatDetectionResult",
    "ContentScanner",
    "FileContentGuard",
    "SecurityViolationError",
]
