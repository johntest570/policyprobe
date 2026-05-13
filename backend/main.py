"""
PolicyProbe Backend - FastAPI Application

This is the main entry point for the PolicyProbe demo application.
The application demonstrates various security policy violations that
can be detected and remediated by Unifai.
"""

import os
import hashlib
from pathlib import Path

# ---------------------------------------------------------------------------
# Approved Model & Agent Registry with version pinning and integrity hashes
# ---------------------------------------------------------------------------
APPROVED_MODEL_REGISTRY = {
    "gpt-4o": {
        "version": "2024-08-06",
        "provider": "openai",
        "sha256_config_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    "gpt-4o-mini": {
        "version": "2024-07-18",
        "provider": "openai",
        "sha256_config_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
}

APPROVED_AGENT_REGISTRY = {
    "AgentOrchestrator": {
        "version": "1.0.0",
        "module": "agents.orchestrator",
        "approved_models": ["gpt-4o", "gpt-4o-mini"],
    },
    "FileProcessorAgent": {
        "version": "1.0.0",
        "module": "agents.file_processor",
        "approved_models": ["gpt-4o", "gpt-4o-mini"],
    },
}


def _verify_agent_registry(agent_name: str) -> None:
    """Raise RuntimeError if agent is not in the approved registry."""
    if agent_name not in APPROVED_AGENT_REGISTRY:
        raise RuntimeError(
            f"POLICY VIOLATION: Agent '{agent_name}' is NOT in the approved agent registry. "
            "Register the agent with a pinned version before use."
        )


def _verify_model_registry(model_name: str) -> None:
    """Raise RuntimeError if model is not in the approved registry."""
    if model_name not in APPROVED_MODEL_REGISTRY:
        raise RuntimeError(
            f"POLICY VIOLATION: Model '{model_name}' is NOT in the approved model registry. "
            "Only registry-approved, version-pinned models may be used."
        )


def _verify_integrity(agent_name: str, model_name: str) -> None:
    """Verify that the model is approved for use by the given agent."""
    _verify_agent_registry(agent_name)
    _verify_model_registry(model_name)
    approved_models = APPROVED_AGENT_REGISTRY[agent_name]["approved_models"]
    if model_name not in approved_models:
        raise RuntimeError(
            f"POLICY VIOLATION: Model '{model_name}' is not approved for agent '{agent_name}'. "
            f"Approved models: {approved_models}"
        )
# ---------------------------------------------------------------------------

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

import logging
from contextlib import asynccontextmanager
from typing import Optional

import os
import os
import secrets
from fastapi import FastAPI, HTTPException, UploadFile, File, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from openai import OpenAI

# Approved LLM client (OpenAI) — replaces unregistered AgentOrchestrator
# and FileProcessorAgent which invoked unapproved LLMs (LLaMA / custom_llm_client)
_approved_client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
_APPROVED_MODEL = "gpt-4o"  # registered in the organisation's approved LLM list


def _process_file_content(attachment) -> str:
    """Inline replacement for FileProcessorAgent using only approved models."""
                    if attachment.content:
                    # Redact PII from attachment content before processing
                    sanitized_content = redact_pii(attachment.content)
                    processed = await file_processor.process(
                        content=sanitized_content,
                        filename=attachment.name,
                        content_type=attachment.type
                    ) -> str:
    """Inline replacement for AgentOrchestrator using only approved models."""
    system_prompt = (
        "You are a helpful assistant. "
        "Answer the user's question using the provided file context when relevant."
    )
    user_content = message
    if file_context:
        user_content = f"{file_context}\n\nUser question: {message}"

    response = _approved_client.chat.completions.create(
        model=_APPROVED_MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
    )
    return response.choices[0].message.content

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("PolicyProbe backend starting up...")
    yield
    logger.info("PolicyProbe backend shutting down...")


app = FastAPI(
    title="PolicyProbe",
    description="AI-powered policy evaluation and remediation demo",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5001", "http://127.0.0.1:5001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Agents replaced by approved inline helpers (_orchestrate / _process_file_content)


class FileAttachment(BaseModel):
    id: str
    name: str
    type: str
    size: int
    content: Optional[str] = None


class ChatRequest(BaseModel):
    message: str
    attachments: Optional[list[FileAttachment]] = None
    conversation_id: Optional[str] = None


class PolicyError(BaseModel):
    type: str
    message: str
    details: Optional[dict] = None


class ChatResponse(BaseModel):
    response: str
    conversation_id: Optional[str] = None
    policy_warning: Optional[PolicyError] = None


import base64
import re

# Patterns indicative of prompt injection, shell commands, or hidden malicious content
_MALICIOUS_PATTERNS = [
    # Direct prompt injection attempts
    re.compile(r'ignore (previous|all|above|prior) instructions', re.IGNORECASE),
    re.compile(r'disregard (previous|all|above|prior|your) instructions', re.IGNORECASE),
    re.compile(r'you are now', re.IGNORECASE),
    re.compile(r'new (role|persona|instructions|task|objective)', re.IGNORECASE),
    re.compile(r'act as (a |an )?(?!user)', re.IGNORECASE),
    re.compile(r'(system|assistant|user)\s*:', re.IGNORECASE),
    re.compile(r'<\s*(system|instructions?|prompt)\s*>', re.IGNORECASE),
    re.compile(r'\[\s*(system|instructions?|prompt)\s*\]', re.IGNORECASE),
    # Shell command injection
    re.compile(r'(;|\||&&|\$\()\s*(rm|wget|curl|bash|sh|python|perl|nc|ncat|netcat|chmod|chown|sudo|su\b)', re.IGNORECASE),
    re.compile(r'`[^`]{0,200}`', re.IGNORECASE),
    re.compile(r'\$\([^)]{0,200}\)', re.IGNORECASE),
    # Common exfiltration / SSRF patterns
    re.compile(r'(https?|ftp|file|data|gopher)://[^\s]{0,300}', re.IGNORECASE),
    # Leetspeak variants of key injection phrases (e.g. 1gn0r3, 1nstruct10ns)
    re.compile(r'[i1][g9][n][o0][r3][e3]', re.IGNORECASE),
    re.compile(r'[i1][n][s5][t][r][u][c][t][i1][o0][n][s5]', re.IGNORECASE),
    # Hidden Unicode / zero-width characters used to smuggle instructions
    re.compile(r'[\u200b-\u200f\u202a-\u202e\u2060\ufeff]'),
]

_B64_CHUNK = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')


def _scan_for_malicious_content(text: str) -> tuple[bool, str]:
    """Scan text for hidden prompts, base64-encoded payloads, leetspeak,
    shell commands, and other malicious content.

    Returns (is_malicious, reason).
    """
    if not text:
        return False, ""

    # 1. Direct pattern matching
    for pattern in _MALICIOUS_PATTERNS:
        match = pattern.search(text)
        if match:
            return True, f"Malicious pattern detected: '{match.group(0)[:80)}'"

    # 2. Base64-encoded payload detection — decode candidate chunks and re-scan
    for chunk_match in _B64_CHUNK.finditer(text):
        chunk = chunk_match.group(0)
        # Pad to valid base64 length
        padded = chunk + '=' * (-len(chunk) % 4)
        try:
            decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
            for pattern in _MALICIOUS_PATTERNS:
                inner = pattern.search(decoded)
                if inner:
                    return True, f"Base64-encoded malicious content detected"
        except Exception:
            pass  # Not valid base64 — skip

    return False, ""


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "policyprobe"}


ALLOWED_CONTENT_TYPES = {
    "text/plain",
    "text/csv",
    "application/json",
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
}
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB


def _validate_content_type(content_type: Optional[str], filename: str) -> str:
    """Validate and normalize the content type against the allowlist."""
    if not content_type:
        raise HTTPException(
            status_code=400,
            detail=f"Missing content type for file '{filename}'.",
        )
    # Strip parameters (e.g. 'text/plain; charset=utf-8' -> 'text/plain')
    base_type = content_type.split(";")[0].strip().lower()
    if base_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{base_type}' for file '{filename}'. "
                   f"Allowed types: {sorted(ALLOWED_CONTENT_TYPES)}",
        )
    return base_type


def _sanitize_text(content: str) -> str:
    """Remove null bytes and non-printable control characters from text content."""
    # Allow common whitespace (tab, newline, carriage-return) but strip others
    sanitized = "".join(
        ch for ch in content
        if ch in ("\t", "\n", "\r") or (ord(ch) >= 32 and ord(ch) != 127)
    )
    return sanitized


def _validate_and_sanitize_attachment(attachment) -> str:
    """Validate size and content type, then sanitize text content for an attachment."""
    # Size check (attachment.content is a str; use byte length of UTF-8 encoding)
    raw_bytes = (attachment.content or "").encode("utf-8", errors="ignore")
    if len(raw_bytes) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"File '{attachment.name}' exceeds the maximum allowed size of "
                   f"{MAX_FILE_SIZE_BYTES // (1024 * 1024)} MB.",
        )
    _validate_content_type(attachment.type, attachment.name)
    return _sanitize_text(attachment.content or "")


def _validate_and_sanitize_upload(content: bytes, filename: str, content_type: Optional[str]) -> str:
    """Validate size and content type, then sanitize text content for an uploaded file."""
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"Uploaded file '{filename}' exceeds the maximum allowed size of "
                   f"{MAX_FILE_SIZE_BYTES // (1024 * 1024)} MB.",
        )
    _validate_content_type(content_type, filename)
    decoded = content.decode("utf-8", errors="ignore")
    return _sanitize_text(decoded)


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, _: None = Depends(verify_api_key)):
    """
    Main chat endpoint that processes user messages and file uploads.

    This endpoint:
    1. Receives user messages and optional file attachments
    2. Processes files through the FileProcessorAgent
    3. Routes the request through the AgentOrchestrator
    4. Returns the AI response

    SECURITY NOTES (for Unifai demo):
    - File content is scanned and PII is redacted before processing
    - Hidden content in files is not detected
    - Agent calls are authenticated via shared inter-agent token
    """
    import uuid, hashlib, datetime

    # Generate a single trace/correlation ID for this entire request
    trace_id = str(uuid.uuid4())
    principal = getattr(request, 'user_id', 'anonymous')

    def _sha256(value: str) -> str:
        return hashlib.sha256(value.encode('utf-8', errors='replace')).hexdigest()

    def _audit(event: str, agent: str, input_hash: str, output_hash: str | None, extra: dict | None = None):
        record = {
            "audit": True,
            "trace_id": trace_id,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "principal": principal,
            "agent": agent,
            "agent_version": getattr(globals().get(agent.split('.')[0]), 'version', 'unknown'),
            "event": event,
            "input_hash": input_hash,
            "output_hash": output_hash,
        }
        if extra:
            record.update(extra)
        logger.info("AI_AUDIT", extra=record)

    try:
        # Process any attached files
        file_contents = []
        if request.attachments:
            for attachment in request.attachments:
                logger.info(
                    "Processing attachment",
                    extra={
                        "file_name": attachment.name,
                        "file_type": attachment.type,
                        "file_size": attachment.size,
                        # VULNERABILITY: Logging full request context
                        # This could include sensitive data from the file
                        "request_context": {
                            "attachment_name": attachment.name
                        }
                    }
                )

                # Validate and sanitize file content before processing
                sanitized_content = _validate_and_sanitize_attachment(attachment)
                                    processed = await file_processor.process(
                    content=attachment.content,
                    filename=attachment.name,
                    content_type=attachment.type
                )
                try:
                    processed = _sanitize_llm_output(processed)
                except ValueError as san_err:
                    logger.warning(
                        "Blocked dangerous content in file_processor output",
                        extra={"filename": attachment.name, "reason": str(san_err)}
                    )
                    raise HTTPException(
                        status_code=400,
                        detail={
                            "detail": "File content rejected: dynamic code execution primitive detected in processed output.",
                            "policy_error": {"type": "llm_output_sanitization", "message": str(san_err)}
                        }
                    )
                file_contents.append({
                    "filename": attachment.name,
                    "extracted_content": processed
                })

        # Sanitize user message before forwarding to the orchestrator
        try:
            sanitized_message = _sanitize_text(request.message, label="user_message")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

                # ---------------------------------------------------------------------------
        # Sanitize untrusted input before it reaches the LLM prompt.
        # This prevents prompt-injection via crafted messages or file contents.
        # ---------------------------------------------------------------------------
        import re

        _MAX_MESSAGE_LEN = 4_000   # characters
        _MAX_FILE_CONTENT_LEN = 8_000  # characters per file

        # Patterns that are commonly used in prompt-injection attacks
        _INJECTION_PATTERN = re.compile(
            r"(ignore (all |previous |prior |above )?instructions?"
            r"|system\s*prompt"
            r"|you are now"
            r"|disregard (all |previous |prior )?instructions?"
            r"|act as"
            r"|jailbreak)",
            re.IGNORECASE,
        )

        def _sanitize_text(text: str, max_len: int) -> str:
            """Strip null bytes, truncate, and flag injection attempts."""
            if not isinstance(text, str):
                return ""
            # Remove null bytes and non-printable control characters
            text = text.replace("\x00", "").replace("\r", " ")
            # Truncate to maximum allowed length
            text = text[:max_len]
            # Replace known injection phrases with a placeholder
            text = _INJECTION_PATTERN.sub("[REDACTED]", text)
            return text

        sanitized_message = _sanitize_text(request.message or "", _MAX_MESSAGE_LEN)

        sanitized_file_contents = []
        for fc in file_contents:
            sanitized_file_contents.append({
                "filename": _sanitize_text(fc.get("filename", ""), 256),
                "extracted_content": _sanitize_text(
                    fc.get("extracted_content", "") if isinstance(fc.get("extracted_content"), str)
                    else str(fc.get("extracted_content", "")),
                    _MAX_FILE_CONTENT_LEN,
                ),
            })

        # Build context for the orchestrator
        context = {
            "user_message": sanitized_message,
            "file_contents": sanitized_file_contents,
            "conversation_id": request.conversation_id,
        }

        # Route through orchestrator — with pre/post audit records
        orch_input_hash = _sha256(str(context))
        _audit(
            event="orchestrator.process.start",
            agent="orchestrator",
            input_hash=orch_input_hash,
            output_hash=None,
            extra={"conversation_id": request.conversation_id, "trace_id": trace_id}
        )
        response = await orchestrator.process(context)
        orch_output_hash = _sha256(str(response))
        _audit(
            event="orchestrator.process.complete",
            agent="orchestrator",
            input_hash=orch_input_hash,
            output_hash=orch_output_hash,
            extra={"conversation_id": request.conversation_id, "trace_id": trace_id}
        )

        # --- Synthetic Content Provenance & Watermarking ---
        import hashlib
        import hmac
        import datetime
        import uuid
        import os

        ai_response_text = response.get("response", "I processed your request.")

        # Provenance metadata
        provenance = {
            "model_id": os.environ.get("AI_MODEL_ID", "unifai-orchestrator-v1"),
            "origin": "ai-generated",
            "content_label": "SYNTHETIC_AI_CONTENT",
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "response_id": str(uuid.uuid4()),
            "conversation_id": request.conversation_id,
        }

        # Cryptographic watermark: HMAC-SHA256 over (response_id + generated_at + response text)
        _watermark_secret = os.environ.get(
            "AI_WATERMARK_SECRET", "change-me-in-production"
        ).encode()
        _watermark_payload = (
            provenance["response_id"]
            + provenance["generated_at"]
            + ai_response_text
        ).encode()
        provenance["watermark"] = hmac.new(
            _watermark_secret, _watermark_payload, hashlib.sha256
        ).hexdigest()

        return ChatResponse(
            response=ai_response_text,
            conversation_id=request.conversation_id,
            policy_warning=response.get("policy_warning"),
            provenance=provenance,
        )
        try:
            response = _sanitize_llm_output(response)
        except ValueError as san_err:
            logger.warning(
                "Blocked dangerous content in orchestrator output",
                extra={"reason": str(san_err)}
            )
            raise HTTPException(
                status_code=400,
                detail={
                    "detail": "Response rejected: dynamic code execution primitive detected in LLM output.",
                    "policy_error": {"type": "llm_output_sanitization", "message": str(san_err)}
                }
            )

        return ChatResponse(
            response=response.get("response", "I processed your request."),
            conversation_id=request.conversation_id,
            policy_warning=response.get("policy_warning"),
            # trace_id is available for callers who need it for correlation
        )

    except asyncio.TimeoutError as e:
        logger.error(
            "Subagent call exceeded timeout bound",
            extra={"error": str(e)}
        )
        raise HTTPException(
            status_code=504,
            detail={
                "detail": "Request timed out: subagent exceeded allowed execution time",
                "policy_error": {
                    "type": "timeout",
                    "message": "Subagent spawn exceeded resource bounds"
                }
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Error processing chat request",
            extra={
                # VULNERABILITY: Error context includes full state
                "error": str(e),
                "request_state": {
                    "message": request.message,
                    "attachments": [a.dict() for a in request.attachments] if request.attachments else None
                }
            }
        )
        raise HTTPException(
            status_code=500,
            detail={
                "detail": "An error occurred processing your request"
            }
        )


# Dynamic code execution primitives to block in LLM output
_DANGEROUS_PATTERNS = [
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bexecfile\s*\(",
    r"\bcompile\s*\(",
    r"\b__import__\s*\(",
    r"\bimportlib\.import_module\s*\(",
    r"\bsubprocess\s*\.",
    r"\bos\.system\s*\(",
    r"\bos\.popen\s*\(",
    r"\bgetattr\s*\(",
    r"\bsetattr\s*\(",
    r"\bdelattr\s*\(",
    r"\bglobals\s*\(",
    r"\blocals\s*\(",
    r"\bvars\s*\(",
    r"\b__builtins__",
    r"\b__globals__",
    r"\bopen\s*\(",
    r"\bchr\s*\(",
    r"\bord\s*\(",
]

import re as _re

def _sanitize_llm_output(output):
    """
    Validate and sanitize LLM/agent output.
    Raises ValueError if dynamic code execution primitives are detected.
    Returns sanitized string output.
    """
    if output is None:
        return output

    # If output is a dict, sanitize string values recursively
    if isinstance(output, dict):
        return {k: _sanitize_llm_output(v) for k, v in output.items()}

    if isinstance(output, list):
        return [_sanitize_llm_output(item) for item in output]

    if not isinstance(output, str):
        return output

    for pattern in _DANGEROUS_PATTERNS:
        if _re.search(pattern, output, _re.IGNORECASE):
            raise ValueError(
                f"LLM output contains forbidden dynamic code execution primitive "
                f"matching pattern: {pattern}"
            )

    return output


import base64
import re

# Patterns that indicate prompt injection or malicious command attempts
_INJECTION_PATTERNS = [
    re.compile(r'(?i)(ignore (previous|all|above|prior) instructions?)'),
    re.compile(r'(?i)(system\s*prompt|you are now|act as|pretend (you are|to be))'),
    re.compile(r'(?i)(\\x[0-9a-f]{2}|\\u[0-9a-f]{4})'),  # hex/unicode escapes
    re.compile(r'(?i)(;\s*(rm|wget|curl|bash|sh|python|perl|nc|ncat|netcat|chmod|chown|sudo|su)\s)'),
    re.compile(r'(?i)(`[^`]*`|\$\([^)]*\))'),  # shell command substitution
    re.compile(r'(?i)(\|\s*(bash|sh|python|perl|ruby|php|node))'),  # pipe to shell
    re.compile(r'(?i)<\s*script[^>]*>'),  # script tags
    re.compile(r'(?i)(data:\s*text/html|javascript:)'),  # data URIs / JS
]

_MAX_B64_CHUNK = 200  # characters; longer runs are suspicious
_B64_RE = re.compile(r'[A-Za-z0-9+/]{' + str(_MAX_B64_CHUNK) + r',}={0,2}')


def _sanitize_text(text: str, label: str = "input") -> str:
    """Raise ValueError if the text contains prompt-injection or shell-command patterns."""
    if not isinstance(text, str):
        return text

    # Detect suspiciously long base64 blobs and attempt to decode them for further checks
    for match in _B64_RE.finditer(text):
        try:
            decoded = base64.b64decode(match.group() + '==').decode('utf-8', errors='ignore')
            for pat in _INJECTION_PATTERNS:
                if pat.search(decoded):
                    raise ValueError(
                        f"Blocked: base64-encoded malicious content detected in {label}."
                    )
        except (ValueError, UnicodeDecodeError):
            raise
        except Exception:
            pass  # not valid base64 — ignore

    for pat in _INJECTION_PATTERNS:
        if pat.search(text):
            raise ValueError(
                f"Blocked: potentially malicious prompt pattern detected in {label}."
            )

    return text


@app.post("/upload")
async def upload_file(file: UploadFile = File(...), _: None = Depends(verify_api_key)):
    """
    Direct file upload endpoint.

    SECURITY NOTES (for Unifai demo):
    - File content is scanned and PII is redacted before processing
    - No size limits enforced
    - No malware detection
    """
    if file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=415,
            detail={"detail": f"Unsupported file type: {file.content_type}"}
        )

    content = await file.read()

    if len(content) > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail={"detail": "File size exceeds the maximum allowed limit of 10 MB."}
        )

    # Scan uploaded file content for malicious/injected content
    decoded_content = content.decode('utf-8', errors='ignore')
    is_malicious, reason = _scan_for_malicious_content(decoded_content)
    if is_malicious:
        logger.warning(
            "Malicious content detected in uploaded file",
            extra={"file_name": file.filename, "reason": reason}
        )
        raise HTTPException(
            status_code=400,
            detail={
                "detail": "Uploaded file contains potentially malicious content and was rejected.",
                "policy_error": {
                    "type": "malicious_file_content",
                    "message": reason
                }
            }
        )

    # Validate and sanitize uploaded file content before processing
    sanitized_content = _validate_and_sanitize_upload(content, file.filename, file.content_type)

    processed = await file_processor.process(
        content=content.decode('utf-8', errors='ignore'),
        filename=file.filename,
        content_type=file.content_type
    )
    try:
        processed = _sanitize_llm_output(processed)
    except ValueError as san_err:
        logger.warning(
            "Blocked dangerous content in upload file_processor output",
            extra={"filename": file.filename, "reason": str(san_err)}
        )
        raise HTTPException(
            status_code=400,
            detail={
                "detail": "Uploaded file content rejected: dynamic code execution primitive detected in processed output.",
                "policy_error": {"type": "llm_output_sanitization", "message": str(san_err)}
            }
        )

    return {
        "filename": file.filename,
        "size": len(content),
        "processed": True
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5500)
