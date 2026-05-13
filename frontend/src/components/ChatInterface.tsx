'use client'

import { useState, useRef, useEffect } from 'react'
import { useSession } from 'next-auth/react'
import { v4 as uuidv4 } from 'uuid'
import { MessageList } from './MessageList'
import { FileUpload } from './FileUpload'
import { Send, Paperclip, Loader2 } from 'lucide-react'

export interface Message {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: Date
  attachments?: FileAttachment[]
  error?: PolicyError
}

export interface FileAttachment {
  id: string
  name: string
  type: string
  size: number
  content?: string
}

export interface PolicyError {
  type: 'pii' | 'threat' | 'auth' | 'general'
  message: string
  details?: Record<string, unknown>
}

// --- Input sanitization & validation helpers ---

const MAX_INPUT_LENGTH = 4000
const MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024 // 1 MB
const ALLOWED_FILE_TYPES = new Set([
  'text/plain',
  'text/markdown',
  'text/csv',
  'application/json',
  'application/pdf',
])

function sanitizeTextInput(text: string): string {
  // Trim whitespace
  let sanitized = text.trim()
  // Truncate to max length
  if (sanitized.length > MAX_INPUT_LENGTH) {
    sanitized = sanitized.slice(0, MAX_INPUT_LENGTH)
  }
  // Remove null bytes and other non-printable control characters (except common whitespace)
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
  return sanitized
}

function validateFileAttachment(file: File): string | null {
  if (!ALLOWED_FILE_TYPES.has(file.type)) {
    return `File type "${file.type}" is not allowed. Permitted types: ${[...ALLOWED_FILE_TYPES].join(', ')}.`
  }
  if (file.size > MAX_FILE_SIZE_BYTES) {
    return `File "${file.name}" exceeds the maximum allowed size of 1 MB.`
  }
  return null
}

function sanitizeFileContent(content: string): string {
  // Truncate file content to avoid excessively large payloads
  const MAX_CONTENT_LENGTH = 50000
  let sanitized = content
  if (sanitized.length > MAX_CONTENT_LENGTH) {
    sanitized = sanitized.slice(0, MAX_CONTENT_LENGTH)
  }
  // Remove null bytes and non-printable control characters
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
  return sanitized
}

// --- End helpers ---

// Patterns indicative of prompt injection or malicious content in uploaded files
const MALICIOUS_PATTERNS: { label: string; pattern: RegExp }[] = [
  // Direct prompt injection attempts
  { label: 'prompt injection', pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i },
  { label: 'prompt injection', pattern: /you\s+are\s+now\s+(a\s+)?(?!assistant|helpful)/i },
  { label: 'prompt injection', pattern: /disregard\s+(all\s+)?(previous|prior|above)/i },
  { label: 'prompt injection', pattern: /new\s+instructions?\s*:/i },
  { label: 'prompt injection', pattern: /system\s*prompt\s*:/i },
  { label: 'prompt injection', pattern: /\[INST\]|\[\/?SYS\]|<\|im_start\|>|<\|im_end\|>/i },
  // Shell commands
  { label: 'shell command', pattern: /(?:^|\s)(rm\s+-rf|sudo\s+|chmod\s+|chown\s+|wget\s+|curl\s+.*\|\s*(?:bash|sh)|eval\s*\(|exec\s*\()/m },
  { label: 'shell command', pattern: /`[^`]{0,200}`/ },
  { label: 'shell command', pattern: /\$\([^)]{0,200}\)/ },
  // Base64-encoded content (long base64 strings that may hide instructions)
  { label: 'base64 encoded content', pattern: /(?:[A-Za-z0-9+\/]{40,}={0,2})/ },
  // Leetspeak patterns that spell out injection keywords
  { label: 'leetspeak injection', pattern: /1[Gg][Nn][Oo][Rr][Ee]\s+[Pp][Rr][Ee][Vv][Ii][Oo][Uu][Ss]/i },
  { label: 'leetspeak injection', pattern: /[!i1][gq9][n][o0][r][e3]\s+[a4][l1][l1]/i },
  // Hidden unicode / zero-width characters used to smuggle instructions
  { label: 'hidden unicode characters', pattern: /[\u200B-\u200D\uFEFF\u00AD\u2060]/ },
  // Attempts to override role or persona
  { label: 'role override', pattern: /act\s+as\s+(if\s+you\s+are|a)\s+(?!helpful|an\s+assistant)/i },
  { label: 'role override', pattern: /pretend\s+(you\s+are|to\s+be)\s+/i },
  { label: 'role override', pattern: /your\s+(true\s+)?role\s+is/i },
  // Data exfiltration patterns
  { label: 'data exfiltration', pattern: /send\s+(all\s+)?(user\s+data|credentials?|passwords?|api\s+keys?)/i },
  { label: 'data exfiltration', pattern: /exfiltrate|exfil\b/i },
]

function sanitizeFileContent(content: string, fileName: string): string {
  for (const { label, pattern } of MALICIOUS_PATTERNS) {
    if (pattern.test(content)) {
      throw new Error(
        `File "${fileName}" was rejected because it contains potentially malicious content (${label}). Please review the file before uploading.`
      )
    }
  }
  // Strip any zero-width / invisible characters as an extra precaution
  return content.replace(/[\u200B-\u200D\uFEFF\u00AD\u2060]/g, '')
}

// ---------------------------------------------------------------------------
// Client-side prompt sanitization
// ---------------------------------------------------------------------------
const INVISIBLE_CHAR_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\uFFF9-\uFFFC]/;

// Base64 blocks of 20+ chars (heuristic for encoded payloads)
const BASE64_PAYLOAD_RE = /(?:[A-Za-z0-9+/]{20,}={0,2})/;

// Common shell / OS command patterns
const SHELL_CMD_RE = /(?:^|[\s;|&`$(){}])(?:bash|sh|zsh|cmd|powershell|pwsh|exec|eval|system|popen|subprocess|os\.system|__import__|importlib|curl\s|wget\s|nc\s|ncat\s|netcat\s|chmod\s|chown\s|rm\s+-[rf]|dd\s+if=|mkfifo|socat\s)/i;

// Binary / executable magic bytes encoded as text or escape sequences
const BINARY_RE = /(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|%[0-9a-f]{2}){4,}/i;

// Leetspeak substitution that reconstructs dangerous keywords
function normalizeLeet(text: string): string {
  return text
    .replace(/0/g, 'o')
    .replace(/1/g, 'i')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/@/g, 'a')
    .replace(/\$/g, 's');
}

const LEET_DANGEROUS_RE = /(?:exec|eval|system|shell|script|import|payload|exploit|inject|bypass|malware|rootkit|backdoor|keylog|ransomware)/i;

function sanitizePrompt(text: string): { safe: boolean; reason?: string } {
  if (INVISIBLE_CHAR_RE.test(text)) {
    return { safe: false, reason: 'Input contains hidden or invisible characters that are not allowed.' };
  }
  if (BASE64_PAYLOAD_RE.test(text)) {
    // Only flag if it looks like an encoded command (contains shell keywords after decode attempt)
    try {
      const decoded = atob(text.match(BASE64_PAYLOAD_RE)![0]);
      if (SHELL_CMD_RE.test(decoded) || LEET_DANGEROUS_RE.test(decoded)) {
        return { safe: false, reason: 'Input appears to contain a base64-encoded command payload.' };
      }
    } catch {
      // Not valid base64 — ignore
    }
  }
  if (SHELL_CMD_RE.test(text)) {
    return { safe: false, reason: 'Input contains shell command patterns that are not allowed.' };
  }
  if (BINARY_RE.test(text)) {
    return { safe: false, reason: 'Input contains binary or executable byte sequences that are not allowed.' };
  }
  const normalized = normalizeLeet(text);
  if (LEET_DANGEROUS_RE.test(normalized)) {
    return { safe: false, reason: 'Input contains obfuscated dangerous keywords that are not allowed.' };
  }
  return { safe: true };
}
// ---------------------------------------------------------------------------

// PII patterns and redaction utility
const PII_PATTERNS: Array<{ pattern: RegExp; placeholder: string }> = [
  { pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, placeholder: '[REDACTED_EMAIL]' },
  { pattern: /\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g, placeholder: '[REDACTED_PHONE]' },
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, placeholder: '[REDACTED_SSN]' },
  { pattern: /\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{3,4}\b/g, placeholder: '[REDACTED_CARD]' },
  { pattern: /\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b/g, placeholder: '[REDACTED_NAME]' },
  { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, placeholder: '[REDACTED_IP]' },
]

function redactPII(text: string): string {
  let redacted = text
  for (const { pattern, placeholder } of PII_PATTERNS) {
    redacted = redacted.replace(pattern, placeholder)
  }
  return redacted
}

// Singapore PII detection patterns
const SINGAPORE_PII_PATTERNS: { name: string; pattern: RegExp }[] = [
  // NRIC/FIN: S/T/F/G followed by 7 digits and a letter
  { name: 'NRIC/FIN', pattern: /\b[STFG]\d{7}[A-Z]\b/i },
  // SingPass ID (same format as NRIC/FIN, but also catch common "SingPass" label proximity)
  { name: 'SingPass ID', pattern: /singpass[\s:]*[STFG]\d{7}[A-Z]/i },
  // Singapore mobile numbers: +65 or 65 followed by 8-digit number starting with 8 or 9
  { name: 'Singapore phone number', pattern: /(?:\+65|\b65)?\s*[89]\d{7}\b/ },
  // Singapore postal codes: 6-digit codes in range 010000–829999
  { name: 'Singapore postal code', pattern: /\b(?:0[1-9]|[1-7]\d|8[0-2])\d{4}\b/ },
]

function detectSingaporePII(text: string): string[] {
  const found: string[] = []
  for (const { name, pattern } of SINGAPORE_PII_PATTERNS) {
    if (pattern.test(text)) {
      found.push(name)
    }
  }
  return found
}

export function ChatInterface() {
  const { data: session, status } = useSession()
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [pendingFiles, setPendingFiles] = useState<File[]>([])
  const [showFileUpload, setShowFileUpload] = useState(false)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // Stable session ID generated once per component mount
  const [sessionId] = useState<string>(() => uuidv4())
  // Per-session HMAC key generated once and reused for all requests
  const sessionKeyRef = useRef<CryptoKey | null>(null)

  // Derive a signed conversation token: base64url(sessionId|iat) + '.' + base64url(hmac)
  const getSignedConversationToken = async (): Promise<string> => {
    if (!sessionKeyRef.current) {
      sessionKeyRef.current = await crypto.subtle.generateKey(
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign', 'verify']
      )
    }
    const iat = Math.floor(Date.now() / 1000)
    const payload = `${sessionId}|${iat}`
    const encoder = new TextEncoder()
    const sigBuffer = await crypto.subtle.sign(
      'HMAC',
      sessionKeyRef.current,
      encoder.encode(payload)
    )
    const sigBase64 = btoa(String.fromCharCode(...new Uint8Array(sigBuffer)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    const payloadBase64 = btoa(payload)
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    return `${payloadBase64}.${sigBase64}`
  }

  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus()
    }
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!input.trim() && pendingFiles.length === 0) return

    // Sanitize user input before sending to the AI endpoint
    if (input.trim()) {
      const sanitization = sanitizePrompt(input)
      if (!sanitization.safe) {
        const blockMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: `⚠️ Your message was blocked: ${sanitization.reason}`,
          timestamp: new Date(),
          error: { type: 'threat', message: sanitization.reason ?? 'Blocked by prompt safety filter.' },
        }
        setMessages(prev => [...prev, blockMessage])
        setInput('')
        return
      }
    }

    // Validate and sanitize text input
    const sanitizedInput = sanitizeTextInput(input)

    const attachments: FileAttachment[] = []

    // Validate and process pending files
    for (const file of pendingFiles) {
      const validationError = validateFileAttachment(file)
      if (validationError) {
        const errMsg: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: validationError,
          timestamp: new Date(),
          error: { type: 'general', message: validationError },
        }
        setMessages(prev => [...prev, errMsg])
        return
      }
      const rawContent = await readFileContent(file)
      const content = sanitizeFileContent(rawContent)
      attachments.push({
        id: uuidv4(),
        name: file.name,
        type: file.type,
        size: file.size,
        content,
      })
    }

          const userMessage: Message = {
        id: uuidv4(),
        role: 'user',
        content: sanitizedInput || `Uploaded ${pendingFiles.length} file(s)`,
      timestamp: new Date(),
      attachments: attachments.length > 0 ? attachments : undefined,
    }

    setMessages(prev => [...prev, userMessage])
    setInput('')
    setPendingFiles([])
    setShowFileUpload(false)
    setIsLoading(true)

    try {
            // Data minimisation: strip file content before forwarding to backend.
      // Only send metadata; never forward raw/base64 file bytes.
      const MAX_ATTACHMENTS = 5
      const MAX_FILE_SIZE_BYTES = 512 * 1024 // 512 KB per file
      const sanitisedAttachments = attachments
        .slice(0, MAX_ATTACHMENTS)
        .filter(a => a.size <= MAX_FILE_SIZE_BYTES)
        .map(({ id, name, type, size }) => ({ id, name, type, size }))

      const sessionToken =
        (typeof window !== 'undefined' &&
          (sessionStorage.getItem('auth_token') ||
            localStorage.getItem('auth_token'))) ||
        ''

      const response = await fetch('/api/backend/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
        },
                body: JSON.stringify({
          message: input,
          attachments: attachments,
          conversation_id: await getSignedConversationToken(),
        }),
      }),
      })

      const data = await response.json()

      if (!response.ok) {
        // Handle policy violations returned as errors
        const errorMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: sanitizeLLMOutput(data.detail || 'An error occurred'),
          timestamp: new Date(),
          error: data.policy_error ? {
            type: data.policy_error.type,
            message: data.policy_error.message,
            details: data.policy_error.details,
          } : undefined,
        }
        setMessages(prev => [...prev, errorMessage])
      } else {
                const aiTimestamp = new Date()
        const provenanceFooter =
          `\n\n---\n` +
          `⚠️ **AI-Generated Content** | ` +
          `Model: ${data.model_id ?? 'ai-assistant'} | ` +
          `Generated: ${aiTimestamp.toISOString()} | ` +
          `Origin: synthetic`
        const assistantMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: data.response + provenanceFooter,
          timestamp: aiTimestamp,
          // Provenance metadata for synthetic AI-generated content
          ...({
            syntheticOrigin: true,
            modelId: data.model_id ?? 'ai-assistant',
            generatedAt: aiTimestamp.toISOString(),
          } as Record<string, unknown>),
          error: data.policy_warning ? {
            type: data.policy_warning.type,
            message: data.policy_warning.message,
            details: data.policy_warning.details,
          } : undefined,
        } : undefined,
        }
        setMessages(prev => [...prev, assistantMessage])
      }
    } catch (error) {
      const errorMessage: Message = {
        id: uuidv4(),
        role: 'assistant',
        content: 'Failed to connect to the backend. Please ensure the server is running.',
        timestamp: new Date(),
        error: {
          type: 'general',
          message: 'Connection error',
        },
      }
      setMessages(prev => [...prev, errorMessage])
    } finally {
      setIsLoading(false)
    }
  }

  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bnew\s+Function\s*\(/gi,
    /\bsetTimeout\s*\(\s*['"`]/gi,
    /\bsetInterval\s*\(\s*['"`]/gi,
    /\bimportScripts\s*\(/gi,
    /\bdocument\.write\s*\(/gi,
    /\bwindow\s*\[\s*['"`]/gi,
    /\bglobalThis\s*\[\s*['"`]/gi,
    /\bFunction\s*\(/gi,
  ]

  const sanitizeLLMOutput = (text: string): string => {
    if (typeof text !== 'string') return 'Invalid response received.'
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(text)) {
        console.warn('Potentially dangerous content detected in LLM output and blocked.')
        return '[Response blocked: contains disallowed dynamic code execution primitives.]'
      }
    }
    return text
  }

  const readFileContent = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => {
        const result = reader.result as string
        // For binary files, return base64
        if (file.type.startsWith('image/') || file.type === 'application/pdf') {
          resolve(result.split(',')[1]) // Remove data URL prefix
        } else {
          resolve(result)
        }
      }
      reader.onerror = reject

      if (file.type.startsWith('image/') || file.type === 'application/pdf') {
        reader.readAsDataURL(file)
      } else {
        reader.readAsText(file)
      }
    })
  }

  const handleFileSelect = (files: File[]) => {
    setPendingFiles(prev => [...prev, ...files])
  }

  const removePendingFile = (index: number) => {
    setPendingFiles(prev => prev.filter((_, i) => i !== index))
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmit(e)
    }
  }

  return (
    <div className="flex flex-col h-screen">
      {/* Header */}
      <header className="flex items-center justify-center py-3 border-b border-chat-border bg-chat-sidebar">
        <h1 className="text-xl font-semibold text-white">PolicyProbe</h1>
      </header>

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto chat-scrollbar">
        {messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-gray-400">
            <div className="text-4xl mb-4">🔍</div>
            <h2 className="text-2xl font-medium text-white mb-2">PolicyProbe</h2>
            <p className="text-center max-w-md">
              Upload documents to analyze or ask questions about policy compliance.
              <br />
              <span className="text-sm text-gray-500 mt-2 block">
                Supports PDF, Word, HTML, and image files
              </span>
            </p>
          </div>
        ) : (
          <MessageList messages={messages} />
        )}
      </div>

      {/* File Upload Modal */}
      {showFileUpload && (
        <div className="border-t border-chat-border bg-chat-input p-4">
          <FileUpload onFilesSelected={handleFileSelect} />
        </div>
      )}

      {/* Pending Files Display */}
      {pendingFiles.length > 0 && (
        <div className="border-t border-chat-border bg-chat-input px-4 py-2">
          <div className="flex flex-wrap gap-2">
            {pendingFiles.map((file, index) => (
              <div
                key={index}
                className="flex items-center gap-2 bg-chat-hover rounded-lg px-3 py-1.5 text-sm"
              >
                <span className="text-gray-300">{file.name}</span>
                <button
                  onClick={() => removePendingFile(index)}
                  className="text-gray-500 hover:text-red-400"
                >
                  ×
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Input Area */}
      <div className="border-t border-chat-border bg-chat-bg p-4">
        <form onSubmit={handleSubmit} className="max-w-3xl mx-auto">
          <div className="relative flex items-end bg-chat-input rounded-xl border border-chat-border">
            {/* File Upload Button */}
            <button
              type="button"
              onClick={() => setShowFileUpload(!showFileUpload)}
              className="p-3 text-gray-400 hover:text-white transition-colors"
            >
              <Paperclip className="w-5 h-5" />
            </button>

            {/* Hidden file input */}
            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept=".pdf,.doc,.docx,.html,.htm,.txt,.json,.jpg,.jpeg,.png"
              className="hidden"
              onChange={(e) => {
                if (e.target.files) {
                  handleFileSelect(Array.from(e.target.files))
                }
              }}
            />

            {/* Text Input */}
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Message PolicyProbe..."
              className="flex-1 bg-transparent text-white placeholder-gray-500 resize-none py-3 pr-12 focus:outline-none max-h-48"
              rows={1}
              disabled={isLoading}
            />

            {/* Send Button */}
            <button
              type="submit"
              disabled={isLoading || (!input.trim() && pendingFiles.length === 0)}
              className="absolute right-2 bottom-2 p-2 text-gray-400 hover:text-white disabled:opacity-50 disabled:hover:text-gray-400 transition-colors"
            >
              {isLoading ? (
                <Loader2 className="w-5 h-5 animate-spin" />
              ) : (
                <Send className="w-5 h-5" />
              )}
            </button>
          </div>
          <p className="text-xs text-center text-gray-500 mt-2">
            PolicyProbe demonstrates AI policy evaluation and remediation
          </p>
        </form>
      </div>
    </div>
  )
}
