import { NextRequest, NextResponse } from 'next/server'
import { createHash } from 'crypto'
import { appendFileSync } from 'fs'
import { join } from 'path'

// Patterns that indicate dynamic code execution primitives in LLM output
const DANGEROUS_PATTERNS: RegExp[] = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /new\s+Function\s*\(/gi,
  /\bsetTimeout\s*\(\s*['"`]/gi,
  /\bsetInterval\s*\(\s*['"`]/gi,
  /\bsetImmediate\s*\(\s*['"`]/gi,
  /\bexecScript\s*\(/gi,
  /\bindirect\s+eval\b/gi,
  /\bvm\.runInThisContext\s*\(/gi,
  /\bvm\.runInNewContext\s*\(/gi,
  /\bvm\.runInContext\s*\(/gi,
  /\bprocess\.binding\s*\(/gi,
  /\brequire\s*\(\s*['"`]child_process/gi,
  /\bspawn\s*\(/gi,
  /\bexecSync\s*\(/gi,
]

function containsDangerousCode(value: string): boolean {
  return DANGEROUS_PATTERNS.some((pattern) => pattern.test(value))
}

function sanitizeLLMOutput(data: unknown): { safe: boolean; sanitized: unknown } {
  if (typeof data === 'string') {
    if (containsDangerousCode(data)) {
      return { safe: false, sanitized: null }
    }
    return { safe: true, sanitized: data }
  }

  if (Array.isArray(data)) {
    const sanitizedArray: unknown[] = []
    for (const item of data) {
      const result = sanitizeLLMOutput(item)
      if (!result.safe) {
        return { safe: false, sanitized: null }
      }
      sanitizedArray.push(result.sanitized)
    }
    return { safe: true, sanitized: sanitizedArray }
  }

  if (data !== null && typeof data === 'object') {
    const sanitizedObj: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
      const result = sanitizeLLMOutput(value)
      if (!result.safe) {
        return { safe: false, sanitized: null }
      }
      sanitizedObj[key] = result.sanitized
    }
    return { safe: true, sanitized: sanitizedObj }
  }

  // Primitives other than string (number, boolean, null) are safe
  return { safe: true, sanitized: data }
}

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5500'
const API_SECRET = process.env.API_SECRET
const BACKEND_API_KEY = process.env.BACKEND_API_KEY
const BACKEND_API_KEY = process.env.BACKEND_API_KEY
const AUDIT_LOG_PATH = process.env.AUDIT_LOG_PATH || join(process.cwd(), 'audit-ai-chat.log')

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

function writeAuditRecord(record: Record<string, unknown>): void {
  const line = JSON.stringify(record) + '\n'
  try {
    appendFileSync(AUDIT_LOG_PATH, line, { encoding: 'utf8', flag: 'a' })
  } catch (fsErr) {
    // Fall back to structured stderr so the record is still capturable by log aggregators
    process.stderr.write('[AUDIT FALLBACK] ' + line)
  }
}

export async function POST(request: NextRequest) {
  const requestTimestamp = new Date().toISOString()
  // Capture principal: prefer X-Forwarded-For, fall back to a placeholder
  const principal =
    request.headers.get('x-forwarded-for') ??
    request.headers.get('x-real-ip') ??
    'unknown'

  let bodyRaw = ''
  let body: unknown = {}

  try {
    bodyRaw = await request.text()
    body = JSON.parse(bodyRaw)
  } catch {
    // bodyRaw stays as-is; body stays as empty object
  }

  const inputHash = sha256(bodyRaw)

  try {
        if (!BACKEND_API_KEY) {
      console.error('BACKEND_API_KEY is not configured')
      return NextResponse.json(
        {
          detail: 'Backend authentication is not configured',
          policy_error: {
            type: 'authentication',
            message: 'Inter-agent authentication secret is missing',
          },
        },
        { status: 500 }
      )
    }

        if (!BACKEND_API_KEY) {
      console.error('BACKEND_API_KEY environment variable is not set')
      return NextResponse.json({ detail: 'Server misconfiguration' }, { status: 500 })
    }

    const response = await fetch(`${BACKEND_URL}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${BACKEND_API_KEY}`,
      },
      body: JSON.stringify(body),
    })

    const data = await response.json()
    const responseTimestamp = new Date().toISOString()
    const outputRaw = JSON.stringify(data)
    const outputHash = sha256(outputRaw)

    // Extract model identifier from response if the backend surfaces it
    const modelId: string =
      (data as Record<string, unknown>)?.model as string ??
      (data as Record<string, unknown>)?.model_id as string ??
      'unknown'

    writeAuditRecord({
      event: 'ai_chat_proxy',
      request_timestamp: requestTimestamp,
      response_timestamp: responseTimestamp,
      principal,
      input_hash: inputHash,
      output_hash: outputHash,
      model_id: modelId,
      http_status: response.status,
      outcome: response.ok ? 'success' : 'backend_error',
    })

    if (!response.ok) {
      return NextResponse.json(data, { status: response.status })
    }

    return NextResponse.json(data)
  } catch (error) {
    const errorTimestamp = new Date().toISOString()
    writeAuditRecord({
      event: 'ai_chat_proxy',
      request_timestamp: requestTimestamp,
      error_timestamp: errorTimestamp,
      principal,
      input_hash: inputHash,
      model_id: 'unknown',
      outcome: 'proxy_error',
      error_message: error instanceof Error ? error.message : String(error),
    })
    return NextResponse.json(
      {
        detail: 'Failed to connect to backend service',
        policy_error: {
          type: 'general',
          message: 'Backend service unavailable',
        },
      },
      { status: 503 }
    )
  }
},
        { status: 400 }
      )
    }

    // Sanitize: trim whitespace and enforce a maximum length
    const MAX_MESSAGE_LENGTH = 4000
    const sanitizedMessage = body.message.trim()
    if (sanitizedMessage.length === 0) {
      return NextResponse.json(
        { detail: 'Invalid request: "message" must not be empty.' },
        { status: 400 }
      )
    }
    if (sanitizedMessage.length > MAX_MESSAGE_LENGTH) {
      return NextResponse.json(
        { detail: `Invalid request: "message" must not exceed ${MAX_MESSAGE_LENGTH} characters.` },
        { status: 400 }
      )
    }

    // Reconstruct a safe payload with only known, expected fields
    const sanitizedBody: Record<string, unknown> = { message: sanitizedMessage }
    if (body.conversation_id !== undefined) {
      if (typeof body.conversation_id !== 'string' && typeof body.conversation_id !== 'number') {
        return NextResponse.json(
          { detail: 'Invalid request: "conversation_id" must be a string or number.' },
          { status: 400 }
        )
      }
      sanitizedBody.conversation_id = body.conversation_id
    }

    const response = await fetch(`${BACKEND_URL}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(sanitizedBody),
    })

    const data = await response.json()

    if (!response.ok) {
      const errorCheck = sanitizeLLMOutput(data)
      if (!errorCheck.safe) {
        console.warn('Dangerous code execution primitive detected in LLM error response; blocking.')
        return NextResponse.json(
          { detail: 'Response blocked: unsafe content detected in LLM output.' },
          { status: 502 }
        )
      }
      return NextResponse.json(errorCheck.sanitized, { status: response.status })
    }

    const { safe, sanitized } = sanitizeLLMOutput(data)
    if (!safe) {
      console.warn('Dangerous code execution primitive detected in LLM response; blocking.')
      return NextResponse.json(
        { detail: 'Response blocked: unsafe content detected in LLM output.' },
        { status: 502 }
      )
    }

    return NextResponse.json(sanitized)
  } catch (error) {
    console.error('Backend proxy error:', error)
    return NextResponse.json(
      {
        detail: 'Failed to connect to backend service',
        policy_error: {
          type: 'general',
          message: 'Backend service unavailable',
        },
      },
      { status: 503 }
    )
  }
}
