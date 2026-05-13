'use client'

import { Message } from './ChatInterface'
import { ErrorDisplay } from './ErrorDisplay'
import { User, Bot, Paperclip } from 'lucide-react'

interface MessageListProps {
  messages: Message[]
}

export function MessageList({ messages }: MessageListProps) {
  return (
    <div className="flex flex-col">
      {messages.map((message) => (
        <div
          key={message.id}
          className={`py-6 ${
            message.role === 'assistant' ? 'bg-chat-hover' : ''
          }`}
        >
          <div className="max-w-3xl mx-auto px-4 flex gap-4">
            {/* Avatar */}
            <div
              className={`flex-shrink-0 w-8 h-8 rounded-sm flex items-center justify-center ${
                message.role === 'user'
                  ? 'bg-purple-600'
                  : 'bg-teal-600'
              }`}
            >
              {message.role === 'user' ? (
                <User className="w-5 h-5 text-white" />
              ) : (
                <Bot className="w-5 h-5 text-white" />
              )}
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0">
              {/* Attachments */}
              {message.attachments && message.attachments.length > 0 && (
                <div className="flex flex-wrap gap-2 mb-3">
                  {message.attachments.map((attachment) => (
                    <div
                      key={attachment.id}
                      className="flex items-center gap-2 bg-chat-input rounded-lg px-3 py-2 text-sm border border-chat-border"
                    >
                      <Paperclip className="w-4 h-4 text-gray-400" />
                      <span className="text-gray-300">{attachment.name}</span>
                      <span className="text-gray-500 text-xs">
                        ({formatFileSize(attachment.size)})
                      </span>
                    </div>
                  ))}
                </div>
              )}

                            {/* Message Content or Error */}
              {message.error ? (
                <ErrorDisplay error={message.error} />
              ) : (
                <div className="message-content text-gray-100">
                  {maskPII(message.content)}
                </div>
              )}
                >
                  {message.role === 'assistant' && (
                    <div className="flex items-center gap-1 mb-1">
                      <span
                        className="inline-flex items-center gap-1 text-xs font-medium text-teal-400 border border-teal-700 rounded px-1.5 py-0.5 bg-teal-950"
                        title={`AI-generated content | Generated at: ${message.timestamp.toISOString()}`}
                        aria-label="AI-generated content"
                      >
                        <Bot className="w-3 h-3" />
                        AI-Generated
                      </span>
                    </div>
                  )}
                  {message.content}
                </div>
              )}

              {/* Timestamp */}
              <div className="text-xs text-gray-500 mt-2">
                {formatTime(message.timestamp)}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

/**
 * Replaces common PII patterns in a string with redacted placeholders.
 * Patterns covered: SSN, credit card numbers, phone numbers, email addresses,
 * and simple US street addresses.
 */
function maskPII(text: string): string {
  if (!text) return text

  // SSN: 123-45-6789 or 123 45 6789 or 123456789
  text = text.replace(/\b\d{3}[\s-]\d{2}[\s-]\d{4}\b/g, '[SSN REDACTED]')
  text = text.replace(/\b\d{9}\b/g, '[SSN REDACTED]')

  // Credit card numbers (13–16 digits, optionally separated by spaces or dashes)
  text = text.replace(/\b(?:\d[ -]?){13,16}\b/g, '[CC REDACTED]')

  // Phone numbers: various formats
  text = text.replace(
    /\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
    '[PHONE REDACTED]'
  )

  // Email addresses
  text = text.replace(
    /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
    '[EMAIL REDACTED]'
  )

  // Simple US street addresses: e.g. "123 Main St", "456 Elm Avenue"
  text = text.replace(
    /\b\d+\s+[A-Za-z0-9\s]+(?:St|Street|Ave|Avenue|Blvd|Boulevard|Rd|Road|Dr|Drive|Ln|Lane|Way|Ct|Court|Pl|Place)\b\.?/gi,
    '[ADDRESS REDACTED]'
  )

  return text
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatTime(date: Date): string {
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}
