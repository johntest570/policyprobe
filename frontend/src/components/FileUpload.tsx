'use client'

import { useState, useCallback, useRef } from 'react'
import { Upload, FileText, Image, File } from 'lucide-react'

interface FileUploadProps {
  onFilesSelected: (files: File[]) => void
}

const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024 // 10 MB

// Suspicious patterns that should never appear in documents sent to the AI model
const SUSPICIOUS_TEXT_PATTERNS = [
  /<script[\s\S]*?>/i,
  /javascript\s*:/i,
  /vbscript\s*:/i,
  /on\w+\s*=/i,          // inline event handlers
  /data\s*:\s*text\/html/i,
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
  /\bsystem\s*\(/i,
  /\bpasswd\b/i,
  /\b\/etc\/shadow\b/i,
]

// Magic-byte signatures for allowed image types
const IMAGE_MAGIC: Record<string, number[][]> = {
  'image/jpeg': [[0xff, 0xd8, 0xff]],
  'image/png':  [[0x89, 0x50, 0x4e, 0x47]],
}

async function sanitizeFile(file: File): Promise<{ ok: boolean; reason?: string }> {
  // 1. Size check
  if (file.size > MAX_FILE_SIZE_BYTES) {
    return { ok: false, reason: `"${file.name}" exceeds the 10 MB size limit.` }
  }

  const buffer = await file.arrayBuffer()
  const bytes = new Uint8Array(buffer)

  // 2. Null-byte check (common in binary exploits embedded in documents)
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0x00 && !file.type.startsWith('image/') && file.type !== 'application/pdf') {
      return { ok: false, reason: `"${file.name}" contains null bytes and may be malicious.` }
    }
  }

  // 3. Magic-byte validation for images
  if (file.type.startsWith('image/')) {
    const signatures = IMAGE_MAGIC[file.type]
    if (signatures) {
      const matched = signatures.some(sig =>
        sig.every((byte, idx) => bytes[idx] === byte)
      )
      if (!matched) {
        return { ok: false, reason: `"${file.name}" does not match expected image format.` }
      }
    }
    // Images pass — no text scanning needed
    return { ok: true }
  }

  // 4. Text-content scanning for non-image files
  const decoder = new TextDecoder('utf-8', { fatal: false })
  const text = decoder.decode(buffer)

  for (const pattern of SUSPICIOUS_TEXT_PATTERNS) {
    if (pattern.test(text)) {
      return { ok: false, reason: `"${file.name}" contains potentially malicious content.` }
    }
  }

  return { ok: true }
}

export function FileUpload({ onFilesSelected }: FileUploadProps) {
  const [isDragOver, setIsDragOver] = useState(false)
  const [validationError, setValidationError] = useState<string | null>(null)

  const sanitizeAndValidateFiles = useCallback(
    async (files: File[]) => {
      setValidationError(null)
      const safeFiles: File[] = []
      const errors: string[] = []

      for (const file of files) {
        const result = await sanitizeFile(file)
        if (result.ok) {
          safeFiles.push(file)
        } else {
          errors.push(result.reason ?? `"${file.name}" failed validation.`)
        }
      }

      if (errors.length > 0) {
        setValidationError(errors.join(' '))
      }

      if (safeFiles.length > 0) {
        onFilesSelected(safeFiles)
      }
    },
    [onFilesSelected]
  )

      const handleDrop = useCallback(
    async (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault()
      setIsDragOver(false)

      const files = Array.from(e.dataTransfer.files)
      const validFiles = files.filter(isValidFileType)
      const safeFiles = await filterFilesForPII(validFiles)

      if (safeFiles.length > 0) {
        onFilesSelected(safeFiles)
      }
    },
    [onFilesSelected]
  ) => {
      e.preventDefault()
      setIsDragOver(false)

      const files = Array.from(e.dataTransfer.files)
      const validFiles = files.filter(isValidFileType)

      if (validFiles.length > 0) {
        const redactedFiles = await redactPIIFromFiles(validFiles)
        onFilesSelected(redactedFiles)
      }
    },
    [onFilesSelected]
  ) => {
      e.preventDefault()
      setIsDragOver(false)

      const files = Array.from(e.dataTransfer.files)
      const validFiles = files.filter(isValidFileType)

      if (validFiles.length > 0) {
        sanitizeAndValidateFiles(validFiles)
      }
    },
    [onFilesSelected]
  )

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragOver(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragOver(false)
  }, [])

      const handleFileInput = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      if (e.target.files) {
        const files = Array.from(e.target.files)
        const validFiles = files.filter(isValidFileType)
        const safeFiles = await filterFilesForPII(validFiles)

        if (safeFiles.length > 0) {
          onFilesSelected(safeFiles)
        }
      }
    },
    [onFilesSelected]
  ) => {
      if (e.target.files) {
        const files = Array.from(e.target.files)
        const validFiles = files.filter(isValidFileType)

        if (validFiles.length > 0) {
          const redactedFiles = await redactPIIFromFiles(validFiles)
          onFilesSelected(redactedFiles)
        }
      }
    },
    [onFilesSelected]
  ) => {
      if (e.target.files) {
        const files = Array.from(e.target.files)
        const validFiles = files.filter(isValidFileType)

        if (validFiles.length > 0) {
          sanitizeAndValidateFiles(validFiles)
        }
      }
    },
    [onFilesSelected]
  )

  return (
    <div
      className={`file-upload-zone rounded-lg p-6 text-center cursor-pointer ${
        isDragOver ? 'drag-over' : ''
      }`}
      onDrop={handleDrop}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
    >
      {validationError && (
        <p className="text-red-400 text-sm mb-2" role="alert">{validationError}</p>
      )}
      <input
        type="file"
        multiple
        accept=".pdf,.doc,.docx,.html,.htm,.txt,.json,.jpg,.jpeg,.png"
        className="hidden"
        id="file-upload-input"
        onChange={handleFileInput}
      />
      <label htmlFor="file-upload-input" className="cursor-pointer">
        <Upload className="w-10 h-10 text-gray-400 mx-auto mb-3" />
        <p className="text-gray-300 mb-2">
          Drag and drop files here, or click to browse
        </p>
        <div className="flex justify-center gap-4 text-xs text-gray-500">
          <div className="flex items-center gap-1">
            <FileText className="w-4 h-4" />
            <span>PDF, DOC, HTML</span>
          </div>
          <div className="flex items-center gap-1">
            <Image className="w-4 h-4" />
            <span>JPG, PNG</span>
          </div>
          <div className="flex items-center gap-1">
            <File className="w-4 h-4" />
            <span>TXT, JSON</span>
          </div>
        </div>
      </label>
    </div>
  )
}

function isValidFileType(file: File): boolean {
  const validTypes = [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/html',
    'text/plain',
    'application/json',
    'image/jpeg',
    'image/png',
  ]

  const validExtensions = ['.pdf', '.doc', '.docx', '.html', '.htm', '.txt', '.json', '.jpg', '.jpeg', '.png']

  const hasValidType = validTypes.includes(file.type)
  const hasValidExtension = validExtensions.some(ext =>
    file.name.toLowerCase().endsWith(ext)
  )

  return hasValidType || hasValidExtension
}
