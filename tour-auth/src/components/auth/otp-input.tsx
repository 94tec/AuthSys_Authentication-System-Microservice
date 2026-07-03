"use client"
import React, { useRef, useCallback } from "react"
import { cn } from "@/lib/utils"

interface OtpInputProps {
  length?: number
  value: string
  onChange: (value: string) => void
  className?: string
  disabled?: boolean
}

export function OtpInput({ length = 6, value, onChange, className, disabled }: OtpInputProps) {
  const inputsRef = useRef<(HTMLInputElement | null)[]>([])
  const digits = value.padEnd(length, "").split("").slice(0, length)

  const focus = (i: number) => inputsRef.current[i]?.focus()

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>, idx: number) => {
      const raw = e.target.value.replace(/\D/g, "")
      if (!raw) {
        const next = [...digits]
        next[idx] = ""
        onChange(next.join(""))
        return
      }
      // Support paste: distribute chars across cells
      if (raw.length > 1) {
        const merged = raw.slice(0, length)
        onChange(merged.padEnd(length, "").slice(0, length))
        focus(Math.min(merged.length, length - 1))
        return
      }
      const next = [...digits]
      next[idx] = raw[0]
      onChange(next.join(""))
      if (idx < length - 1) focus(idx + 1)
    },
    [digits, length, onChange]
  )

  const handleKeyDown = (e: React.KeyboardEvent, idx: number) => {
    if (e.key === "Backspace" && !digits[idx] && idx > 0) focus(idx - 1)
    if (e.key === "ArrowLeft" && idx > 0) focus(idx - 1)
    if (e.key === "ArrowRight" && idx < length - 1) focus(idx + 1)
  }

  return (
    <div className={cn("flex gap-2 justify-center", className)}>
      {digits.map((d, i) => (
        <input
          key={i}
          ref={(el) => { inputsRef.current[i] = el }}
          type="text"
          inputMode="numeric"
          maxLength={6} // allow paste
          value={d}
          disabled={disabled}
          onChange={(e) => handleChange(e, i)}
          onKeyDown={(e) => handleKeyDown(e, i)}
          onFocus={(e) => e.target.select()}
          className="otp-cell disabled:opacity-50"
          aria-label={`Digit ${i + 1}`}
        />
      ))}
    </div>
  )
}
