"use client"
interface PasswordStrengthProps {
  password: string
}

function getStrength(p: string): { score: number; label: string; color: string } {
  let score = 0
  if (p.length >= 8)           score++
  if (/[A-Z]/.test(p))         score++
  if (/[a-z]/.test(p))         score++
  if (/[0-9]/.test(p))         score++
  if (/[^A-Za-z0-9]/.test(p)) score++

  if (score <= 1) return { score, label: "Weak",   color: "#8B2E2E" }
  if (score <= 2) return { score, label: "Fair",   color: "#C9742F" }
  if (score <= 3) return { score, label: "Good",   color: "#a07c2f" }
  if (score <= 4) return { score, label: "Strong", color: "#3D5A4C" }
  return             { score, label: "Excellent", color: "#2a3f35" }
}

export function PasswordStrength({ password }: PasswordStrengthProps) {
  if (!password) return null
  const { score, label, color } = getStrength(password)

  return (
    <div className="mt-2 space-y-1">
      <div className="flex gap-1">
        {Array.from({ length: 5 }).map((_, i) => (
          <div
            key={i}
            className="h-1 flex-1 rounded-full transition-all duration-300"
            style={{ backgroundColor: i < score ? color : "hsl(var(--border))" }}
          />
        ))}
      </div>
      <p className="text-xs" style={{ color }}>{label}</p>
    </div>
  )
}
