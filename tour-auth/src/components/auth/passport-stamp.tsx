import { cn } from "@/lib/utils"
import { CheckCircle2 } from "lucide-react"

interface PassportStampProps {
  title: string
  subtitle?: string
  className?: string
}

export function PassportStamp({ title, subtitle, className }: PassportStampProps) {
  return (
    <div className={cn("flex flex-col items-center gap-4 animate-fade-up", className)}>
      {/* Outer dashed ring */}
      <div className="stamp-ring w-28 h-28 animate-stamp-in">
        {/* Inner solid ring */}
        <div className="w-24 h-24 rounded-full border-2 border-[#C9742F] bg-[#C9742F]/10 flex items-center justify-center">
          <CheckCircle2 className="w-10 h-10 text-[#C9742F]" strokeWidth={1.5} />
        </div>
      </div>
      <div className="text-center">
        <p className="font-display text-xl font-semibold text-foreground">{title}</p>
        {subtitle && <p className="text-sm text-muted-foreground mt-1">{subtitle}</p>}
      </div>
    </div>
  )
}
