import { cn } from "@/lib/utils"
import { Check } from "lucide-react"

interface Step {
  label: string
  description?: string
}

interface TrailStepsProps {
  steps: Step[]
  current: number // 0-indexed
  className?: string
}

export function TrailSteps({ steps, current, className }: TrailStepsProps) {
  return (
    <div className={cn("flex items-start gap-0", className)}>
      {steps.map((step, i) => {
        const done   = i < current
        const active = i === current
        const last   = i === steps.length - 1

        return (
          <div key={i} className="flex flex-col items-center flex-1">
            {/* Connector row */}
            <div className="flex items-center w-full">
              {/* Left connector */}
              <div className={cn("flex-1 h-px", i === 0 ? "invisible" : done || active ? "bg-[#C9742F]" : "bg-border")} />

              {/* Waypoint circle */}
              <div
                className={cn(
                  "w-8 h-8 rounded-full border-2 flex items-center justify-center text-xs font-mono font-bold shrink-0 transition-all duration-300",
                  done   && "bg-[#C9742F] border-[#C9742F] text-sand-50",
                  active && "bg-card border-[#C9742F] text-[#C9742F] ring-4 ring-[#C9742F]/20",
                  !done && !active && "bg-card border-border text-muted-foreground"
                )}
              >
                {done ? <Check className="w-3.5 h-3.5 text-white" /> : i + 1}
              </div>

              {/* Right connector */}
              <div className={cn("flex-1 h-px", last ? "invisible" : done ? "bg-[#C9742F]" : "bg-border")} />
            </div>

            {/* Label */}
            <div className="mt-2 text-center px-1">
              <p className={cn("text-xs font-semibold", active ? "text-[#C9742F]" : done ? "text-foreground" : "text-muted-foreground")}>
                {step.label}
              </p>
              {step.description && (
                <p className="text-[10px] text-muted-foreground mt-0.5 hidden sm:block">{step.description}</p>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}
