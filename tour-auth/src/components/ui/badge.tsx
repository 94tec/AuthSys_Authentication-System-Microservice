import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold transition-colors",
  {
    variants: {
      variant: {
        default:     "bg-primary text-primary-foreground",
        secondary:   "bg-secondary text-secondary-foreground",
        clay:        "bg-[#C9742F]/15 text-[#C9742F] border border-[#C9742F]/30",
        moss:        "bg-[#3D5A4C]/15 text-[#3D5A4C] border border-[#3D5A4C]/30",
        rust:        "bg-[#8B2E2E]/15 text-[#8B2E2E] border border-[#8B2E2E]/30",
        pending:     "bg-amber-100 text-amber-800 border border-amber-200",
        active:      "bg-emerald-100 text-emerald-800 border border-emerald-200",
        locked:      "bg-slate-100 text-slate-600 border border-slate-200",
        outline:     "border border-border text-foreground",
      },
    },
    defaultVariants: { variant: "default" },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />
}

export { Badge, badgeVariants }
