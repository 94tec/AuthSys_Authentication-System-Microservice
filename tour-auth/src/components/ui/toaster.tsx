"use client"
import { Toaster as Sonner } from "sonner"

export function Toaster() {
  return (
    <Sonner
      position="top-right"
      toastOptions={{
        classNames: {
          toast:       "bg-card border border-border text-foreground shadow-lg rounded-lg",
          title:       "font-semibold text-sm",
          description: "text-xs text-muted-foreground",
          success:     "border-l-4 border-l-[#3D5A4C]",
          error:       "border-l-4 border-l-[#8B2E2E]",
          warning:     "border-l-4 border-l-[#C9742F]",
        },
      }}
    />
  )
}
