import { cn } from "@/lib/utils"
import { Mountain } from "lucide-react"
import Link from "next/link"

interface AuthLayoutProps {
  children: React.ReactNode
  className?: string
  /** Optional heading shown above the card */
  heading?: string
  /** Optional subheading */
  subheading?: string
  /** Show the back-to-login link */
  showBackToLogin?: boolean
}

export function AuthLayout({ children, className, heading, subheading, showBackToLogin }: AuthLayoutProps) {
  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Topbar brand */}
      <header className="flex items-center gap-2.5 px-6 py-4 border-b border-border/50">
        <div className="w-8 h-8 rounded-lg bg-[#C9742F] flex items-center justify-center">
          <Mountain className="w-4 h-4 text-white" strokeWidth={2} />
        </div>
        <span className="font-display text-base font-semibold text-foreground tracking-tight">
          Venture Tours
        </span>
      </header>

      {/* Center content */}
      <main className={cn("flex-1 flex items-center justify-center px-4 py-12", className)}>
        <div className="w-full max-w-md space-y-6">
          {(heading || subheading) && (
            <div className="text-center space-y-1">
              {heading && (
                <h1 className="font-display text-3xl font-semibold text-foreground">{heading}</h1>
              )}
              {subheading && (
                <p className="text-muted-foreground text-sm">{subheading}</p>
              )}
            </div>
          )}

          {children}

          {showBackToLogin && (
            <p className="text-center text-sm text-muted-foreground">
              <Link href="/login" className="text-[#C9742F] hover:underline font-medium">
                ← Back to login
              </Link>
            </p>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="py-4 text-center text-xs text-muted-foreground border-t border-border/50">
        © {new Date().getFullYear()} Venture Tours · Staff Portal
      </footer>
    </div>
  )
}
