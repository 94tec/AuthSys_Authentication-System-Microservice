import type { ReactNode } from "react";
import Link from "next/link";
import { Compass } from "lucide-react";

interface AuthLayoutProps {
  children: ReactNode;
  eyebrow: string;
  title: string;
  subtitle: string;
}

export function AuthLayout({
  children,
  eyebrow,
  title,
  subtitle,
}: AuthLayoutProps) {
  return (
    <div className="grid min-h-screen lg:grid-cols-2">
      {/* Left: brand panel */}
      <aside className="relative hidden flex-col justify-between overflow-hidden bg-expedition-forest p-10 text-expedition-sand lg:flex">
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.07]"
          style={{
            backgroundImage:
              "radial-gradient(circle at 20% 20%, white 0.5px, transparent 0.5px)",
            backgroundSize: "24px 24px",
          }}
          aria-hidden="true"
        />

        <Link href="/" className="relative z-10 flex items-center gap-2.5">
          <Compass className="h-6 w-6 text-expedition-clay" strokeWidth={1.75} />
          <span className="font-display text-lg font-medium tracking-tight">
            Basecamp Access
          </span>
        </Link>

        <div className="relative z-10 max-w-md">
          <p className="font-mono text-xs uppercase tracking-[0.2em] text-expedition-clay">
            {eyebrow}
          </p>
          <h1 className="mt-3 font-display text-4xl font-medium leading-[1.1] tracking-tight text-balance">
            {title}
          </h1>
          <p className="mt-4 text-sm leading-relaxed text-expedition-sand/70">
            {subtitle}
          </p>
        </div>

        <p className="relative z-10 font-mono text-[11px] text-expedition-sand/40">
          Internal staff access only. All sessions are logged.
        </p>
      </aside>

      {/* Right: form panel */}
      <main className="flex flex-1 items-center justify-center bg-background px-6 py-12 sm:px-10">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-2.5 lg:hidden">
            <Compass className="h-5 w-5 text-accent" strokeWidth={1.75} />
            <span className="font-display text-base font-medium tracking-tight">
              Basecamp Access
            </span>
          </div>
          {children}
        </div>
      </main>
    </div>
  );
}
