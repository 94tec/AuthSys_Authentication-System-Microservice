import { cn } from "@/lib/utils";

interface PassportStampProps {
  label: string;
  className?: string;
}

export function PassportStamp({ label, className }: PassportStampProps) {
  return (
    <div
      className={cn(
        "relative inline-flex h-28 w-28 -rotate-3 animate-stamp-in items-center justify-center",
        className
      )}
      role="img"
      aria-label={`${label} verified`}
    >
      <svg
        viewBox="0 0 120 120"
        className="absolute inset-0 h-full w-full text-accent"
        fill="none"
      >
        <circle
          cx="60"
          cy="60"
          r="54"
          stroke="currentColor"
          strokeWidth="2.5"
          strokeDasharray="4 3"
        />
        <circle cx="60" cy="60" r="46" stroke="currentColor" strokeWidth="1.5" />
      </svg>
      <div className="flex flex-col items-center justify-center text-center text-accent">
        <span className="font-display text-[11px] font-semibold uppercase tracking-[0.18em]">
          {label}
        </span>
        <span className="mt-0.5 font-mono text-[9px] tracking-wider opacity-80">
          VERIFIED
        </span>
      </div>
    </div>
  );
}
