import type { ReactNode } from "react";

interface PageHeaderProps {
  eyebrow: string;
  title: string;
  subtitle?: string;
  action?: ReactNode;
}

export function PageHeader({ eyebrow, title, subtitle, action }: PageHeaderProps) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div>
        <p className="font-mono text-xs uppercase tracking-[0.15em] text-accent">{eyebrow}</p>
        <h1 className="mt-1 font-display text-3xl font-medium tracking-tight">{title}</h1>
        {subtitle && (
          <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>
        )}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}
