import { Check } from "lucide-react";
import { cn } from "@/lib/utils";

export interface TrailStep {
  label: string;
  description: string;
}

interface TrailProgressProps {
  steps: TrailStep[];
  currentStep: number; // 0-indexed
}

export function TrailProgress({ steps, currentStep }: TrailProgressProps) {
  return (
    <div className="w-full">
      <ol className="flex items-start justify-between">
        {steps.map((step, idx) => {
          const isComplete = idx < currentStep;
          const isCurrent = idx === currentStep;

          return (
            <li
              key={step.label}
              className="relative flex flex-1 flex-col items-center text-center"
            >
              {idx > 0 && (
                <div
                  className={cn(
                    "absolute right-1/2 top-4 h-px w-full -translate-y-1/2",
                    idx <= currentStep ? "bg-accent" : "bg-border"
                  )}
                  style={{ left: "-50%" }}
                  aria-hidden="true"
                />
              )}

              <div
                className={cn(
                  "relative z-10 flex h-8 w-8 items-center justify-center rounded-full border-2 text-xs font-semibold transition-colors duration-300",
                  isComplete &&
                    "border-accent bg-accent text-accent-foreground",
                  isCurrent &&
                    "border-accent bg-background text-accent ring-4 ring-accent/20",
                  !isComplete &&
                    !isCurrent &&
                    "border-border bg-background text-muted-foreground"
                )}
                aria-current={isCurrent ? "step" : undefined}
              >
                {isComplete ? (
                  <Check className="h-4 w-4" strokeWidth={2.5} />
                ) : (
                  idx + 1
                )}
              </div>

              <span
                className={cn(
                  "mt-2 text-xs font-medium leading-tight sm:text-sm",
                  isCurrent ? "text-foreground" : "text-muted-foreground"
                )}
              >
                {step.label}
              </span>
              <span className="hidden text-[11px] text-muted-foreground sm:mt-0.5 sm:block">
                {step.description}
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
