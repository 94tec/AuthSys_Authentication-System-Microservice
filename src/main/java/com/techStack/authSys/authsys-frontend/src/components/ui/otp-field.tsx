"use client";

import * as React from "react";
import { OTPInput, type SlotProps } from "input-otp";
import { cn } from "@/lib/utils";

interface OtpFieldProps {
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  hasError?: boolean;
  length?: number;
}

function Slot(props: SlotProps & { hasError?: boolean }) {
  return (
    <div
      className={cn(
        "relative flex h-14 w-12 items-center justify-center rounded-lg border-2 bg-card font-mono text-xl font-semibold text-foreground transition-all duration-150 sm:h-16 sm:w-14",
        props.isActive
          ? "border-accent ring-2 ring-accent/30"
          : "border-border",
        props.hasError && "border-destructive",
        props.char && "border-secondary/60"
      )}
    >
      {props.char !== null && <div>{props.char}</div>}
      {props.hasFakeCaret && (
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
          <div className="h-6 w-px animate-pulse bg-accent" />
        </div>
      )}
    </div>
  );
}

export function OtpField({
  value,
  onChange,
  disabled,
  hasError,
  length = 6,
}: OtpFieldProps) {
  return (
    <OTPInput
      value={value}
      onChange={onChange}
      maxLength={length}
      disabled={disabled}
      inputMode="numeric"
      containerClassName="flex items-center gap-2 sm:gap-3 justify-between"
      render={({ slots }) => (
        <>
          {slots.map((slot, idx) => (
            <Slot key={idx} {...slot} hasError={hasError} />
          ))}
        </>
      )}
    />
  );
}
