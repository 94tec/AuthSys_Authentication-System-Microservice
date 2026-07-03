"use client";

import { Toaster as SonnerToaster } from "sonner";

export function Toaster() {
  return (
    <SonnerToaster
      position="top-center"
      toastOptions={{
        classNames: {
          toast:
            "bg-card border border-border text-card-foreground font-sans rounded-lg shadow-md",
          title: "text-sm font-medium",
          description: "text-sm text-muted-foreground",
          actionButton: "bg-accent text-accent-foreground",
          cancelButton: "bg-muted text-muted-foreground",
          error: "border-destructive/40",
          success: "border-success/40",
        },
      }}
    />
  );
}
