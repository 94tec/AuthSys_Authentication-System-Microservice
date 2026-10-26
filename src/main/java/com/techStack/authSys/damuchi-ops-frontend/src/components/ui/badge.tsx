import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
    "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium transition-colors",
    {
        variants: {
            variant: {
                default: "border-transparent bg-primary text-primary-foreground",
                secondary: "border-transparent bg-secondary text-secondary-foreground",
                success: "border-transparent bg-success/15 text-success",
                warning: "border-transparent bg-warning/15 text-warning",
                destructive: "border-transparent bg-destructive/15 text-destructive",
                outline: "border-border text-foreground",

                neutral: "border-border bg-muted text-muted-foreground",
                savanna: "border-savanna/20 bg-savanna/10 text-savanna",
                amber: "border-amber-200 bg-amber-100 text-amber-800",
                red: "border-red-200 bg-red-100 text-red-700",
                blue: "border-blue-200 bg-blue-100 text-blue-700",
            },
        },
        defaultVariants: {
            variant: "default",
        },
    }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge, badgeVariants };
