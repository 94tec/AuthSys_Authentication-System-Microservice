"use client";

import { ShieldCheck, Star, Zap } from "lucide-react";

export function TrustBar() {
    return (
        <div className="hidden border-b border-white/5 bg-foreground py-2 text-center text-xs text-background/80 lg:block">
            <div className="mx-auto flex max-w-7xl items-center justify-center gap-8">
                <span className="flex items-center gap-2">
                    <ShieldCheck className="h-3.5 w-3.5" />
                    Licensed Operators
                </span>

                <span className="flex items-center gap-2">
                    <Star className="h-3.5 w-3.5" />
                    4.9 Guest Rating
                </span>

                <span className="flex items-center gap-2">
                    <Zap className="h-3.5 w-3.5" />
                    Replies Within 2 Hours
                </span>
            </div>
        </div>
    );
}