"use client";

import { Button } from "@/components/ui/button";
import { EnquiryModal } from "@/components/landing/enquiry/enquiry-modal";

const AUTH_FRONTEND_URL =
    process.env.NEXT_PUBLIC_AUTH_FRONTEND_URL ?? "http://localhost:3000";

export function AuthActions() {
    return (
        <div className="flex items-center gap-2">
            {/* Enquiry */}
            <EnquiryModal source="navbar-desktop" />

            {/* Sign in — authsys-frontend owns /login, this app has no
                local login page. Links straight there rather than through
                /login-redirect, since there's no protected-route "intended
                path" to preserve for a plain nav-bar click. */}
            <a href={`${AUTH_FRONTEND_URL}/login`}>
                <Button
                    variant="ghost"
                    size="sm"
                    className="
                        rounded-full
                        px-3.5
                        text-sm
                        font-medium
                        text-muted-foreground
                        hover:bg-muted
                        hover:text-foreground
                    "
                >
                    Sign In
                </Button>
            </a>
        </div>
    );
}