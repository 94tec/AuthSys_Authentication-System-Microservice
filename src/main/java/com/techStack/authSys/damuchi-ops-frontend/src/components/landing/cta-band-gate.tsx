"use client";

import { CtaBand } from "./cta-band";
import { useVisitorContext } from "./visitor-provider";

export function CtaBandGate() {
    const { status } = useVisitorContext();

    // Don't render the public CTA while visitor/auth state
    // is still being resolved. This prevents a flash of content.
    if (status === "loading") {
        return null;
    }

    // Authenticated customers and staff already have
    // their own authenticated navigation/actions.
    if (status === "customer" || status === "staff") {
        return null;
    }

    return <CtaBand />;
}
