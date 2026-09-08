import { Navbar }        from "@/components/layout/navbar";
import { Footer }        from "@/components/layout/footer";
import { VisitorProvider }     from "@/components/landing/visitor-provider";
import { WelcomeBackBand }     from "@/components/landing/welcome-back-band";
import { Hero }                from "@/components/landing/hero/hero";
import { TrustStats }          from "@/components/landing/trust-stats";
import { TourGrid }            from "@/components/tours/tour-grid";
import { DestinationsStrip }   from "@/components/landing/destinations-strip";
import { HowItWorks }          from "@/components/landing/how-it-works";
import { Testimonials }        from "@/components/landing/testimonials";
import { EnquiryBand }         from "@/components/landing/enquiry/enquiry-band";
import { CtaBandGate }         from "@/components/landing/cta-band-gate";
import { FloatingEnquiryCta }  from "@/components/landing/floating-enquiry-cta";
import type { Metadata }       from "next";
import {TourShowcaseSection} from "@/components/tours/tour-showcase-section";

export const metadata: Metadata = {
    title:       "Damuchi Safaris | East Africa's tours, real local guides",
    description: "Safaris across Kenya, Tanzania, Uganda & Rwanda — beach escapes, mountain treks, gorilla encounters, and cultural tours. Send an enquiry and hear back from a real local guide within hours.",
    robots:      { index: true, follow: true },
    openGraph: {
        title:       "Damuchi Safaris | East Africa's tours, real local guides",
        description: "Savannahs, coastlines, volcanoes, and gorillas — enquire directly with local experts across East Africa.",
        type:        "website",
    },
};

/**
 * Public landing page — browsable without authentication.
 *
 * Authentication-aware: wrapped in VisitorProvider (client component),
 * which resolves visitor status ("loading" → "guest" | "customer" | "staff")
 * from the persisted auth store. Defaults to "guest" until hydration
 * completes — an unauthenticated visitor is never shown customer-only
 * content, and an authenticated customer sees the guest view for at most
 * one render before hydration resolves (never the reverse). See
 * hooks/use-visitor.ts for the hydration-safety details.
 *
 * Personalization touches exactly two sections:
 *   - WelcomeBackBand: renders only for status === "customer", replaces
 *     the generic guest CTA push with quick links (My Enquiries, Saved
 *     Tours, Browse more).
 *   - CtaBandGate: renders CtaBand only for guests — a logged-in customer
 *     shouldn't see a register/sign-in prompt.
 * Every other section (Hero, TrustStats, TourGrid, DestinationsStrip,
 * HowItWorks, Testimonials, EnquiryBand) renders identically regardless
 * of visitor status — no data filtering needed there, since enquire-button.tsx listings
 * and enquiry forms are the same for guests and customers alike.
 *
 * Enquiry-first, not booking: no payment or checkout entry points exist
 * on this page. TourCard links to the enquire-button.tsx detail page ("View →"), and
 * EnquiryBand collects a enquire-button.tsx-specific enquiry (tourId required by the
 * backend) rather than any booking/payment flow.
 *
 * Layout order:
 *   1. PublicNavbar
 *   2. WelcomeBackBand    — customers only
 *   3. Hero
 *   4. TrustStats
 *   5. TourGrid
 *   6. DestinationsStrip
 *   7. HowItWorks
 *   8. Testimonials
 *   9. EnquiryBand
 *  10. CtaBandGate        — guests only
 *  11. PublicFooter
 *
 * FloatingEnquiryCta renders fixed/mobile-only, outside the main flow.
 *
 * All data fetching is in TourGrid (client component, Next.js fetch + revalidate).
 * SSG/ISR is not used here because enquire-button.tsx availability changes frequently.
 */
export default function PublicLandingPage() {
    return (
        <VisitorProvider>
            <div className="flex min-h-screen flex-col bg-background">
                <Navbar />
                <WelcomeBackBand />
                <main className="flex-1">
                    <Hero />
                    <TourGrid />
                    <DestinationsStrip />
                    <HowItWorks />
                    <Testimonials />
                    <CtaBandGate />
                    <TrustStats />
                </main>
                <Footer />
                <FloatingEnquiryCta />
            </div>
        </VisitorProvider>
    );
}