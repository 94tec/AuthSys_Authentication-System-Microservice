import { PublicNavbar } from "@/app/(public)/components/landing/public-navbar";
import { Hero } from "@/app/(public)/components/landing/hero";
import { TourGrid } from "@/app/(public)/components/landing/tour-grid";
import { DestinationsStrip } from "@/app/(public)/components/landing/destinations-strip";
import { HowItWorks } from "@/app/(public)/components/landing/how-it-works";
import { CtaBand } from "@/app/(public)/components/landing/cta-band";
import { PublicFooter } from "@/app/(public)/components/landing/public-footer";
import type { Metadata } from "next";

// Overrides the staff-portal default in the root layout — this page is
// public-facing and should be discoverable, unlike /dashboard and /admin.
export const metadata: Metadata = {
  title: "Basecamp | Curated tours, real guides",
  description:
    "Browse safaris, beach escapes, mountain treks, and cultural tours. Book directly with local guides — transparent pricing, no quotes needed.",
  robots: { index: true, follow: true },
};

// Root — public guest landing page. Browsing tours requires no auth.
// Authenticated users who land here can still browse; the dashboard
// link lives behind /login once they sign in.
export default function RootPage() {
  return (
    <div className="flex min-h-screen flex-col bg-background">
      <PublicNavbar />
      <main className="flex-1">
        <Hero />
        <TourGrid />
        <DestinationsStrip />
        <HowItWorks />
        <CtaBand />
      </main>
      <PublicFooter />
    </div>
  );
}
