"use client";

import Link from "next/link";
import {
  ArrowUpRight,
  Check,
  Compass,
  Facebook,
  Heart,
  Instagram,
  Mail,
  MapPin,
  MessageCircle, MessageSquareText,
  Phone,
  Sparkles,
  Youtube,
} from "lucide-react";
import {EnquiryModal} from "@/components/landing/enquiry/enquiry-modal";

const EXPLORE_LINKS = [
  { href: "/safaris", label: "Safaris" },
  { href: "/destinations", label: "Destinations" },
  { href: "/hotels", label: "Hotels" },
  { href: "/experiences", label: "Experiences" },
];

const PLAN_LINKS = [
  { href: "/plan-your-trip", label: "Plan Your Trip" },
  { href: "/travel-guide", label: "Travel Guide" },
  { href: "/best-time-to-visit", label: "Best Time to Visit" },
  { href: "/faq", label: "FAQs" },
];

const COMPANY_LINKS = [
  { href: "/about", label: "Our Story" },
  { href: "/about/team", label: "Meet the Team" },
  { href: "/testimonials", label: "Guest Reviews" },
  { href: "/sustainability", label: "Sustainability" },
  { href: "/contact", label: "Contact Us" },
];

const SOCIAL_LINKS = [
  {
    href: "https://instagram.com",
    icon: Instagram,
    label: "Instagram",
  },
  {
    href: "https://facebook.com",
    icon: Facebook,
    label: "Facebook",
  },
  {
    href: "https://youtube.com",
    icon: Youtube,
    label: "YouTube",
  },
];

const JOURNEY_STEPS = [
  "Send your enquiry",
  "Receive your quote",
  "Accept when ready",
  "Complete your booking",
];

export function Footer() {
  return (
    <footer className="relative overflow-hidden bg-gray-950 text-white/70">
      {/* ═══════════════════════════════════════════════
          AMBIENT BACKGROUND
      ═══════════════════════════════════════════════ */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0"
      >
        <div className="absolute -left-32 top-0 h-96 w-96 rounded-full bg-coral/10 blur-3xl" />

        <div className="absolute right-[-10rem] top-1/3 h-[32rem] w-[32rem] rounded-full bg-emerald-500/5 blur-3xl" />

        <div
          className="absolute inset-0 opacity-[0.025]"
          style={{
            backgroundImage:
              "linear-gradient(to right, currentColor 1px, transparent 1px), linear-gradient(to bottom, currentColor 1px, transparent 1px)",
            backgroundSize: "48px 48px",
          }}
        />
      </div>

      <div className="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        {/* ═══════════════════════════════════════════════
            CTA / JOURNEY BANNER
        ═══════════════════════════════════════════════ */}
        <div className="border-b border-white/10 py-12 sm:py-14 lg:py-16">
          <div className="relative overflow-hidden rounded-3xl border border-white/10 bg-white/[0.04] p-6 backdrop-blur-sm sm:p-8 lg:p-10">
            {/* Glow */}
            <div
              aria-hidden="true"
              className="absolute -right-24 -top-24 h-64 w-64 rounded-full bg-coral/10 blur-3xl"
            />

            <div className="relative flex flex-col gap-8 lg:flex-row lg:items-center lg:justify-between">
              <div className="max-w-2xl">
                <div className="inline-flex items-center gap-2 rounded-full border border-orange/20 bg-orange/10 px-4 py-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-orange-300">
                  <MessageSquareText className="h-3.5 w-3.5" />
                  Your journey starts here
                </div>

                <h2 className="mt-4 font-display text-2xl font-medium tracking-tight text-white sm:text-3xl lg:text-4xl">
                  Have a trip in mind?
                  <span className="text-coral">
                    {" "}
                    Tell us about it.
                  </span>
                </h2>

                <p className="mt-3 max-w-xl text-sm leading-6 text-white/55 sm:text-base">
                  Share your dates, destinations, group size, interests,
                  and preferences. We&apos;ll turn your ideas into a
                  tailored quote — automatically where possible, or with
                  help from our team.
                </p>
              </div>

              <div className="shrink-0">
                <EnquiryModal source="navbar-desktop" />
              </div>
            </div>

            {/* Journey mini-flow */}
            <div className="relative mt-8 grid gap-3 border-t border-white/10 pt-6 sm:grid-cols-2 lg:grid-cols-4">
              {JOURNEY_STEPS.map((step, index) => (
                <div
                  key={step}
                  className="flex items-center gap-2.5"
                >
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-white/5 font-mono text-[9px] text-coral ring-1 ring-inset ring-white/10">
                    {String(index + 1).padStart(2, "0")}
                  </span>

                  <span className="text-xs text-white/50">
                    {step}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ═══════════════════════════════════════════════
            MAIN FOOTER
        ═══════════════════════════════════════════════ */}
        <div className="grid gap-12 py-14 sm:grid-cols-2 lg:grid-cols-[1.5fr_1fr_1fr_1fr] lg:py-16">
          {/* ─────────────────────────────────────────
              BRAND
          ───────────────────────────────────────── */}
          <div>
            <Link
              href="/"
              className="group inline-flex items-center font-display text-xl font-semibold tracking-tight text-white"
            >
              Damuchi
              <span className="ml-1 text-coral transition-colors group-hover:text-white">
                Safaris
              </span>
            </Link>

            <p className="mt-5 max-w-sm text-sm leading-7 text-white/50">
              Curated journeys across Kenya, Tanzania, Uganda,
              and Rwanda — with local expertise, flexible planning,
              and a human team behind every enquiry.
            </p>

            {/* Trust points */}
            <div className="mt-6 space-y-2.5">
              <div className="flex items-center gap-2 text-xs text-white/45">
                <Check
                  className="h-3.5 w-3.5 text-coral"
                  aria-hidden="true"
                />
                Personalised travel planning
              </div>

              <div className="flex items-center gap-2 text-xs text-white/45">
                <Check
                  className="h-3.5 w-3.5 text-coral"
                  aria-hidden="true"
                />
                Tailored quotes for your requirements
              </div>

              <div className="flex items-center gap-2 text-xs text-white/45">
                <Check
                  className="h-3.5 w-3.5 text-coral"
                  aria-hidden="true"
                />
                Local East African expertise
              </div>
            </div>

            {/* Socials */}
            <div className="mt-7 flex items-center gap-2.5">
              {SOCIAL_LINKS.map(
                ({ href, icon: Icon, label }) => (
                  <a
                    key={label}
                    href={href}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label={label}
                    className="flex h-9 w-9 items-center justify-center rounded-full border border-white/10 bg-white/[0.04] text-white/55 transition-all duration-300 hover:-translate-y-0.5 hover:border-coral/40 hover:bg-coral hover:text-gray-950"
                  >
                    <Icon
                      className="h-3.5 w-3.5"
                      aria-hidden="true"
                    />
                  </a>
                ),
              )}
            </div>
          </div>

          {/* ─────────────────────────────────────────
              EXPLORE
          ───────────────────────────────────────── */}
          <div>
            <h3 className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-white">
              Explore
            </h3>

            <ul className="mt-5 space-y-3">
              {EXPLORE_LINKS.map((link) => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="group inline-flex items-center gap-1 text-sm text-white/50 transition-colors duration-200 hover:text-coral"
                  >
                    {link.label}

                    <ArrowUpRight
                      className="h-3 w-3 opacity-0 transition-all duration-200 group-hover:-translate-y-0.5 group-hover:translate-x-0.5 group-hover:opacity-100"
                      aria-hidden="true"
                    />
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* ─────────────────────────────────────────
              PLAN
          ───────────────────────────────────────── */}
          <div>
            <h3 className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-white">
              Plan your trip
            </h3>

            <ul className="mt-5 space-y-3">
              {PLAN_LINKS.map((link) => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="group inline-flex items-center gap-1 text-sm text-white/50 transition-colors duration-200 hover:text-coral"
                  >
                    {link.label}

                    <ArrowUpRight
                      className="h-3 w-3 opacity-0 transition-all duration-200 group-hover:-translate-y-0.5 group-hover:translate-x-0.5 group-hover:opacity-100"
                      aria-hidden="true"
                    />
                  </Link>
                </li>
              ))}
            </ul>

            <Link
              href="/enquiry"
              className="mt-6 inline-flex items-center gap-2 text-xs font-semibold text-coral transition-colors hover:text-white"
            >
              <Compass
                className="h-3.5 w-3.5"
                aria-hidden="true"
              />
              Custom trip enquiry
            </Link>
          </div>

          {/* ─────────────────────────────────────────
              COMPANY + CONTACT
          ───────────────────────────────────────── */}
          <div>
            <h3 className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-white">
              Company
            </h3>

            <ul className="mt-5 space-y-3">
              {COMPANY_LINKS.map((link) => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="group inline-flex items-center gap-1 text-sm text-white/50 transition-colors duration-200 hover:text-coral"
                  >
                    {link.label}

                    <ArrowUpRight
                      className="h-3 w-3 opacity-0 transition-all duration-200 group-hover:-translate-y-0.5 group-hover:translate-x-0.5 group-hover:opacity-100"
                      aria-hidden="true"
                    />
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* ═══════════════════════════════════════════════
            CONTACT STRIP
        ═══════════════════════════════════════════════ */}
        <div className="border-t border-white/10 py-8">
          <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
            {/* Email */}
            <a
              href="mailto:hello@damuchisafaris.co.ke"
              className="group flex items-center gap-3 rounded-xl border border-white/5 bg-white/[0.025] p-3.5 transition-all duration-300 hover:border-coral/20 hover:bg-white/[0.05]"
            >
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-coral/10 text-coral">
                <Mail
                  className="h-4 w-4"
                  aria-hidden="true"
                />
              </span>

              <div className="min-w-0">
                <p className="text-[9px] font-semibold uppercase tracking-[0.15em] text-white/30">
                  Email
                </p>

                <p className="mt-0.5 truncate text-sm text-white/60 transition-colors group-hover:text-white">
                  hello@damuchisafaris.co.ke
                </p>
              </div>
            </a>

            {/* Phone */}
            <a
              href="tel:+254700000000"
              className="group flex items-center gap-3 rounded-xl border border-white/5 bg-white/[0.025] p-3.5 transition-all duration-300 hover:border-coral/20 hover:bg-white/[0.05]"
            >
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-coral/10 text-coral">
                <Phone
                  className="h-4 w-4"
                  aria-hidden="true"
                />
              </span>

              <div>
                <p className="text-[9px] font-semibold uppercase tracking-[0.15em] text-white/30">
                  Call us
                </p>

                <p className="mt-0.5 text-sm text-white/60 transition-colors group-hover:text-white">
                  +254 700 000 000
                </p>
              </div>
            </a>

            {/* WhatsApp */}
            <Link
              href="/whatsapp"
              className="group flex items-center gap-3 rounded-xl border border-white/5 bg-white/[0.025] p-3.5 transition-all duration-300 hover:border-emerald-400/20 hover:bg-white/[0.05]"
            >
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-emerald-400/10 text-emerald-400">
                <MessageCircle
                  className="h-4 w-4"
                  aria-hidden="true"
                />
              </span>

              <div className="min-w-0">
                <p className="text-[9px] font-semibold uppercase tracking-[0.15em] text-white/30">
                  Preferred by many travellers
                </p>

                <p className="mt-0.5 text-sm text-white/60 transition-colors group-hover:text-white">
                  Chat with us on WhatsApp
                </p>
              </div>
            </Link>
          </div>
        </div>

        {/* ═══════════════════════════════════════════════
            BOTTOM BAR
        ═══════════════════════════════════════════════ */}
        <div className="flex flex-col gap-5 border-t border-white/10 py-6 text-xs md:flex-row md:items-center md:justify-between">
          <p className="text-white/30">
            © {new Date().getFullYear()} Damuchi Safaris.
            All rights reserved.
          </p>

          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-white/30">
            <Link
              href="/privacy"
              className="transition-colors hover:text-white/60"
            >
              Privacy
            </Link>

            <span aria-hidden="true">•</span>

            <Link
              href="/terms"
              className="transition-colors hover:text-white/60"
            >
              Terms
            </Link>

            <span aria-hidden="true">•</span>

            <Link
              href="/contact"
              className="transition-colors hover:text-white/60"
            >
              Support
            </Link>
          </div>

          <div className="flex items-center gap-2 text-white/30">
            <MapPin
              className="h-3.5 w-3.5 text-coral"
              aria-hidden="true"
            />

            <span>Based in Mombasa · Serving East Africa</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
