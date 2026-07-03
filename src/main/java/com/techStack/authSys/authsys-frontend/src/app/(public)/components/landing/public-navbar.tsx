"use client";

import Link from "next/link";
import { useState } from "react";
import { Compass, Menu, X } from "lucide-react";
import { Button } from "@/components/ui/button";

const NAV_LINKS = [
  { href: "#tours", label: "Tours" },
  { href: "#destinations", label: "Destinations" },
  { href: "#how-it-works", label: "How it works" },
];

export function PublicNavbar() {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50 border-b border-border/60 bg-background/90 backdrop-blur-md">
      <div className="container flex h-16 items-center justify-between">
        <Link href="/" className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-expedition-forest">
            <Compass className="h-4 w-4 text-expedition-clay" strokeWidth={1.75} />
          </div>
          <span className="font-display text-base font-medium tracking-tight">
            Basecamp
          </span>
        </Link>

        <nav className="hidden items-center gap-8 md:flex">
          {NAV_LINKS.map((link) => (
            <a
              key={link.href}
              href={link.href}
              className="text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
            >
              {link.label}
            </a>
          ))}
        </nav>

        <div className="hidden items-center gap-3 md:flex">
          <Button asChild variant="ghost" size="sm">
            <Link href="/login">Sign in</Link>
          </Button>
          <Button asChild variant="accent" size="sm">
            <Link href="/register">Get started</Link>
          </Button>
        </div>

        <button
          className="flex h-9 w-9 items-center justify-center rounded-md text-foreground md:hidden"
          onClick={() => setMobileOpen((v) => !v)}
          aria-label="Toggle menu"
        >
          {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </div>

      {mobileOpen && (
        <div className="border-t border-border bg-background px-4 py-4 md:hidden">
          <nav className="flex flex-col gap-1">
            {NAV_LINKS.map((link) => (
              <a
                key={link.href}
                href={link.href}
                onClick={() => setMobileOpen(false)}
                className="rounded-md px-3 py-2.5 text-sm font-medium text-foreground hover:bg-muted"
              >
                {link.label}
              </a>
            ))}
          </nav>
          <div className="mt-3 flex flex-col gap-2 border-t border-border pt-3">
            <Button asChild variant="outline" className="w-full">
              <Link href="/login">Sign in</Link>
            </Button>
            <Button asChild variant="accent" className="w-full">
              <Link href="/register">Get started</Link>
            </Button>
          </div>
        </div>
      )}
    </header>
  );
}
