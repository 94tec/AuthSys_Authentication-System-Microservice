import Link from "next/link";
import { Compass } from "lucide-react";

export function PublicFooter() {
  return (
    <footer className="border-t border-border bg-card/40">
      <div className="container py-10">
        <div className="flex flex-col items-start justify-between gap-8 sm:flex-row">
          <div>
            <Link href="/" className="flex items-center gap-2.5">
              <div className="flex h-7 w-7 items-center justify-center rounded-md bg-expedition-forest">
                <Compass className="h-3.5 w-3.5 text-expedition-clay" strokeWidth={1.75} />
              </div>
              <span className="font-display text-sm font-medium tracking-tight">
                Basecamp
              </span>
            </Link>
            <p className="mt-3 max-w-xs text-sm text-muted-foreground">
              Curated tours, real guides, no surprises. Book your next trip in minutes.
            </p>
          </div>

          <div className="flex gap-12">
            <div>
              <p className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
                Explore
              </p>
              <div className="mt-3 flex flex-col gap-2">
                <a href="#tours" className="text-sm text-muted-foreground hover:text-foreground">
                  Tours
                </a>
                <a href="#destinations" className="text-sm text-muted-foreground hover:text-foreground">
                  Destinations
                </a>
              </div>
            </div>
            <div>
              <p className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
                Account
              </p>
              <div className="mt-3 flex flex-col gap-2">
                <Link href="/login" className="text-sm text-muted-foreground hover:text-foreground">
                  Sign in
                </Link>
                <Link href="/register" className="text-sm text-muted-foreground hover:text-foreground">
                  Create account
                </Link>
              </div>
            </div>
          </div>
        </div>

        <div className="mt-10 flex flex-col items-center justify-between gap-3 border-t border-border pt-6 text-xs text-muted-foreground sm:flex-row">
          <p>© {new Date().getFullYear()} Basecamp. All rights reserved.</p>
          <p className="font-mono">Built for travelers, by travelers.</p>
        </div>
      </div>
    </footer>
  );
}
