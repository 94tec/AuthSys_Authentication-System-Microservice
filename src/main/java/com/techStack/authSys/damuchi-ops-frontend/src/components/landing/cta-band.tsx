import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";

export function CtaBand() {
  return (
      <section className="container pb-16 sm:pb-20" aria-labelledby="cta-heading">
        <div className="relative overflow-hidden rounded-2xl bg-expedition-forest px-8 py-14 text-center sm:px-16 sm:py-20">
          {/* Dot-grid texture */}
          <div
              className="pointer-events-none absolute inset-0 opacity-[0.06]"
              style={{
                backgroundImage:
                    "radial-gradient(circle at 70% 30%, white 0.5px, transparent 0.5px)",
                backgroundSize: "22px 22px",
              }}
              aria-hidden="true"
          />
          <h2
              id="cta-heading"
              className="relative font-display text-3xl font-medium tracking-tight text-balance text-expedition-sand sm:text-4xl"
          >
            Your next trip is one account away.
          </h2>
          <p className="relative mx-auto mt-3 max-w-md text-sm text-expedition-sand/70 sm:text-base">
            Create your free account to save favourites, track every enquiry,
            and hear back from local guides faster.
          </p>
          <div className="relative mt-7 flex flex-col items-center gap-3 sm:flex-row sm:justify-center">
            <Button asChild variant="accent" size="lg">
              <Link href="/register">
                Create your account
                <ArrowRight className="h-4 w-4" aria-hidden="true" />
              </Link>
            </Button>
            <Button
                asChild
                variant="ghost"
                size="lg"
                className="text-expedition-sand/80 hover:bg-expedition-sand/10 hover:text-expedition-sand"
            >
              <Link href="/login">Sign in</Link>
            </Button>
          </div>
        </div>
      </section>
  );
}