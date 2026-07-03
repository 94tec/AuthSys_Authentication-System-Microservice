import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";

export function CtaBand() {
  return (
    <section className="container pb-16 sm:pb-20">
      <div className="relative overflow-hidden rounded-2xl bg-expedition-forest px-8 py-14 text-center sm:px-16 sm:py-20">
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.06]"
          style={{
            backgroundImage:
              "radial-gradient(circle at 70% 30%, white 0.5px, transparent 0.5px)",
            backgroundSize: "22px 22px",
          }}
          aria-hidden="true"
        />
        <h2 className="relative font-display text-3xl font-medium tracking-tight text-expedition-sand text-balance sm:text-4xl">
          Your next trip is one account away.
        </h2>
        <p className="relative mx-auto mt-3 max-w-md text-sm text-expedition-sand/70 sm:text-base">
          Create your free account to book, save favorites, and track every trip in one place.
        </p>
        <Button asChild variant="accent" size="lg" className="relative mt-7">
          <Link href="/register">
            Create your account
            <ArrowRight className="h-4 w-4" />
          </Link>
        </Button>
      </div>
    </section>
  );
}
