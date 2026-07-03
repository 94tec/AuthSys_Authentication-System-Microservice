import { Search, UserPlus, CreditCard, Backpack } from "lucide-react";

const STEPS = [
  {
    icon: Search,
    title: "Browse the catalogue",
    description: "Filter by category, duration, or destination — see real prices upfront, no quotes needed.",
  },
  {
    icon: UserPlus,
    title: "Create your account",
    description: "Takes under a minute. We'll verify your phone so your booking confirmations actually reach you.",
  },
  {
    icon: CreditCard,
    title: "Book and pay securely",
    description: "Lock in your dates with a deposit or pay in full — your invoice and itinerary land in your inbox instantly.",
  },
  {
    icon: Backpack,
    title: "Show up and go",
    description: "Your guide already has your details. Just bring yourself — and maybe sunscreen.",
  },
];

export function HowItWorks() {
  return (
    <section id="how-it-works" className="border-y border-border bg-card/40 py-16 sm:py-20">
      <div className="container">
        <div className="mx-auto max-w-2xl text-center">
          <p className="font-mono text-xs uppercase tracking-[0.15em] text-accent">
            How it works
          </p>
          <h2 className="mt-2 font-display text-3xl font-medium tracking-tight sm:text-4xl">
            Four steps between you and the trailhead.
          </h2>
        </div>

        <div className="mt-12 grid grid-cols-1 gap-8 sm:grid-cols-2 lg:grid-cols-4">
          {STEPS.map((step, idx) => {
            const Icon = step.icon;
            return (
              <div key={step.title} className="relative">
                {idx < STEPS.length - 1 && (
                  <div
                    className="absolute left-6 top-12 hidden h-px w-full bg-border lg:block"
                    aria-hidden="true"
                  />
                )}
                <div className="relative flex h-12 w-12 items-center justify-center rounded-full border-2 border-accent/30 bg-background">
                  <Icon className="h-5 w-5 text-accent" strokeWidth={1.75} />
                </div>
                <p className="mt-4 font-mono text-xs text-muted-foreground">
                  Step {idx + 1}
                </p>
                <h3 className="mt-1 font-display text-lg font-medium tracking-tight">
                  {step.title}
                </h3>
                <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">
                  {step.description}
                </p>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
