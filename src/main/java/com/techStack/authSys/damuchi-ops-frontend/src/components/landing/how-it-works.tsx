"use client";

import {
  Check,
  ClipboardList,
  MessageCircle,
  Send,
  Sparkles,
} from "lucide-react";
import {
  motion,
  useReducedMotion,
} from "framer-motion";

const STEPS = [
  {
    number: "01",
    icon: Sparkles,
    title: "Create your journey",
    description:
      "Browse our destinations and tours, or tell us exactly what you have in mind. Choose a ready-made experience or start a personalised tour enquiry.",
    marker: "Explore & enquire",
  },
  {
    number: "02",
    icon: Send,
    title: "Send your enquiry",
    description:
      "Share your dates, group size, destination, activities, preferences, budget, and anything else that matters to your trip. Your enquiry gives our team the full picture.",
    marker: "Tell us what you need",
  },
  {
    number: "03",
    icon: ClipboardList,
    title: "Receive your quote",
    description:
      "We turn your enquiry into a tailored trip quote. Depending on the tour, your quote may be generated automatically or prepared by our staff or admin team.",
    marker: "Quote prepared",
  },
  {
    number: "04",
    icon: MessageCircle,
    title: "Approve & complete",
    description:
      "Review the quote and accept it when you're ready. We'll then guide you through completing your booking using your preferred channel — email, WhatsApp, or another agreed option.",
    marker: "Your adventure begins",
  },
];

export function HowItWorks() {
  const shouldReduceMotion = useReducedMotion();

  return (
    <section
      id="how-it-works"
      aria-labelledby="how-it-works-heading"
      className="relative overflow-hidden border-y border-border bg-card/40 py-16 sm:py-20 lg:py-24"
    >
      {/* ═══════════════════════════════════════════
          AMBIENT BACKGROUND
      ═══════════════════════════════════════════ */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0"
      >
        <motion.div
          animate={
            shouldReduceMotion
              ? undefined
              : {
                  x: [0, 30, 0],
                  y: [0, -15, 0],
                }
          }
          transition={{
            duration: 14,
            repeat: Infinity,
            ease: "easeInOut",
          }}
          className="absolute left-1/2 top-0 h-80 w-[min(900px,100%)] -translate-x-1/2 rounded-full bg-accent/5 blur-3xl"
        />

        <motion.div
          animate={
            shouldReduceMotion
              ? undefined
              : {
                  x: [0, -25, 0],
                  y: [0, 20, 0],
                }
          }
          transition={{
            duration: 17,
            repeat: Infinity,
            ease: "easeInOut",
          }}
          className="absolute bottom-0 left-0 h-72 w-72 rounded-full bg-expedition-clay/5 blur-3xl"
        />

        <div
          className="absolute inset-0 opacity-[0.025]"
          style={{
            backgroundImage:
              "linear-gradient(to right, currentColor 1px, transparent 1px), linear-gradient(to bottom, currentColor 1px, transparent 1px)",
            backgroundSize: "48px 48px",
          }}
        />
      </div>

      <div className="container relative">
        {/* ═══════════════════════════════════════════
            HEADER
        ═══════════════════════════════════════════ */}
        <motion.div
          initial={
            shouldReduceMotion
              ? false
              : {
                  opacity: 0,
                  y: 20,
                }
          }
          whileInView={
            shouldReduceMotion
              ? undefined
              : {
                  opacity: 1,
                  y: 0,
                }
          }
          viewport={{
            once: true,
            amount: 0.25,
          }}
          transition={{
            duration: 0.55,
            ease: "easeOut",
          }}
          className="mx-auto max-w-2xl text-center"
        >
          <div className="inline-flex items-center gap-2 rounded-full border border-accent/20 bg-accent/5 px-3 py-1.5">
            <span
              className="h-1.5 w-1.5 rounded-full bg-accent"
              aria-hidden="true"
            />

            <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-accent">
              How it works
            </span>
          </div>

          <h2
            id="how-it-works-heading"
            className="mt-4 font-display text-3xl font-medium tracking-tight text-foreground sm:text-4xl lg:text-5xl"
          >
            Your trip starts with
            <span className="text-accent">
              {" "}
              a conversation.
            </span>
          </h2>

          <p className="mt-4 text-sm leading-7 text-muted-foreground sm:text-base">
            Tell us where you want to go, what you want to
            experience, and how you want to travel. We take it
            from there — from enquiry to quote to confirmed
            adventure.
          </p>
        </motion.div>

        {/* ═══════════════════════════════════════════
            JOURNEY STEPS
        ═══════════════════════════════════════════ */}
        <ol
          className="relative mt-12 grid grid-cols-1 gap-5 sm:grid-cols-2 lg:mt-16 lg:grid-cols-4 lg:gap-4"
          aria-label="How booking works"
        >
          {/* Desktop journey line */}
          <div
            aria-hidden="true"
            className="absolute left-[12.5%] right-[12.5%] top-8 hidden lg:block"
          >
            <div className="h-px w-full bg-gradient-to-r from-transparent via-border to-transparent" />

            {/* Animated progress */}
            {!shouldReduceMotion && (
              <motion.div
                initial={{
                  scaleX: 0,
                }}
                whileInView={{
                  scaleX: 1,
                }}
                viewport={{
                  once: true,
                  amount: 0.25,
                }}
                transition={{
                  duration: 1.4,
                  delay: 0.3,
                  ease: "easeInOut",
                }}
                className="absolute inset-y-0 left-0 w-full origin-left bg-gradient-to-r from-accent/20 via-accent/50 to-accent/20"
              />
            )}
          </div>

          {STEPS.map((step, index) => {
            const Icon = step.icon;

            return (
              <motion.li
                key={step.number}
                initial={
                  shouldReduceMotion
                    ? false
                    : {
                        opacity: 0,
                        y: 24,
                      }
                }
                whileInView={
                  shouldReduceMotion
                    ? undefined
                    : {
                        opacity: 1,
                        y: 0,
                      }
                }
                viewport={{
                  once: true,
                  amount: 0.2,
                }}
                transition={{
                  duration: 0.5,
                  delay: Math.min(index * 0.1, 0.3),
                  ease: "easeOut",
                }}
                className="group relative"
              >
                <motion.div
                  whileHover={
                    shouldReduceMotion
                      ? undefined
                      : {
                          y: -5,
                        }
                  }
                  className="relative h-full rounded-2xl border border-border/70 bg-background/75 p-5 shadow-sm backdrop-blur-sm transition-all duration-300 hover:border-accent/25 hover:shadow-xl hover:shadow-black/5 lg:border-transparent lg:bg-transparent lg:p-4 lg:shadow-none"
                >
                  {/* ───────────────────────────────
                      NUMBER / ICON
                  ─────────────────────────────── */}
                  <div className="flex items-center justify-between lg:block">
                    <div
                      className="relative flex h-16 w-16 items-center justify-center rounded-full border-2 border-accent/20 bg-background shadow-sm transition-all duration-500 group-hover:border-accent/50 group-hover:shadow-lg group-hover:shadow-accent/10"
                      aria-hidden="true"
                    >
                      {/* Inner ring */}
                      <span className="absolute inset-1.5 rounded-full border border-accent/10" />

                      {/* Animated pulse */}
                      {!shouldReduceMotion && (
                        <motion.span
                          animate={{
                            scale: [1, 1.15, 1],
                            opacity: [0.15, 0, 0.15],
                          }}
                          transition={{
                            duration: 3,
                            repeat: Infinity,
                            ease: "easeOut",
                            delay: index * 0.5,
                          }}
                          className="absolute inset-0 rounded-full border border-accent"
                        />
                      )}

                      <Icon
                        className="relative h-5 w-5 text-accent transition-transform duration-300 group-hover:scale-110"
                        strokeWidth={1.7}
                      />
                    </div>

                    <span className="font-mono text-xs font-semibold tracking-[0.15em] text-accent/60 lg:absolute lg:right-4 lg:top-4">
                      {step.number}
                    </span>
                  </div>

                  {/* ───────────────────────────────
                      CONTENT
                  ─────────────────────────────── */}
                  <h3 className="mt-5 font-display text-lg font-semibold tracking-tight text-foreground">
                    {step.title}
                  </h3>

                  <p className="mt-2 text-sm leading-6 text-muted-foreground">
                    {step.description}
                  </p>

                  {/* ───────────────────────────────
                      STEP MARKER
                  ─────────────────────────────── */}
                  <div className="mt-5 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground/60">
                    <span className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-accent/10">
                      <Check
                        className="h-2.5 w-2.5 text-accent"
                        strokeWidth={2.5}
                        aria-hidden="true"
                      />
                    </span>

                    <span>{step.marker}</span>
                  </div>

                  {/* Mobile connector */}
                  {index < STEPS.length - 1 && (
                    <div
                      aria-hidden="true"
                      className="absolute bottom-[-22px] left-1/2 h-5 w-px -translate-x-1/2 bg-gradient-to-b from-border to-transparent sm:hidden"
                    />
                  )}
                </motion.div>
              </motion.li>
            );
          })}
        </ol>

        {/* ═══════════════════════════════════════════
            QUOTE CALLOUT
        ═══════════════════════════════════════════ */}
        <motion.div
          initial={
            shouldReduceMotion
              ? false
              : {
                  opacity: 0,
                  y: 15,
                }
          }
          whileInView={
            shouldReduceMotion
              ? undefined
              : {
                  opacity: 1,
                  y: 0,
                }
          }
          viewport={{
            once: true,
            amount: 0.2,
          }}
          transition={{
            duration: 0.55,
            delay: 0.25,
          }}
          className="mx-auto mt-12 max-w-3xl"
        >
          <div className="relative overflow-hidden rounded-2xl border border-accent/15 bg-accent/[0.04] p-5 sm:p-6">
            {/* Decorative glow */}
            <div
              aria-hidden="true"
              className="absolute -right-20 -top-20 h-40 w-40 rounded-full bg-accent/10 blur-3xl"
            />

            <div className="relative flex flex-col gap-4 sm:flex-row sm:items-center">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-accent/15 bg-accent/10">
                <Sparkles
                  className="h-4 w-4 text-accent"
                  aria-hidden="true"
                />
              </div>

              <div>
                <p className="text-sm font-semibold text-foreground">
                  Not sure where to start?
                </p>

                <p className="mt-1 text-xs leading-5 text-muted-foreground sm:text-sm">
                  Just tell us what you&apos;re looking for.
                  Our team can turn your ideas into a practical
                  itinerary and quote.
                </p>
              </div>
            </div>
          </div>
        </motion.div>

        {/* ═══════════════════════════════════════════
            BOTTOM REASSURANCE
        ═══════════════════════════════════════════ */}
        <motion.div
          initial={
            shouldReduceMotion
              ? false
              : {
                  opacity: 0,
                  y: 10,
                }
          }
          whileInView={
            shouldReduceMotion
              ? undefined
              : {
                  opacity: 1,
                  y: 0,
                }
          }
          viewport={{
            once: true,
            amount: 0.2,
          }}
          transition={{
            duration: 0.5,
            delay: 0.35,
          }}
          className="mx-auto mt-8 flex max-w-2xl items-center justify-center gap-2 text-center text-xs text-muted-foreground"
        >
          <span
            className="h-1.5 w-1.5 rounded-full bg-emerald-500"
            aria-hidden="true"
          />

          <span>
            Flexible planning. Personalised quotes. Human
            support.
          </span>
        </motion.div>
      </div>
    </section>
  );
}
