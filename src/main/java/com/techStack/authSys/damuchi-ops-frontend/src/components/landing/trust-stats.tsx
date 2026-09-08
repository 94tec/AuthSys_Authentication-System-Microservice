"use client";

import { useEffect, useRef, useState } from "react";
import {
  BadgeCheck,
  Globe2,
  ShieldCheck,
  Star,
  Users,
} from "lucide-react";
import { motion, useReducedMotion } from "framer-motion";

interface Stat {
  value: number;
  suffix?: string;
  decimals?: number;
  label: string;
  icon: React.ElementType;
}

const STATS: Stat[] = [
  {
    value: 340,
    suffix: "+",
    label: "Curated Tours",
    icon: Globe2,
  },
  {
    value: 6200,
    suffix: "+",
    label: "Travelers Hosted",
    icon: Users,
  },
  {
    value: 4.9,
    decimals: 1,
    suffix: "★",
    label: "Average Rating",
    icon: Star,
  },
  {
    value: 4,
    label: "Countries Covered",
    icon: BadgeCheck,
  },
];

function useCountUp(
    target: number,
    decimals: number,
    active: boolean,
) {
  const [value, setValue] = useState(0);
  const reducedMotion = useReducedMotion();

  useEffect(() => {
    if (!active) return;

    if (reducedMotion) {
      setValue(target);
      return;
    }

    const duration = 1800;
    const start = performance.now();

    let frameId: number;

    const tick = (now: number) => {
      const progress = Math.min(
          (now - start) / duration,
          1,
      );

      // Smooth ease-out cubic.
      const eased = 1 - Math.pow(1 - progress, 3);

      setValue(eased * target);

      if (progress < 1) {
        frameId = requestAnimationFrame(tick);
      } else {
        setValue(target);
      }
    };

    frameId = requestAnimationFrame(tick);

    return () => cancelAnimationFrame(frameId);
  }, [active, target, reducedMotion]);

  return decimals > 0
      ? value.toFixed(decimals)
      : Math.round(value).toLocaleString();
}

function StatItem({
                    stat,
                    active,
                    index,
                  }: {
  stat: Stat;
  active: boolean;
  index: number;
}) {
  const display = useCountUp(
      stat.value,
      stat.decimals ?? 0,
      active,
  );

  const Icon = stat.icon;

  return (
      <motion.div
          initial={{
            opacity: 0,
            y: 20,
          }}
          animate={
            active
                ? {
                  opacity: 1,
                  y: 0,
                }
                : undefined
          }
          transition={{
            duration: 0.6,
            delay: index * 0.08,
            ease: "easeOut",
          }}
          className="
        group relative
        flex flex-col
        items-center
        text-center
        sm:items-start
        sm:text-left
      "
      >
        {/* Icon */}
        <div
            className="
          mb-4
          flex h-10 w-10
          items-center justify-center
          rounded-xl
          border border-white/10
          bg-white/[0.06]
          text-amber-400
          transition-all
          duration-300
          group-hover:border-amber-400/20
          group-hover:bg-amber-400/10
          group-hover:shadow-[0_0_30px_rgba(245,158,11,0.12)]
        "
        >
          <Icon
              className="h-4 w-4"
              strokeWidth={1.8}
              aria-hidden="true"
          />
        </div>

        {/* Number */}
        <div className="flex items-baseline">
        <span
            className="
            font-display
            text-3xl
            font-semibold
            tracking-tight
            text-white
            sm:text-2xl
          "
        >
          {display}
        </span>

          {stat.suffix && (
              <span
                  className="
              ml-0.5
              text-xl
              font-semibold
              text-amber-400
              sm:text-2xl
            "
              >
            {stat.suffix}
          </span>
          )}
        </div>

        {/* Label */}
        <span
            className="
          mt-1.5
          text-[11px]
          font-medium
          uppercase
          tracking-[0.18em]
          text-white/45
        "
        >
        {stat.label}
      </span>
      </motion.div>
  );
}

export function TrustStats() {
  const [active, setActive] = useState(false);
  const ref = useRef<HTMLElement>(null);

  useEffect(() => {
    const element = ref.current;

    if (!element) return;

    // Start slightly before the section is fully visible.
    const observer = new IntersectionObserver(
        ([entry]) => {
          if (entry.isIntersecting) {
            setActive(true);
            observer.disconnect();
          }
        },
        {
          threshold: 0.2,
          rootMargin: "0px 0px -40px 0px",
        },
    );

    observer.observe(element);

    return () => observer.disconnect();
  }, []);

  return (
      <section
          ref={ref}
          aria-label="Damuchi Safaris trust statistics"
          className="
        relative
        overflow-hidden
        border-y
        border-white/[0.06]
        bg-gray-950
      "
      >
        {/* Atmospheric glow */}
        <div
            className="
          pointer-events-none
          absolute
          left-1/2
          top-1/2
          h-80
          w-[700px]
          -translate-x-1/2
          -translate-y-1/2
          rounded-full
          bg-amber-500/[0.045]
          blur-[110px]
        "
            aria-hidden="true"
        />

        {/* Subtle top highlight */}
        <div
            className="
          pointer-events-none
          absolute inset-x-0 top-0
          h-px
          bg-gradient-to-r
          from-transparent
          via-white/10
          to-transparent
        "
            aria-hidden="true"
        />

        <div className="relative mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8 lg:py-14">
          {/* Stats */}
          <div
              className="
            grid
            grid-cols-2
            gap-y-10
            sm:grid-cols-4
            sm:divide-x
            sm:divide-white/[0.08]
          "
          >
            {STATS.map((stat, index) => (
                <div
                    key={stat.label}
                    className="
                px-4
                first:sm:pl-0
                last:sm:pr-0
              "
                >
                  <StatItem
                      stat={stat}
                      active={active}
                      index={index}
                  />
                </div>
            ))}
          </div>

          {/* Verification statement */}
          <motion.div
              initial={{
                opacity: 0,
              }}
              animate={
                active
                    ? {
                      opacity: 1,
                    }
                    : undefined
              }
              transition={{
                delay: 0.5,
                duration: 0.7,
              }}
              className="
            mx-auto mt-12
            flex max-w-3xl
            flex-col items-center
            justify-center
            gap-3
            border-t
            border-white/[0.07]
            pt-7
            text-center
            sm:flex-row
          "
          >
            <div
                className="
              flex h-8 w-8
              shrink-0
              items-center justify-center
              rounded-full
              bg-emerald-400/10
              text-emerald-400
            "
            >
              <ShieldCheck
                  className="h-4 w-4"
                  aria-hidden="true"
              />
            </div>

            <p className="text-xs leading-relaxed text-white/45">
            <span className="font-medium text-white/65">
              Verified local operators
            </span>{" "}
              across Kenya, Tanzania, Uganda &amp; Rwanda.
            </p>
          </motion.div>
        </div>
      </section>
  );
}