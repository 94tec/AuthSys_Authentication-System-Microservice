"use client";

import { useEffect, useRef, useState } from "react";
import axios from "axios";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  AlertTriangle,
  ArrowRight,
  Check,
  LoaderCircle,
  LockKeyhole,
  ShieldCheck,
  Sparkles,
} from "lucide-react";

import { useAuthStore } from "@/store/auth-store";
import { isSameOriginRedirect } from "@/lib/auth-redirect-utils";
import type { Role, TokenPair } from "@/types/index-types";

const API_BASE_URL =
    process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8001/api";

const VALID_ROLES: readonly Role[] = [
  "SUPER_ADMIN",
  "ADMIN",
  "MANAGER",
  "OPERATOR",
  "USER",
  "GUEST",
];

function toRoles(value: unknown): Role[] {
  if (!Array.isArray(value)) return [];

  return value.filter((role): role is Role =>
      VALID_ROLES.includes(role as Role)
  );
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const payload = token.split(".")[1];

    if (!payload) return null;

    const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const normalized = base64.padEnd(
        base64.length + ((4 - (base64.length % 4)) % 4),
        "="
    );

    return JSON.parse(atob(normalized));
  } catch {
    return null;
  }
}

type Stage = "verifying" | "success" | "error";

const STAGE_CONTENT = {
  verifying: {
    eyebrow: "Secure authentication",
    title: "Signing you in",
    description:
        "We're securely verifying your session and preparing your account.",
  },
  success: {
    eyebrow: "Authentication complete",
    title: "Welcome back",
    description:
        "Everything looks good. We're taking you to your destination.",
  },
} satisfies Record<
    Exclude<Stage, "error">,
    {
      eyebrow: string;
      title: string;
      description: string;
    }
>;

export default function AuthCallbackPage() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [stage, setStage] = useState<Stage>("verifying");
  const [error, setError] = useState<string | null>(null);
  const [slow, setSlow] = useState(false);

  const hasFiredRef = useRef(false);

  useEffect(() => {
    if (hasFiredRef.current) return;

    hasFiredRef.current = true;

    const code = searchParams.get("code");

    const rawNext = searchParams.get("next") || "/";
    const next = isSameOriginRedirect(rawNext) ? rawNext : "/";

    if (!code) {
      router.replace("/login-required");
      return;
    }

    const slowTimer = window.setTimeout(() => {
      setSlow(true);
    }, 4000);

    const redeem = async () => {
      try {
        const { data } = await axios.post<TokenPair>(
            `${API_BASE_URL}/auth/sso/redeem`,
            { code },
            {
              timeout: 10_000,
            }
        );

        useAuthStore.getState().setTokens({
          accessToken: data.accessToken,
          refreshToken: data.refreshToken,
        });

        const claims = decodeJwtPayload(data.accessToken);

        if (claims) {
          useAuthStore.getState().setUser({
            id:
                (claims.userId as string) ??
                (claims.sub as string) ??
                "",
            email: (claims.email as string) ?? "",
            roles: toRoles(claims.roles),
          });
        }

        /*
         * Best-effort account enrichment.
         *
         * Authentication does not wait for this request. The JWT already gives
         * us enough information to establish the local user session.
         */
        void import("@/lib/auth-api")
            .then(({ authApi }) => authApi.getCurrentUser?.())
            .then((fullUser) => {
              if (fullUser) {
                useAuthStore.getState().setUser(fullUser);
              }
            })
            .catch((profileError) => {
              console.warn(
                  "Background profile fetch failed after SSO login:",
                  profileError
              );
            });

        window.clearTimeout(slowTimer);

        setSlow(false);
        setStage("success");

        window.setTimeout(() => {
          router.replace(next);
        }, 900);
      } catch (err) {
        console.error("SSO redeem failed:", err);

        const message = axios.isAxiosError(err)
            ? (
            err.response?.data as
                | {
              message?: string;
            }
                | undefined
        )?.message ?? err.message
            : "Unexpected error";

        window.clearTimeout(slowTimer);

        setSlow(false);
        setStage("error");
        setError(
            `This sign-in link may have expired or already been used. ${message}`
        );
      }
    };

    void redeem();

    return () => {
      window.clearTimeout(slowTimer);
    };
  }, [router, searchParams]);

  return (
      <main className="relative isolate flex min-h-screen overflow-hidden bg-[#070709] text-white">
        {/* ===============================================================
          BACKGROUND
      =============================================================== */}

        <div className="pointer-events-none absolute inset-0 -z-20 bg-[radial-gradient(circle_at_top,#181318_0%,#09090b_42%,#050506_100%)]" />

        {/* animated grid */}
        <div
            className="
          pointer-events-none
          absolute
          inset-0
          -z-10
          opacity-[0.055]
          [background-image:linear-gradient(rgba(255,255,255,.15)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,.15)_1px,transparent_1px)]
          [background-size:64px_64px]
          [mask-image:radial-gradient(ellipse_at_center,black_10%,transparent_75%)]
        "
        />

        {/* coral glow */}
        <div
            className="
          pointer-events-none
          absolute
          -left-40
          -top-40
          -z-10
          h-[32rem]
          w-[32rem]
          rounded-full
          bg-coral/15
          blur-[130px]
          animate-[authFloat_9s_ease-in-out_infinite]
        "
        />

        {/* orange glow */}
        <div
            className="
          pointer-events-none
          absolute
          -bottom-48
          -right-32
          -z-10
          h-[36rem]
          w-[36rem]
          rounded-full
          bg-orange/10
          blur-[140px]
          animate-[authFloatReverse_11s_ease-in-out_infinite]
        "
        />

        {/* center glow */}
        <div
            className="
          pointer-events-none
          absolute
          left-1/2
          top-1/2
          -z-10
          h-[28rem]
          w-[28rem]
          -translate-x-1/2
          -translate-y-1/2
          rounded-full
          bg-white/[0.025]
          blur-[80px]
        "
        />

        {/* floating particles */}
        <div className="pointer-events-none absolute inset-0 -z-10 overflow-hidden">
          <span className="absolute left-[14%] top-[22%] h-1 w-1 animate-[particle_7s_ease-in-out_infinite] rounded-full bg-coral/60" />
          <span className="absolute right-[18%] top-[34%] h-1.5 w-1.5 animate-[particle_9s_ease-in-out_1s_infinite] rounded-full bg-orange/40" />
          <span className="absolute bottom-[23%] left-[22%] h-1 w-1 animate-[particle_8s_ease-in-out_2s_infinite] rounded-full bg-white/40" />
          <span className="absolute bottom-[33%] right-[25%] h-1 w-1 animate-[particle_10s_ease-in-out_500ms_infinite] rounded-full bg-coral/30" />
        </div>

        {/* ===============================================================
          PAGE CONTENT
      =============================================================== */}

        <section className="relative mx-auto flex min-h-screen w-full max-w-7xl items-center justify-center px-5 py-12 sm:px-8">
          <div className="w-full max-w-[460px]">
            {/* top branding */}
            <div
                className="
              mb-7
              flex
              animate-[authFadeDown_.7s_ease-out_both]
              items-center
              justify-center
              gap-2
              text-sm
              font-medium
              text-white/45
            "
            >
              <div className="flex h-7 w-7 items-center justify-center rounded-lg border border-white/10 bg-white/[0.05] shadow-lg shadow-black/20">
                <LockKeyhole className="h-3.5 w-3.5 text-coral" />
              </div>

              <span>Secure authentication</span>
            </div>

            {/* ===========================================================
              CARD
          =========================================================== */}

            <div
                className="
              relative
              animate-[authEnter_.75s_cubic-bezier(.16,1,.3,1)_both]
              overflow-hidden
              rounded-[32px]
              border
              border-white/[0.09]
              bg-white/[0.045]
              p-[1px]
              shadow-[0_30px_100px_-25px_rgba(0,0,0,.8)]
              backdrop-blur-2xl
            "
            >
              {/* animated border highlight */}
              <div
                  className="
                pointer-events-none
                absolute
                -inset-[150%]
                animate-[borderRotate_9s_linear_infinite]
                bg-[conic-gradient(from_0deg,transparent_0deg,transparent_280deg,rgba(255,107,87,.22)_320deg,transparent_360deg)]
              "
              />

              <div className="relative overflow-hidden rounded-[31px] bg-[#0d0d10]/90">
                {/* inner top light */}
                <div className="pointer-events-none absolute inset-x-16 top-0 h-px bg-gradient-to-r from-transparent via-white/25 to-transparent" />

                <div className="px-7 py-9 sm:px-10 sm:py-11">
                  {stage === "error" ? (
                      <ErrorState error={error} />
                  ) : (
                      <AuthenticationState
                          stage={stage}
                          slow={slow}
                      />
                  )}
                </div>

                {/* =======================================================
                  FOOTER STATUS
              ======================================================= */}

                <div className="border-t border-white/[0.065] bg-white/[0.018] px-7 py-4 sm:px-10">
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex items-center gap-2 text-[11px] text-white/35">
                      <ShieldCheck className="h-3.5 w-3.5 text-emerald-400/70" />

                      <span>Protected connection</span>
                    </div>

                    <div className="flex items-center gap-1.5 text-[11px] text-white/25">
                    <span
                        className={`h-1.5 w-1.5 rounded-full ${
                            stage === "error"
                                ? "bg-red-400"
                                : stage === "success"
                                    ? "bg-emerald-400"
                                    : "animate-pulse bg-coral"
                        }`}
                    />

                      {stage === "error"
                          ? "Action required"
                          : stage === "success"
                              ? "Verified"
                              : "Verifying"}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* bottom message */}
            <p
                className="
              mt-6
              animate-[authFadeUp_.7s_ease-out_.2s_both]
              text-center
              text-[11px]
              leading-relaxed
              text-white/25
            "
            >
              Your credentials are transmitted securely and never exposed
              during this process.
            </p>
          </div>
        </section>

        <style jsx global>{`
        @keyframes authEnter {
          from {
            opacity: 0;
            transform: translateY(22px) scale(0.975);
            filter: blur(8px);
          }

          to {
            opacity: 1;
            transform: translateY(0) scale(1);
            filter: blur(0);
          }
        }

        @keyframes authFadeDown {
          from {
            opacity: 0;
            transform: translateY(-10px);
          }

          to {
            opacity: 1;
            transform: translateY(0);
          }
        }

        @keyframes authFadeUp {
          from {
            opacity: 0;
            transform: translateY(10px);
          }

          to {
            opacity: 1;
            transform: translateY(0);
          }
        }

        @keyframes authFloat {
          0%,
          100% {
            transform: translate3d(0, 0, 0) scale(1);
          }

          50% {
            transform: translate3d(50px, 35px, 0) scale(1.08);
          }
        }

        @keyframes authFloatReverse {
          0%,
          100% {
            transform: translate3d(0, 0, 0) scale(1);
          }

          50% {
            transform: translate3d(-40px, -30px, 0) scale(1.1);
          }
        }

        @keyframes borderRotate {
          to {
            transform: rotate(360deg);
          }
        }

        @keyframes particle {
          0%,
          100% {
            opacity: 0.2;
            transform: translateY(0) scale(1);
          }

          50% {
            opacity: 0.8;
            transform: translateY(-30px) scale(1.5);
          }
        }

        @keyframes shieldPulse {
          0%,
          100% {
            box-shadow:
              0 0 0 0 rgba(255, 107, 87, 0),
              0 14px 45px rgba(0, 0, 0, 0.4);
          }

          50% {
            box-shadow:
              0 0 0 10px rgba(255, 107, 87, 0.035),
              0 14px 45px rgba(0, 0, 0, 0.4);
          }
        }

        @keyframes scan {
          0% {
            transform: translateY(-45px);
            opacity: 0;
          }

          20% {
            opacity: 0.8;
          }

          80% {
            opacity: 0.8;
          }

          100% {
            transform: translateY(45px);
            opacity: 0;
          }
        }

        @keyframes successPop {
          0% {
            transform: scale(0.6) rotate(-15deg);
            opacity: 0;
          }

          60% {
            transform: scale(1.1) rotate(3deg);
          }

          100% {
            transform: scale(1) rotate(0);
            opacity: 1;
          }
        }

        @keyframes successRing {
          0% {
            opacity: 0.8;
            transform: scale(0.65);
          }

          100% {
            opacity: 0;
            transform: scale(1.55);
          }
        }

        @keyframes progress {
          0% {
            transform: translateX(-100%);
          }

          55% {
            transform: translateX(-28%);
          }

          100% {
            transform: translateX(-10%);
          }
        }

        @media (prefers-reduced-motion: reduce) {
          *,
          *::before,
          *::after {
            animation-duration: 0.01ms !important;
            animation-iteration-count: 1 !important;
          }
        }
      `}</style>
      </main>
  );
}

/* ========================================================================
   AUTHENTICATION STATE
======================================================================== */

function AuthenticationState({
                               stage,
                               slow,
                             }: {
  stage: Exclude<Stage, "error">;
  slow: boolean;
}) {
  const content = STAGE_CONTENT[stage];
  const success = stage === "success";

  return (
      <div className="flex flex-col items-center text-center">
        {/* ===============================================================
          ICON
        =============================================================== */}

        <div className="relative mb-8 flex h-28 w-28 items-center justify-center">
          {/* outer rings */}
          <div
              className={`
            absolute
            inset-0
            rounded-full
            border
            transition-all
            duration-700
            ${
                  success
                      ? "scale-110 border-emerald-400/0 opacity-0"
                      : "border-white/[0.06] opacity-100"
              }
          `}
          />

          <div
              className={`
            absolute
            inset-[10px]
            rounded-full
            border
            transition-all
            duration-700
            ${
                  success
                      ? "border-emerald-400/10"
                      : "border-coral/10"
              }
          `}
          />

          {!success && (
              <>
                {/* orbit */}
                <div className="absolute left-1/2 top-1/2 animate-[spin_3s_linear_infinite] rounded-full border border-transparent border-t-coral/70 border-r-coral/20" />

                <div className="absolute left-1/2 top-1/2 animate-[spin_5s_linear_infinite_reverse] rounded-full border border-transparent border-b-orange/30" />
              </>
          )}

          {success && (
              <>
                  <div className="absolute left-1/2 top-1/2 h-20 w-20 -translate-x-1/2 -translate-y-1/2 animate-[successRing_1s_ease-out_infinite] rounded-full border border-emerald-400/35" />

                  <div className="absolute left-1/2 top-1/2 h-20 w-20 -translate-x-1/2 -translate-y-1/2 animate-[successRing_1s_ease-out_.35s_infinite] rounded-full border border-emerald-400/20" />
              </>
          )}

          {/* central icon */}
          <div
              className={`
            relative
            flex
            h-[72px]
            w-[72px]
            items-center
            justify-center
            overflow-hidden
            rounded-[24px]
            border
            transition-all
            duration-500
            ${
                  success
                      ? "border-emerald-400/20 bg-emerald-400/[0.10]"
                      : "animate-[shieldPulse_3s_ease-in-out_infinite] border-white/[0.09] bg-white/[0.055]"
              }
          `}
          >
            {!success && (
                <div
                    className="
                pointer-events-none
                absolute
                inset-x-3
                top-1/2
                h-8
                -translate-y-1/2
                animate-[scan_2.4s_ease-in-out_infinite]
                bg-gradient-to-b
                from-transparent
                via-coral/[0.08]
                to-transparent
                blur-sm
              "
                />
            )}

            {success ? (
                <Check className="h-8 w-8 animate-[successPop_.45s_cubic-bezier(.34,1.56,.64,1)_both] stroke-[2.3] text-emerald-400" />
            ) : (
                <ShieldCheck className="relative h-8 w-8 text-white/80" />
            )}
          </div>

          {!success && (
              <div className="absolute bottom-[8px] right-[6px] flex h-7 w-7 items-center justify-center rounded-full border-4 border-[#0d0d10] bg-coral shadow-lg shadow-coral/20">
                <LoaderCircle className="h-3.5 w-3.5 animate-spin text-white" />
              </div>
          )}

          {success && (
              <div className="absolute -right-1 top-2 animate-[successPop_.5s_ease-out_.15s_both]">
                <Sparkles className="h-5 w-5 text-emerald-300/70" />
              </div>
          )}
        </div>

        {/* ===============================================================
          COPY
      =============================================================== */}

        <div
            key={stage}
            className="animate-[authFadeUp_.45s_ease-out_both]"
        >
          <div
              className={`
            mb-3
            inline-flex
            items-center
            gap-2
            rounded-full
            border
            px-3
            py-1.5
            text-[10px]
            font-semibold
            uppercase
            tracking-[0.16em]
            ${
                  success
                      ? "border-emerald-400/15 bg-emerald-400/[0.06] text-emerald-300"
                      : "border-coral/15 bg-coral/[0.05] text-coral"
              }
          `}
          >
          <span
              className={`h-1.5 w-1.5 rounded-full ${
                  success
                      ? "bg-emerald-400"
                      : "animate-pulse bg-coral"
              }`}
          />

            {content.eyebrow}
          </div>

          <h1 className="text-[26px] font-semibold tracking-[-0.035em] text-white sm:text-[28px]">
            {content.title}
          </h1>

          <p className="mx-auto mt-3 max-w-[320px] text-[13px] leading-6 text-white/45">
            {content.description}
          </p>
        </div>

        {/* ===============================================================
          PROGRESS AREA
      =============================================================== */}

        {!success ? (
            <div className="mt-9 w-full">
              <div className="h-1 overflow-hidden rounded-full bg-white/[0.06]">
                <div className="h-full w-full animate-[progress_5s_cubic-bezier(.4,0,.2,1)_forwards] rounded-full bg-gradient-to-r from-coral via-orange to-coral" />
              </div>

              <div className="mt-3 flex items-center justify-between text-[10px] text-white/25">
                <span>Verifying identity</span>
                <span>Encrypted</span>
              </div>

              <div
                  className={`
              grid
              transition-all
              duration-500
              ${
                      slow
                          ? "mt-6 grid-rows-[1fr] opacity-100"
                          : "mt-0 grid-rows-[0fr] opacity-0"
                  }
            `}
              >
                <div className="overflow-hidden">
                  <div className="rounded-2xl border border-amber-400/10 bg-amber-400/[0.045] px-4 py-3 text-left">
                    <div className="flex gap-3">
                      <LoaderCircle className="mt-0.5 h-4 w-4 shrink-0 animate-spin text-amber-300/70" />

                      <div>
                        <p className="text-[11px] font-medium text-amber-100/75">
                          Taking a little longer
                        </p>

                        <p className="mt-1 text-[10px] leading-4 text-white/30">
                          Your session is still being processed. Please keep this
                          window open.
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
        ) : (
            <div className="mt-8 flex items-center gap-2 text-xs text-emerald-300/70">
              <span>Opening your account</span>

              <ArrowRight className="h-3.5 w-3.5 animate-pulse" />
            </div>
        )}
      </div>
  );
}

/* ========================================================================
   ERROR STATE
======================================================================== */

function ErrorState({ error }: { error: string | null }) {
  return (
      <div className="flex flex-col items-center text-center">
        <div className="relative mb-8 flex h-28 w-28 items-center justify-center">
          <div className="absolute inset-0 rounded-full border border-red-400/[0.07]" />

          <div className="absolute inset-3 rounded-full border border-red-400/[0.08]" />

          <div className="absolute inset-5 rounded-full bg-red-500/[0.035] blur-xl" />

          <div className="relative flex h-[72px] w-[72px] items-center justify-center rounded-[24px] border border-red-400/[0.16] bg-red-500/[0.08] shadow-[0_18px_50px_-20px_rgba(239,68,68,.55)]">
            <AlertTriangle className="h-8 w-8 text-red-400" />
          </div>
        </div>

        <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-red-400/15 bg-red-400/[0.055] px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-red-300">
          <span className="h-1.5 w-1.5 rounded-full bg-red-400" />

          Authentication failed
        </div>

        <h1 className="text-[26px] font-semibold tracking-[-0.035em] text-white sm:text-[28px]">
          Couldn't sign you in
        </h1>

        <p className="mx-auto mt-3 max-w-[330px] text-[13px] leading-6 text-white/45">
          {error ??
              "Your authentication session couldn't be completed. Please try signing in again."}
        </p>

        <Link
            href="/login-required"
            className="
          group
          mt-8
          inline-flex
          h-11
          items-center
          justify-center
          gap-2
          rounded-xl
          bg-white
          px-5
          text-[13px]
          font-semibold
          text-black
          shadow-[0_10px_30px_-12px_rgba(255,255,255,.35)]
          transition-all
          duration-300
          hover:-translate-y-0.5
          hover:bg-white/90
          active:translate-y-0
        "
        >
          Try signing in again

          <ArrowRight className="h-4 w-4 transition-transform duration-300 group-hover:translate-x-0.5" />
        </Link>

        <p className="mt-4 text-[10px] text-white/25">
          You may need to request a new sign-in link.
        </p>
      </div>
  );
}