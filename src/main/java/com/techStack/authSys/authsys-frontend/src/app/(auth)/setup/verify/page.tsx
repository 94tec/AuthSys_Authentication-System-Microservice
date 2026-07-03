"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { toast } from "sonner";

import { AuthLayout } from "@/components/auth/auth-layout";
import { TrailProgress } from "@/components/auth/trail-progress";
import { OtpField } from "@/components/ui/otp-field";
import { Button } from "@/components/ui/button";
import { authApi } from "@/lib/auth-api";
import { useAuthStore } from "@/store/auth-store";
import type { ApiError } from "@/types/auth";

const SETUP_STEPS = [
  { label: "New password", description: "Set a secure password" },
  { label: "Verify", description: "Confirm with OTP" },
  { label: "Activate", description: "Account goes live" },
];

const RESEND_COOLDOWN = 45;

export default function SetupVerifyPage() {
  const router = useRouter();
  const tempToken = useAuthStore((s) => s.tempToken);
  const [otp, setOtp] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isResending, setIsResending] = useState(false);
  const [hasError, setHasError] = useState(false);
  const [remainingAttempts, setRemainingAttempts] = useState<number | null>(null);
  const [cooldown, setCooldown] = useState(0);

  const [hasHydrated, setHasHydrated] = useState(
      () => useAuthStore.persist.hasHydrated()
  );

  useEffect(() => {
    if (hasHydrated) return;
    const unsub = useAuthStore.persist.onFinishHydration(() => setHasHydrated(true));
    return unsub;
  }, [hasHydrated]);

  useEffect(() => {
    if (!hasHydrated) return;
    if (!tempToken) {
      toast.error("Session expired. Please sign in again.");
      router.replace("/login");
    }
  }, [hasHydrated, tempToken, router]);

  useEffect(() => {
    if (cooldown <= 0) return;
    const t = setInterval(() => setCooldown((c) => c - 1), 1000);
    return () => clearInterval(t);
  }, [cooldown]);

  async function handleVerify(code: string) {
    if (!tempToken || code.length !== 6) return;
    setIsSubmitting(true);
    setHasError(false);
    try {
      const result = await authApi.verifyOtpFirstTime(tempToken, { otp: code });

      if (!result.valid) {
        setHasError(true);
        setOtp("");
        if (result.expired) {
          toast.error("That code expired. Request a new one.");
        } else if (result.attemptsExceeded) {
          toast.error("Too many attempts. Request a new code.");
        } else {
          setRemainingAttempts(result.remainingAttempts);
          toast.error(result.message || "Incorrect code.");
        }
        return;
      }

      if (result.verificationToken) {
        sessionStorage.setItem("ftl_verification_token", result.verificationToken);
      }

      toast.success("Verified — activating your account");

      // Client-side navigation — same reasoning as setup/password:
      // this flow is gated by tempToken (in-memory Zustand state),
      // not the dashboard's authsys-has-session cookie, so there's
      // no cookie race to avoid here. A full reload would just
      // destroy the in-memory tempToken/verificationToken context
      // before the next page can read it.
      router.push("/setup/complete");

    } catch (err) {
      setHasError(true);
      setOtp("");
      toast.error((err as ApiError).message || "Verification failed.");
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleResend() {
    if (!tempToken || cooldown > 0) return;
    setIsResending(true);
    try {
      const result = await authApi.resendSetupOtp(tempToken);
      if (result.rateLimited) {
        toast.warning(result.message);
      } else {
        toast.success("New code sent");
        setCooldown(RESEND_COOLDOWN);
        setOtp("");
        setHasError(false);
      }
    } catch (err) {
      toast.error((err as ApiError).message || "Couldn't resend code.");
    } finally {
      setIsResending(false);
    }
  }

  if (!hasHydrated) return null;

  return (
      <AuthLayout
          eyebrow="First-time setup"
          title="One code stands between you and the trail."
          subtitle="We sent a 6-digit code to the phone number on file. Enter it to confirm it's really you."
      >
        <div className="mb-7">
          <TrailProgress steps={SETUP_STEPS} currentStep={1} />
        </div>

        <div className="mb-6 flex flex-col items-center text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-accent/10 text-accent">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <h2 className="mt-4 font-display text-2xl font-medium tracking-tight">
            Enter verification code
          </h2>
          <p className="mt-1.5 text-sm text-muted-foreground">
            Check your phone for a 6-digit code.
          </p>
        </div>

        <OtpField
            value={otp}
            onChange={(v) => {
              setOtp(v);
              setHasError(false);
              if (v.length === 6) handleVerify(v);
            }}
            disabled={isSubmitting}
            hasError={hasError}
        />

        {remainingAttempts !== null && remainingAttempts > 0 && (
            <p className="mt-3 text-center text-xs text-warning">
              {remainingAttempts} attempt{remainingAttempts === 1 ? "" : "s"} remaining
            </p>
        )}

        <Button
            type="button"
            variant="accent"
            size="lg"
            className="mt-6 w-full"
            loading={isSubmitting}
            disabled={otp.length !== 6 || isSubmitting}
            onClick={() => handleVerify(otp)}
        >
          Verify code
        </Button>

        <button
            type="button"
            onClick={handleResend}
            disabled={isResending || cooldown > 0}
            className="mt-4 w-full text-center text-sm font-medium text-accent hover:underline disabled:cursor-not-allowed disabled:text-muted-foreground disabled:no-underline"
        >
          {cooldown > 0 ? `Resend code in ${cooldown}s` : "Resend code"}
        </button>
      </AuthLayout>
  );
}