"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { toast } from "sonner";

import { AuthLayout } from "@/components/auth/auth-layout";
import { OtpField } from "@/components/ui/otp-field";
import { Button } from "@/components/ui/button";
import { authApi } from "@/lib/auth-api";
import { useAuthStore } from "@/store/auth-store";
import type { ApiError } from "@/types/auth";

const RESEND_COOLDOWN_SECONDS = 45;

export default function LoginVerifyPage() {
  const router = useRouter();
  const tempToken = useAuthStore((s) => s.tempToken);
  const setTokens = useAuthStore((s) => s.setTokens);
  const [otp, setOtp] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isResending, setIsResending] = useState(false);
  const [hasError, setHasError] = useState(false);
  const [cooldown, setCooldown] = useState(0);

  useEffect(() => {
    if (!tempToken) {
      toast.error("Your session expired. Please sign in again.");
      router.replace("/login");
    }
  }, [tempToken, router]);

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setInterval(() => setCooldown((c) => c - 1), 1000);
    return () => clearInterval(timer);
  }, [cooldown]);

  async function handleVerify(code: string) {
    if (!tempToken || code.length !== 6) return;
    setIsSubmitting(true);
    setHasError(false);
    try {
      const tokenPair = await authApi.verifyLoginOtp(tempToken, { otp: code });
      setTokens(tokenPair);
      toast.success("Welcome back");
      router.push("/dashboard");
    } catch (err) {
      const apiError = err as ApiError;
      setHasError(true);
      setOtp("");
      toast.error(apiError.message || "Incorrect code.");
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleResend() {
    if (!tempToken || cooldown > 0) return;
    setIsResending(true);
    try {
      const result = await authApi.resendLoginOtp(tempToken);
      if (result.rateLimited) {
        toast.warning(result.message);
      } else {
        toast.success("New code sent");
        setCooldown(RESEND_COOLDOWN_SECONDS);
        setOtp("");
        setHasError(false);
      }
    } catch (err) {
      const apiError = err as ApiError;
      toast.error(apiError.message || "Couldn't resend code.");
    } finally {
      setIsResending(false);
    }
  }

  function handleOtpChange(value: string) {
    setOtp(value);
    setHasError(false);
    if (value.length === 6) {
      handleVerify(value);
    }
  }

  return (
    <AuthLayout
      eyebrow="Verify it's you"
      title="A quick check before you head out."
      subtitle="Two-factor verification keeps the dashboard locked to your team alone."
    >
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
        onChange={handleOtpChange}
        disabled={isSubmitting}
        hasError={hasError}
      />

      <Button
        type="button"
        variant="accent"
        size="lg"
        className="mt-6 w-full"
        loading={isSubmitting}
        disabled={otp.length !== 6}
        onClick={() => handleVerify(otp)}
      >
        Verify and sign in
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
