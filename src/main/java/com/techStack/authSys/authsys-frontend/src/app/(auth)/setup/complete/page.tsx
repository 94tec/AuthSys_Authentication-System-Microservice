"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { AuthLayout } from "@/components/auth/auth-layout";
import { TrailProgress } from "@/components/auth/trail-progress";
import { PassportStamp } from "@/components/auth/passport-stamp";
import { Button } from "@/components/ui/button";
import { authApi } from "@/lib/auth-api";
import { useAuthStore } from "@/store/auth-store";
import type { ApiError } from "@/types/auth";

const SETUP_STEPS = [
  { label: "New password", description: "Set a secure password" },
  { label: "Verify", description: "Confirm with OTP" },
  { label: "Activate", description: "Account goes live" },
];

export default function SetupCompletePage() {
  const router = useRouter();
  const setTokens = useAuthStore((s) => s.setTokens);
  const [status, setStatus] = useState<"loading" | "success" | "error">(
    "loading"
  );
  const [errorMessage, setErrorMessage] = useState("");

  const [hasHydrated, setHasHydrated] = useState(useAuthStore.persist.hasHydrated());

  useEffect(() => {
    const unsub = useAuthStore.persist.onFinishHydration(() => setHasHydrated(true));
    setHasHydrated(useAuthStore.persist.hasHydrated());
    return unsub;
  }, []);

  useEffect(() => {
    const verificationToken = sessionStorage.getItem("ftl_verification_token");

    if (!hasHydrated) return;
    if (!verificationToken) {
      setStatus("error");
      setErrorMessage("Missing verification token. Please restart setup.");
      return;
    }

    authApi
      .completeSetup(verificationToken)
      .then((tokenPair) => {
        setTokens(tokenPair);
        sessionStorage.removeItem("ftl_verification_token");
        setStatus("success");
        toast.success("Account activated");
      })
      .catch((err) => {
        const apiError = err as ApiError;
        setStatus("error");
        setErrorMessage(
          apiError.message || "Couldn't complete setup. Please try again."
        );
      });
  }, [setTokens, hasHydrated]);

  return (
    <AuthLayout
      eyebrow="First-time setup"
      title="Welcome to basecamp."
      subtitle="Your account is now active. From here, you can manage tours, review bookings, and help travelers find their next trail."
    >
      <div className="mb-7">
        <TrailProgress steps={SETUP_STEPS} currentStep={2} />
      </div>

      <div className="flex flex-col items-center py-6 text-center">
        {status === "loading" && (
          <>
            <div className="h-14 w-14 animate-pulse rounded-full bg-muted" />
            <p className="mt-5 text-sm text-muted-foreground">
              Activating your account…
            </p>
          </>
        )}

        {status === "success" && (
          <>
            <PassportStamp label="Basecamp" />
            <h2 className="mt-6 font-display text-2xl font-medium tracking-tight">
              Account activated
            </h2>
            <p className="mt-1.5 text-sm text-muted-foreground">
              You're all set. Head to Login to get started.
            </p>
            <Button
              variant="accent"
              size="lg"
              className="mt-6 w-full"
              onClick={() => router.push("/login")}
            >
              Go to Login
            </Button>
          </>
        )}

        {status === "error" && (
          <>
            <div className="flex h-14 w-14 items-center justify-center rounded-full bg-destructive/10 text-destructive">
              !
            </div>
            <h2 className="mt-5 font-display text-2xl font-medium tracking-tight">
              Setup couldn't finish
            </h2>
            <p className="mt-1.5 text-sm text-muted-foreground">{errorMessage}</p>
            <Button
              variant="outline"
              size="lg"
              className="mt-6 w-full"
              onClick={() => router.push("/login")}
            >
              Back to sign in
            </Button>
          </>
        )}
      </div>
    </AuthLayout>
  );
}
