"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { KeyRound } from "lucide-react";
import { toast } from "sonner";

import { AuthLayout } from "@/components/auth/auth-layout";
import { TrailProgress } from "@/components/auth/trail-progress";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
  FormDescription,
} from "@/components/ui/form";
import { changePasswordSchema, type ChangePasswordFormValues } from "@/lib/validations/auth";
import { authApi } from "@/lib/auth-api";
import { useAuthStore } from "@/store/auth-store";
import type { ApiError } from "@/types/auth";

const SETUP_STEPS = [
  { label: "New password", description: "Set a secure password" },
  { label: "Verify", description: "Confirm with OTP" },
  { label: "Activate", description: "Account goes live" },
];

export default function SetupPasswordPage() {
  const router = useRouter();
  const tempToken = useAuthStore((s) => s.tempToken);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Wait for Zustand to rehydrate from sessionStorage before checking tempToken
  const [hasHydrated, setHasHydrated] = useState(
      () => useAuthStore.persist.hasHydrated()
  );

  useEffect(() => {
    if (hasHydrated) return;
    const unsub = useAuthStore.persist.onFinishHydration(() => setHasHydrated(true));
    return unsub;
  }, [hasHydrated]);

  // Redirect if no temp token (only after hydration)
  useEffect(() => {
    if (!hasHydrated) return;
    if (!tempToken) {
      toast.error("Session expired. Please sign in again.");
      router.replace("/login");
    }
  }, [hasHydrated, tempToken, router]);

  const form = useForm<ChangePasswordFormValues>({
    resolver: zodResolver(changePasswordSchema),
    defaultValues: { newPassword: "", confirmPassword: "" },
  });

  async function onSubmit(values: ChangePasswordFormValues) {
    if (!tempToken) {
      toast.error("Session expired. Please sign in again.");
      router.replace("/login");
      return;
    }

    setIsSubmitting(true);
    try {
      const result = await authApi.changePasswordFirstTime(tempToken, {
        newPassword: values.newPassword,
        confirmPassword: values.confirmPassword,
      });

      if (result.rateLimited) {
        toast.warning(result.message || "Too many requests. Try again later.");
        return;
      }

      if (!result.sent) {
        toast.error(result.message || "Couldn't send verification code. Try again.");
        return;
      }

      // Success — OTP sent to phone
      toast.success("Code sent to your phone");

      // Client-side navigation — keeps the JS context (and tempToken) alive.
      // The cookie-race concern that motivated window.location.href only
      // applies to the post-login dashboard redirect, not this flow —
      // this page is gated by tempToken, not the authsys-has-session cookie.
      router.push("/setup/verify");

    } catch (err) {
      const apiError = err as ApiError;
      toast.error(apiError.message || "Couldn't update your password. Try again.");
    } finally {
      setIsSubmitting(false);
    }
  }

  // Show nothing while hydrating (prevents flash of "session expired")
  if (!hasHydrated) {
    return null;
  }

  return (
      <AuthLayout
          eyebrow="First-time setup"
          title="Set a password only you know."
          subtitle="This replaces your temporary password. We'll verify it's really you with a one-time code before it goes live."
      >
        <div className="mb-7">
          <TrailProgress steps={SETUP_STEPS} currentStep={0} />
        </div>

        <div className="mb-6">
          <h2 className="font-display text-2xl font-medium tracking-tight">
            Choose your password
          </h2>
          <p className="mt-1.5 text-sm text-muted-foreground">
            This is permanent — make it count.
          </p>
        </div>

        <Form {...form}>
          <form
              onSubmit={(e) => {
                e.preventDefault();
                form.handleSubmit(onSubmit)(e);
              }}
              className="space-y-5"
          >
            <FormField
                control={form.control}
                name="newPassword"
                render={({ field }) => (
                    <FormItem>
                      <FormLabel>New password</FormLabel>
                      <FormControl>
                        <Input
                            type="password"
                            placeholder="••••••••••"
                            autoComplete="new-password"
                            hasError={!!form.formState.errors.newPassword}
                            {...field}
                        />
                      </FormControl>
                      <FormDescription>
                        At least 10 characters, mixing case, numbers, and symbols.
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                )}
            />

            <FormField
                control={form.control}
                name="confirmPassword"
                render={({ field }) => (
                    <FormItem>
                      <FormLabel>Confirm password</FormLabel>
                      <FormControl>
                        <Input
                            type="password"
                            placeholder="••••••••••"
                            autoComplete="new-password"
                            hasError={!!form.formState.errors.confirmPassword}
                            {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                )}
            />

            <Button
                type="submit"
                variant="accent"
                size="lg"
                className="w-full"
                loading={isSubmitting}
            >
              {!isSubmitting && <KeyRound className="h-4 w-4" />}
              Continue to verification
            </Button>
          </form>
        </Form>
      </AuthLayout>
  );
}