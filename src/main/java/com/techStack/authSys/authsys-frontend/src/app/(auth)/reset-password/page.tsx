"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { KeyRound, CheckCircle2 } from "lucide-react";
import { toast } from "sonner";

import { AuthLayout } from "@/components/auth/auth-layout";
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
import {
  resetPasswordSchema,
  type ResetPasswordFormValues,
} from "@/lib/validations/auth";
import { authApi } from "@/lib/auth-api";
import type { ApiError } from "@/types/auth";

export default function ResetPasswordPage() {
  const router = useRouter();
  const params = useSearchParams();
  const token = params.get("token");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isComplete, setIsComplete] = useState(false);

  const form = useForm<ResetPasswordFormValues>({
    resolver: zodResolver(resetPasswordSchema),
    defaultValues: { newPassword: "", confirmPassword: "" },
  });

  useEffect(() => {
    if (!token) {
      toast.error("This reset link is invalid or incomplete.");
    }
  }, [token]);

  async function onSubmit(values: ResetPasswordFormValues) {
    if (!token) return;
    setIsSubmitting(true);
    try {
      await authApi.resetPassword({
        token,
        newPassword: values.newPassword,
      });
      setIsComplete(true);
      toast.success("Password reset");
    } catch (err) {
      const apiError = err as ApiError;
      toast.error(
        apiError.message || "This link may have expired. Request a new one."
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  if (!token) {
    return (
      <AuthLayout
        eyebrow="Account recovery"
        title="That link didn't make it."
        subtitle="Reset links expire after a short window for your security."
      >
        <div className="flex flex-col items-center py-4 text-center">
          <h2 className="font-display text-2xl font-medium tracking-tight">
            Invalid reset link
          </h2>
          <p className="mt-2 text-sm text-muted-foreground">
            This link is missing or no longer valid. Request a new one to continue.
          </p>
          <Button asChild variant="accent" size="lg" className="mt-6 w-full">
            <Link href="/forgot-password">Request new link</Link>
          </Button>
        </div>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout
      eyebrow="Account recovery"
      title="One new password, one fresh start."
      subtitle="Choose something strong — this is what stands between your account and anyone else."
    >
      {!isComplete ? (
        <>
          <div className="mb-7">
            <h2 className="font-display text-2xl font-medium tracking-tight">
              Set a new password
            </h2>
            <p className="mt-1.5 text-sm text-muted-foreground">
              Make it different from your previous password.
            </p>
          </div>

          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-5">
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
                Reset password
              </Button>
            </form>
          </Form>
        </>
      ) : (
        <div className="flex flex-col items-center py-4 text-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-full bg-success/10 text-success">
            <CheckCircle2 className="h-6 w-6" />
          </div>
          <h2 className="mt-5 font-display text-2xl font-medium tracking-tight">
            Password reset
          </h2>
          <p className="mt-2 text-sm text-muted-foreground">
            Sign in with your new password to continue.
          </p>
          <Button
            variant="accent"
            size="lg"
            className="mt-6 w-full"
            onClick={() => router.push("/login")}
          >
            Back to sign in
          </Button>
        </div>
      )}
    </AuthLayout>
  );
}
