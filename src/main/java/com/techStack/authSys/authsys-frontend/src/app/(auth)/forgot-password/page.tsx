"use client";

import Link from "next/link";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Mail, ArrowLeft } from "lucide-react";
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
} from "@/components/ui/form";
import {
  forgotPasswordSchema,
  type ForgotPasswordFormValues,
} from "@/lib/validations/auth";
import { authApi } from "@/lib/auth-api";
import type { ApiError } from "@/types/auth";

export default function ForgotPasswordPage() {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);

  const form = useForm<ForgotPasswordFormValues>({
    resolver: zodResolver(forgotPasswordSchema),
    defaultValues: { email: "" },
  });

  async function onSubmit(values: ForgotPasswordFormValues) {
    setIsSubmitting(true);
    try {
      await authApi.forgotPassword(values);
      setIsSubmitted(true);
    } catch (err) {
      // Intentionally generic — never reveal whether an email exists in the system
      setIsSubmitted(true);
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <AuthLayout
      eyebrow="Account recovery"
      title="Lost your way back? Let's get you a new trail marker."
      subtitle="We'll send a secure link to reset your password if the email matches an account."
    >
      {!isSubmitted ? (
        <>
          <div className="mb-7">
            <h2 className="font-display text-2xl font-medium tracking-tight">
              Reset your password
            </h2>
            <p className="mt-1.5 text-sm text-muted-foreground">
              Enter the email linked to your account.
            </p>
          </div>

          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-5">
              <FormField
                control={form.control}
                name="email"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Email</FormLabel>
                    <FormControl>
                      <Input
                        type="email"
                        placeholder="you@company.com"
                        autoComplete="email"
                        hasError={!!form.formState.errors.email}
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
                {!isSubmitting && <Mail className="h-4 w-4" />}
                Send reset link
              </Button>
            </form>
          </Form>
        </>
      ) : (
        <div className="flex flex-col items-center py-4 text-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-full bg-accent/10 text-accent">
            <Mail className="h-6 w-6" />
          </div>
          <h2 className="mt-5 font-display text-2xl font-medium tracking-tight">
            Check your email
          </h2>
          <p className="mt-2 text-sm text-muted-foreground">
            If that email matches an account, a reset link is on its way.
          </p>
        </div>
      )}

      <Link
        href="/login"
        className="mt-7 flex items-center justify-center gap-1.5 text-sm font-medium text-accent hover:underline"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        Back to sign in
      </Link>
    </AuthLayout>
  );
}
