"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { UserPlus } from "lucide-react";
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
import { registerSchema, type RegisterFormValues } from "@/lib/validations/auth";
import { authApi } from "@/lib/auth-api";
import type { ApiError } from "@/types/auth";

export default function RegisterPage() {
  const router = useRouter();
  const [isSubmitting, setIsSubmitting] = useState(false);

  const form = useForm<RegisterFormValues>({
    resolver: zodResolver(registerSchema),
    defaultValues: {
      firstName: "",
      lastName: "",
      email: "",
      phoneNumber: "",
      password: "",
      confirmPassword: "",
    },
  });

  async function onSubmit(values: RegisterFormValues) {
    setIsSubmitting(true);
    try {
      const { confirmPassword, ...payload } = values;
      const response = await authApi.register(payload);
      toast.success("Request submitted");
      router.push(`/registration-submitted?email=${encodeURIComponent(values.email)}`);
    } catch (err) {
      const apiError = err as ApiError;
      toast.error(apiError.message || "Registration failed. Try again.");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <AuthLayout
      eyebrow="Join the team"
      title="Request your place at basecamp."
      subtitle="New accounts are reviewed by an admin before activation, so your access stays secure from day one."
    >
      <div className="mb-7">
        <h2 className="font-display text-2xl font-medium tracking-tight">
          Request access
        </h2>
        <p className="mt-1.5 text-sm text-muted-foreground">
          Fill in your details. An admin will review your request.
        </p>
      </div>

      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <FormField
              control={form.control}
              name="firstName"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>First name</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="Asha"
                      autoComplete="given-name"
                      hasError={!!form.formState.errors.firstName}
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="lastName"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Last name</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="Mwangi"
                      autoComplete="family-name"
                      hasError={!!form.formState.errors.lastName}
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

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

          <FormField
            control={form.control}
            name="phoneNumber"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Phone number</FormLabel>
                <FormControl>
                  <Input
                    type="tel"
                    placeholder="+254712345678"
                    autoComplete="tel"
                    hasError={!!form.formState.errors.phoneNumber}
                    {...field}
                  />
                </FormControl>
                <FormDescription>Used for OTP verification.</FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="password"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Password</FormLabel>
                <FormControl>
                  <Input
                    type="password"
                    placeholder="••••••••••"
                    autoComplete="new-password"
                    hasError={!!form.formState.errors.password}
                    {...field}
                  />
                </FormControl>
                <FormDescription>
                  At least 10 characters, with a mix of cases, numbers, and symbols.
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
            {!isSubmitting && <UserPlus className="h-4 w-4" />}
            Submit request
          </Button>
        </form>
      </Form>

      <p className="mt-6 text-center text-sm text-muted-foreground">
        Already have access?{" "}
        <Link href="/login" className="font-medium text-accent hover:underline">
          Sign in
        </Link>
      </p>
    </AuthLayout>
  );
}
