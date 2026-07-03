"use client";

import Link from "next/link"
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Eye, EyeOff, LogIn } from "lucide-react";
import { toast } from "sonner";

import { AuthLayout } from "@/components/auth/auth-layout";
import { GoogleButton } from "@/components/auth/google-button";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Form, FormControl, FormField, FormItem, FormLabel, FormMessage,
} from "@/components/ui/form";
import { loginSchema, type LoginFormValues } from "@/lib/validations/auth";
import { authApi } from "@/lib/auth-api";
import { useAuthStore } from "@/store/auth-store";
import type { ApiError } from "@/types/auth";

// Navigate after yielding to the browser event loop so the cookie
// written by setTokens() is fully committed before the request fires.
function safeNavigate(path: string) {
  requestAnimationFrame(() => {
    setTimeout(() => { window.location.href = path; }, 50);
  });
}

export default function LoginPage() {
  const [showPw, setShowPw] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { setTokens, setTempToken, setUser } = useAuthStore();

  const router = useRouter();

  const form = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: "", password: "" },
  });

  async function onSubmit(values: LoginFormValues) {
    setIsSubmitting(true);
    try {
      const res = await authApi.login(values);

      // ── LoginResponse boolean flags (from Java record) ────────
      //   success, firstTimeLogin, requiresOtp, rateLimited
      //   temporaryToken, userId, accessToken, refreshToken, user, message

      if (res.rateLimited) {
        toast.warning(res.message || "Too many attempts. Try again later.");
        setIsSubmitting(false);
        return;
      }

      if (res.firstTimeLogin) {
        // FirstTimeSetupController expects temporaryToken as X-Temp-Token header
        if (res.temporaryToken) setTempToken(res.temporaryToken);
        toast.info("First-time setup required — set your permanent password.");
        router.push("/setup/password");   // ⬅ client-side push, keeps JS context aliveafeNavigate("/setup/password");
        return;
      }

      if (res.requiresOtp) {
        // OtpController expects temporaryToken as X-Temp-Token header
        if (res.temporaryToken) setTempToken(res.temporaryToken);
        toast.info("Verification code sent to your phone.");
        router.push("/login/verify");
        return;
      }

      if (res.success && res.accessToken) {
        setTokens({
          accessToken: res.accessToken,
          refreshToken: res.refreshToken ?? "",
        });
        console.log("[LoginPage] after setTokens, sessionStorage:", sessionStorage.getItem("authsys-session"));
        if (res.user) setUser(res.user);
        toast.success("Welcome back");
        safeNavigate("/dashboard");
        return;
      }

      // success=true but no accessToken — shouldn't happen, but guard it
      if (res.success && !res.accessToken) {
        toast.error(
            "Server returned success but no token. " +
            `Message: ${res.message}`
        );
        setIsSubmitting(false);
        return;
      }

      // success=false without a known flag — account locked, rejected, etc.
      toast.error(res.message || "Sign in failed. Contact your admin.");
      setIsSubmitting(false);

    } catch (err) {
      const e = err as ApiError;
      // status 0 = CORS or backend down; status 401 = bad credentials
      if (e.status === 0) {
        toast.error(
            "Can't reach the server. Make sure authSys is running on port 8001 " +
            "and CORS allows http://localhost:3000."
        );
      } else {
        toast.error(e.message || "Couldn't sign in. Check your details and try again.");
      }
      setIsSubmitting(false);
    }
  }

  return (
      <AuthLayout
          eyebrow="Staff Portal"
          title="Every great trail starts with the right credentials."
          subtitle="Sign in to manage tours, review approvals, and keep the expedition running."
      >
        <div className="mb-7">
          <h2 className="font-display text-2xl font-medium tracking-tight">Sign in</h2>
          <p className="mt-1.5 text-sm text-muted-foreground">
            Internal access only. All sessions are logged.
          </p>
        </div>

        <GoogleButton label="Sign in with Google" />

        <div className="my-5 flex items-center gap-3">
          <div className="flex-1 border-t border-border" />
          <span className="text-xs text-muted-foreground">or with email</span>
          <div className="flex-1 border-t border-border" />
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

            <FormField
                control={form.control}
                name="password"
                render={({ field }) => (
                    <FormItem>
                      <div className="flex items-center justify-between">
                        <FormLabel>Password</FormLabel>
                        <Link href="/forgot-password" className="text-xs font-medium text-accent hover:underline">
                          Forgot password?
                        </Link>
                      </div>
                      <FormControl>
                        <div className="relative">
                          <Input
                              type={showPw ? "text" : "password"}
                              placeholder="••••••••••"
                              autoComplete="current-password"
                              hasError={!!form.formState.errors.password}
                              className="pr-10"
                              {...field}
                          />
                          <button
                              type="button"
                              onClick={() => setShowPw((v) => !v)}
                              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                              aria-label={showPw ? "Hide password" : "Show password"}
                          >
                            {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                          </button>
                        </div>
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
              {!isSubmitting && <LogIn className="h-4 w-4" />}
              Sign in
            </Button>
          </form>
        </Form>

        <p className="mt-7 text-center text-sm text-muted-foreground">
          New to the team?{" "}
          <Link href="/register" className="font-medium text-accent hover:underline">
            Request access
          </Link>
        </p>
      </AuthLayout>
  );
}