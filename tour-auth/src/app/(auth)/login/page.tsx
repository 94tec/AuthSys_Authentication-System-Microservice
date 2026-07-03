"use client"
import { useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { toast } from "sonner"
import { Eye, EyeOff } from "lucide-react"

import { AuthLayout } from "@/components/layout/auth-layout"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardFooter } from "@/components/ui/card"
import { loginSchema, type LoginFormData } from "@/lib/validations/auth"
import { authApi } from "@/lib/api/auth"
import { useAuthStore } from "@/lib/stores/auth.store"

export default function LoginPage() {
  const router = useRouter()
  const { setSession, setTempToken } = useAuthStore()
  const [showPw, setShowPw] = useState(false)

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<LoginFormData>({ resolver: zodResolver(loginSchema) })

  const onSubmit = async (data: LoginFormData) => {
    try {
      const res = await authApi.login(data)
      if (res.requiresOtp && res.tempToken) {
        setTempToken(res.tempToken)
        router.push("/verify-otp")
      } else if (res.session) {
        setSession(res.session.user, res.session.tokens)
        if (res.session.user.status === "PENDING_SETUP") {
          router.push("/first-time-setup/step-1")
        } else {
          router.push("/dashboard")
        }
      }
    } catch (err: any) {
      toast.error(err.message ?? "Login failed. Please try again.")
    }
  }

  return (
    <AuthLayout
      heading="Welcome back"
      subheading="Sign in to the Venture Tours staff portal"
    >
      <Card>
        <CardContent className="pt-6">
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="email">Email address</Label>
              <Input
                id="email"
                type="email"
                autoComplete="email"
                placeholder="you@venturetours.com"
                {...register("email")}
              />
              {errors.email && <p className="text-xs text-destructive">{errors.email.message}</p>}
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <Label htmlFor="password">Password</Label>
                <Link href="/forgot-password" className="text-xs text-[#C9742F] hover:underline">
                  Forgot password?
                </Link>
              </div>
              <div className="relative">
                <Input
                  id="password"
                  type={showPw ? "text" : "password"}
                  autoComplete="current-password"
                  placeholder="••••••••"
                  {...register("password")}
                  className="pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowPw((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                >
                  {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {errors.password && <p className="text-xs text-destructive">{errors.password.message}</p>}
            </div>

            <Button type="submit" className="w-full" loading={isSubmitting}>
              Sign in
            </Button>
          </form>
        </CardContent>

        <CardFooter className="justify-center border-t border-border pt-4">
          <p className="text-sm text-muted-foreground">
            Need access?{" "}
            <Link href="/register" className="text-[#C9742F] font-medium hover:underline">
              Request an account
            </Link>
          </p>
        </CardFooter>
      </Card>
    </AuthLayout>
  )
}
