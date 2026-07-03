"use client"
import { useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { toast } from "sonner"

import { AuthLayout } from "@/components/layout/auth-layout"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent } from "@/components/ui/card"
import { PassportStamp } from "@/components/auth/passport-stamp"
import { forgotPasswordSchema, type ForgotPasswordFormData } from "@/lib/validations/auth"
import { authApi } from "@/lib/api/auth"

export default function ForgotPasswordPage() {
  const [submitted, setSubmitted] = useState(false)

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<ForgotPasswordFormData>({ resolver: zodResolver(forgotPasswordSchema) })

  const onSubmit = async (data: ForgotPasswordFormData) => {
    try {
      await authApi.forgotPassword(data)
    } catch {
      // Silently swallow — never reveal whether email exists
    } finally {
      setSubmitted(true) // Always show success to avoid email enumeration
    }
  }

  return (
    <AuthLayout
      heading="Reset your password"
      subheading="We'll send a reset link if that email has an account"
      showBackToLogin
    >
      <Card>
        <CardContent className="pt-6 pb-6">
          {submitted ? (
            <div className="py-4 flex flex-col items-center gap-4">
              <PassportStamp
                title="Check your inbox"
                subtitle="If that address is registered, you'll receive a reset link within a few minutes."
              />
            </div>
          ) : (
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="email">Email address</Label>
                <Input id="email" type="email" placeholder="you@venturetours.com" {...register("email")} />
                {errors.email && <p className="text-xs text-destructive">{errors.email.message}</p>}
              </div>
              <Button type="submit" className="w-full" loading={isSubmitting}>
                Send reset link
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </AuthLayout>
  )
}
