"use client"
import { useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { useRouter, useSearchParams } from "next/navigation"
import { toast } from "sonner"
import { Eye, EyeOff } from "lucide-react"

import { AuthLayout } from "@/components/layout/auth-layout"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent } from "@/components/ui/card"
import { PasswordStrength } from "@/components/auth/password-strength"
import { resetPasswordSchema, type ResetPasswordFormData } from "@/lib/validations/auth"
import { authApi } from "@/lib/api/auth"

export default function ResetPasswordPage() {
  const router = useRouter()
  const params = useSearchParams()
  const token = params.get("token") ?? ""
  const [showPw, setShowPw] = useState(false)

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors, isSubmitting },
  } = useForm<ResetPasswordFormData>({ resolver: zodResolver(resetPasswordSchema) })

  const pw = watch("newPassword") ?? ""

  const onSubmit = async (data: ResetPasswordFormData) => {
    if (!token) { toast.error("Invalid or expired reset link."); return }
    try {
      await authApi.resetPassword({ ...data, token })
      toast.success("Password reset! Please sign in with your new password.")
      router.push("/login")
    } catch (err: any) {
      toast.error(err.message ?? "Reset failed. The link may have expired.")
    }
  }

  return (
    <AuthLayout
      heading="Create new password"
      subheading="Choose a strong password for your account"
      showBackToLogin
    >
      <Card>
        <CardContent className="pt-6">
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="newPassword">New password</Label>
              <div className="relative">
                <Input
                  id="newPassword"
                  type={showPw ? "text" : "password"}
                  placeholder="Create a strong password"
                  {...register("newPassword")}
                  className="pr-10"
                />
                <button type="button" onClick={() => setShowPw((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                  {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <PasswordStrength password={pw} />
              {errors.newPassword && <p className="text-xs text-destructive">{errors.newPassword.message}</p>}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="confirmPassword">Confirm password</Label>
              <Input id="confirmPassword" type="password" placeholder="Repeat new password" {...register("confirmPassword")} />
              {errors.confirmPassword && <p className="text-xs text-destructive">{errors.confirmPassword.message}</p>}
            </div>

            <Button type="submit" className="w-full" loading={isSubmitting}>
              Reset password
            </Button>
          </form>
        </CardContent>
      </Card>
    </AuthLayout>
  )
}
