"use client"
import { useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { useRouter } from "next/navigation"
import { toast } from "sonner"
import { Eye, EyeOff } from "lucide-react"

import { AuthLayout } from "@/components/layout/auth-layout"
import { TrailSteps } from "@/components/auth/trail-steps"
import { PasswordStrength } from "@/components/auth/password-strength"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent } from "@/components/ui/card"
import { changePasswordSchema, type ChangePasswordFormData } from "@/lib/validations/auth"
import { authApi } from "@/lib/api/auth"
import { useAuthStore } from "@/lib/stores/auth.store"

const SETUP_STEPS = [
  { label: "Set password", description: "Create a secure password" },
  { label: "Verify identity", description: "Enter your OTP code" },
  { label: "Complete setup", description: "You're all set" },
]

export default function SetupStep1Page() {
  const router = useRouter()
  const { setTempToken } = useAuthStore()
  const [showCurrent, setShowCurrent] = useState(false)
  const [showNew, setShowNew] = useState(false)

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors, isSubmitting },
  } = useForm<ChangePasswordFormData>({ resolver: zodResolver(changePasswordSchema) })

  const newPw = watch("newPassword") ?? ""

  const onSubmit = async (data: ChangePasswordFormData) => {
    try {
      const res = await authApi.changePassword(data)
      if (res.tempToken) setTempToken(res.tempToken)
      router.push("/first-time-setup/step-2")
    } catch (err: any) {
      toast.error(err.message ?? "Failed to update password.")
    }
  }

  return (
    <AuthLayout heading="Account setup" subheading="Complete these steps to activate your account">
      <TrailSteps steps={SETUP_STEPS} current={0} className="mb-6" />

      <Card>
        <CardContent className="pt-6">
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="currentPassword">Temporary password</Label>
              <div className="relative">
                <Input
                  id="currentPassword"
                  type={showCurrent ? "text" : "password"}
                  placeholder="From your invite email"
                  {...register("currentPassword")}
                  className="pr-10"
                />
                <button type="button" onClick={() => setShowCurrent((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                  {showCurrent ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {errors.currentPassword && <p className="text-xs text-destructive">{errors.currentPassword.message}</p>}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="newPassword">New password</Label>
              <div className="relative">
                <Input
                  id="newPassword"
                  type={showNew ? "text" : "password"}
                  placeholder="Create a strong password"
                  {...register("newPassword")}
                  className="pr-10"
                />
                <button type="button" onClick={() => setShowNew((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                  {showNew ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <PasswordStrength password={newPw} />
              {errors.newPassword && <p className="text-xs text-destructive">{errors.newPassword.message}</p>}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="confirmPassword">Confirm password</Label>
              <Input
                id="confirmPassword"
                type="password"
                placeholder="Repeat new password"
                {...register("confirmPassword")}
              />
              {errors.confirmPassword && <p className="text-xs text-destructive">{errors.confirmPassword.message}</p>}
            </div>

            <Button type="submit" className="w-full" loading={isSubmitting}>
              Continue to verification →
            </Button>
          </form>
        </CardContent>
      </Card>
    </AuthLayout>
  )
}
