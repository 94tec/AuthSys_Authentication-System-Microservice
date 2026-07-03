"use client"
import { useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { toast } from "sonner"
import { Settings, Eye, EyeOff, Lock } from "lucide-react"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { PasswordStrength } from "@/components/auth/password-strength"
import { changePasswordSchema, type ChangePasswordFormData } from "@/lib/validations/auth"
import { authApi } from "@/lib/api/auth"
import { useAuthStore } from "@/lib/stores/auth.store"

export default function SettingsPage() {
  const { user } = useAuthStore()
  const [showCurrent, setShowCurrent] = useState(false)
  const [showNew, setShowNew] = useState(false)

  const {
    register,
    handleSubmit,
    watch,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<ChangePasswordFormData>({ resolver: zodResolver(changePasswordSchema) })

  const newPw = watch("newPassword") ?? ""

  const onSubmit = async (data: ChangePasswordFormData) => {
    try {
      await authApi.changePassword(data)
      toast.success("Password updated successfully.")
      reset()
    } catch (err: any) {
      toast.error(err.message ?? "Failed to update password.")
    }
  }

  return (
    <div className="space-y-6 animate-fade-up max-w-2xl">
      {/* Header */}
      <div className="flex items-center gap-2">
        <Settings className="w-5 h-5 text-[#C9742F]" />
        <h2 className="font-display text-xl font-semibold">Settings</h2>
      </div>

      {/* Profile info */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Profile</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4">
            <div className="w-14 h-14 rounded-full bg-[#3D5A4C]/15 flex items-center justify-center text-lg font-bold text-[#3D5A4C]">
              {user?.firstName?.[0]}{user?.lastName?.[0]}
            </div>
            <div>
              <p className="font-semibold">{user?.firstName} {user?.lastName}</p>
              <p className="text-sm text-muted-foreground">{user?.email}</p>
              <div className="flex gap-2 mt-1.5">
                <Badge variant={user?.role === "ADMIN" ? "clay" : "moss"}>{user?.role}</Badge>
                <Badge variant="active">{user?.status}</Badge>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Change password */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Lock className="w-4 h-4 text-muted-foreground" />
            <CardTitle className="text-base">Change Password</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="currentPassword">Current password</Label>
              <div className="relative">
                <Input
                  id="currentPassword"
                  type={showCurrent ? "text" : "password"}
                  placeholder="Your current password"
                  {...register("currentPassword")}
                  className="pr-10"
                />
                <button type="button" onClick={() => setShowCurrent(v => !v)}
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
                <button type="button" onClick={() => setShowNew(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                  {showNew ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <PasswordStrength password={newPw} />
              {errors.newPassword && <p className="text-xs text-destructive">{errors.newPassword.message}</p>}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="confirmPassword">Confirm new password</Label>
              <Input
                id="confirmPassword"
                type="password"
                placeholder="Repeat new password"
                {...register("confirmPassword")}
              />
              {errors.confirmPassword && <p className="text-xs text-destructive">{errors.confirmPassword.message}</p>}
            </div>

            <div className="pt-1">
              <Button type="submit" variant="clay" loading={isSubmitting}>
                Update password
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
