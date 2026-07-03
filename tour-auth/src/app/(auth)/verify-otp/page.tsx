"use client"
import { useState, useCallback } from "react"
import { useRouter } from "next/navigation"
import { toast } from "sonner"

import { AuthLayout } from "@/components/layout/auth-layout"
import { OtpInput } from "@/components/auth/otp-input"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { authApi } from "@/lib/api/auth"
import { useAuthStore } from "@/lib/stores/auth.store"

export default function VerifyOtpPage() {
  const router = useRouter()
  const { tempToken, setSession } = useAuthStore()
  const [otp, setOtp] = useState("")
  const [loading, setLoading] = useState(false)
  const [resending, setResending] = useState(false)

  const handleVerify = useCallback(async () => {
    if (otp.length < 6 || !tempToken) return
    setLoading(true)
    try {
      const session = await authApi.verifyOtp({ otp, tempToken })
      setSession(session.user, session.tokens)
      router.push(session.user.status === "PENDING_SETUP" ? "/first-time-setup/step-1" : "/dashboard")
    } catch (err: any) {
      toast.error(err.message ?? "Invalid code.")
    } finally {
      setLoading(false)
    }
  }, [otp, tempToken, router, setSession])

  const handleResend = async () => {
    if (!tempToken) return
    setResending(true)
    try {
      await authApi.resendOtp(tempToken)
      toast.success("New code sent.")
    } catch {
      toast.error("Couldn't resend code.")
    } finally {
      setResending(false)
    }
  }

  return (
    <AuthLayout
      heading="Two-factor authentication"
      subheading="Enter the verification code sent to your registered email"
      showBackToLogin
    >
      <Card>
        <CardContent className="pt-8 pb-8 flex flex-col items-center gap-6">
          <OtpInput value={otp} onChange={setOtp} disabled={loading} />

          <Button
            className="w-full max-w-xs"
            onClick={handleVerify}
            disabled={otp.length < 6}
            loading={loading}
          >
            Verify & sign in
          </Button>

          <button
            type="button"
            onClick={handleResend}
            disabled={resending}
            className="text-sm text-muted-foreground hover:text-[#C9742F] transition-colors disabled:opacity-50"
          >
            {resending ? "Sending…" : "Resend code"}
          </button>
        </CardContent>
      </Card>
    </AuthLayout>
  )
}
