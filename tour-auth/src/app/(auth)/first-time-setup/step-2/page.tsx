"use client"
import { useState, useCallback } from "react"
import { useRouter } from "next/navigation"
import { toast } from "sonner"

import { AuthLayout } from "@/components/layout/auth-layout"
import { TrailSteps } from "@/components/auth/trail-steps"
import { OtpInput } from "@/components/auth/otp-input"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { authApi } from "@/lib/api/auth"
import { useAuthStore } from "@/lib/stores/auth.store"

const SETUP_STEPS = [
  { label: "Set password" },
  { label: "Verify identity" },
  { label: "Complete setup" },
]

export default function SetupStep2Page() {
  const router = useRouter()
  const { tempToken, setSession } = useAuthStore()
  const [otp, setOtp] = useState("")
  const [loading, setLoading] = useState(false)
  const [resending, setResending] = useState(false)

  const handleVerify = useCallback(async () => {
    if (otp.length < 6) return
    if (!tempToken) { toast.error("Session expired. Please start again."); router.push("/login"); return }
    setLoading(true)
    try {
      const session = await authApi.verifyOtp({ otp, tempToken })
      setSession(session.user, session.tokens)
      router.push("/first-time-setup/step-3")
    } catch (err: any) {
      toast.error(err.message ?? "Invalid code. Please try again.")
    } finally {
      setLoading(false)
    }
  }, [otp, tempToken, router, setSession])

  const handleResend = async () => {
    if (!tempToken) return
    setResending(true)
    try {
      await authApi.resendOtp(tempToken)
      toast.success("New code sent to your email.")
    } catch {
      toast.error("Couldn't resend code. Try again shortly.")
    } finally {
      setResending(false)
    }
  }

  return (
    <AuthLayout heading="Verify your identity" subheading="Enter the 6-digit code sent to your email">
      <TrailSteps steps={SETUP_STEPS} current={1} className="mb-6" />

      <Card>
        <CardContent className="pt-8 pb-8 flex flex-col items-center gap-6">
          <OtpInput value={otp} onChange={setOtp} disabled={loading} />

          <Button
            className="w-full max-w-xs"
            onClick={handleVerify}
            disabled={otp.length < 6}
            loading={loading}
          >
            Verify code
          </Button>

          <button
            type="button"
            onClick={handleResend}
            disabled={resending}
            className="text-sm text-muted-foreground hover:text-[#C9742F] transition-colors disabled:opacity-50"
          >
            {resending ? "Sending…" : "Didn't get a code? Resend"}
          </button>
        </CardContent>
      </Card>
    </AuthLayout>
  )
}
