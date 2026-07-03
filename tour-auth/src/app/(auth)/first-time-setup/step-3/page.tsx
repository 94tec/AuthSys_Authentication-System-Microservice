"use client"
import { useEffect } from "react"
import { useRouter } from "next/navigation"

import { AuthLayout } from "@/components/layout/auth-layout"
import { TrailSteps } from "@/components/auth/trail-steps"
import { PassportStamp } from "@/components/auth/passport-stamp"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { useAuthStore } from "@/lib/stores/auth.store"

const SETUP_STEPS = [
  { label: "Set password" },
  { label: "Verify identity" },
  { label: "Complete setup" },
]

export default function SetupStep3Page() {
  const router = useRouter()
  const { user } = useAuthStore()

  // Auto-redirect after 4s
  useEffect(() => {
    const t = setTimeout(() => router.push("/dashboard"), 4000)
    return () => clearTimeout(t)
  }, [router])

  return (
    <AuthLayout>
      <TrailSteps steps={SETUP_STEPS} current={3} className="mb-6" />

      <Card>
        <CardContent className="pt-10 pb-10 flex flex-col items-center gap-6">
          <PassportStamp
            title={`Welcome, ${user?.firstName ?? "Explorer"}!`}
            subtitle="Your account is fully set up. Redirecting to your dashboard…"
          />
          <Button variant="clay" onClick={() => router.push("/dashboard")} className="mt-2">
            Go to dashboard now →
          </Button>
        </CardContent>
      </Card>
    </AuthLayout>
  )
}
