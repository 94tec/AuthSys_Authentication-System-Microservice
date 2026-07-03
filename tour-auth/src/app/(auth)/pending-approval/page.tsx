"use client"
import { AuthLayout } from "@/components/layout/auth-layout"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Clock } from "lucide-react"
import { useAuthStore } from "@/lib/stores/auth.store"
import { useRouter } from "next/navigation"

export default function PendingApprovalPage() {
  const { clearSession } = useAuthStore()
  const router = useRouter()

  return (
    <AuthLayout
      heading="Awaiting approval"
      subheading="Your account is being reviewed by an administrator"
    >
      <Card>
        <CardContent className="pt-8 pb-8 flex flex-col items-center gap-6">
          <div className="w-20 h-20 rounded-full bg-amber-100 border-2 border-amber-300 flex items-center justify-center">
            <Clock className="w-8 h-8 text-amber-600" strokeWidth={1.5} />
          </div>

          <div className="text-center space-y-2 max-w-xs">
            <p className="text-sm text-muted-foreground">
              You'll receive an email once your account has been approved. This usually takes up to 1 business day.
            </p>
          </div>

          <div className="w-full border-t border-border pt-5 flex flex-col gap-2">
            <Button
              variant="outline"
              className="w-full"
              onClick={() => { clearSession(); router.push("/login") }}
            >
              Sign out
            </Button>
          </div>
        </CardContent>
      </Card>
    </AuthLayout>
  )
}
