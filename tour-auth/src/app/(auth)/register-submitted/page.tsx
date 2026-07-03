import { AuthLayout } from "@/components/layout/auth-layout"
import { PassportStamp } from "@/components/auth/passport-stamp"
import { Card, CardContent } from "@/components/ui/card"
import Link from "next/link"

export default function RegisterSubmittedPage() {
  return (
    <AuthLayout>
      <Card>
        <CardContent className="pt-8 pb-8 flex flex-col items-center gap-6">
          <PassportStamp
            title="Request submitted"
            subtitle="An admin will review your application and get in touch via email."
          />

          <div className="w-full border-t border-border pt-5 text-center space-y-1">
            <p className="text-sm text-muted-foreground">Check your inbox for updates.</p>
            <Link href="/login" className="text-sm text-[#C9742F] hover:underline font-medium">
              Return to login
            </Link>
          </div>
        </CardContent>
      </Card>
    </AuthLayout>
  )
}
