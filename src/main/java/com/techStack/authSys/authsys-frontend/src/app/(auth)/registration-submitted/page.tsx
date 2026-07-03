"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { MailCheck } from "lucide-react";
import { AuthLayout } from "@/components/auth/auth-layout";
import { Button } from "@/components/ui/button";

export default function RegistrationSubmittedPage() {
  const params = useSearchParams();
  const email = params.get("email");

  return (
    <AuthLayout
      eyebrow="Almost there"
      title="Your request is in basecamp's queue."
      subtitle="Every new team member is reviewed before their first trail. We don't cut corners on who holds the keys."
    >
      <div className="flex flex-col items-center text-center">
        <div className="flex h-14 w-14 items-center justify-center rounded-full bg-accent/10 text-accent">
          <MailCheck className="h-6 w-6" />
        </div>

        <h2 className="mt-5 font-display text-2xl font-medium tracking-tight">
          Request submitted
        </h2>
        <p className="mt-2 text-sm text-muted-foreground">
          {email ? (
            <>
              We&apos;ll email <span className="font-medium text-foreground">{email}</span>{" "}
              once an admin reviews your request.
            </>
          ) : (
            "We'll email you once an admin reviews your request."
          )}
        </p>

        <Button asChild variant="outline" className="mt-7 w-full">
          <Link href="/login">Back to sign in</Link>
        </Button>
      </div>
    </AuthLayout>
  );
}
