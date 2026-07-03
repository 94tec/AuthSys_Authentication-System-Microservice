"use client";

import Link from "next/link";
import { Hourglass } from "lucide-react";
import { AuthLayout } from "@/components/auth/auth-layout";
import { Button } from "@/components/ui/button";

export default function PendingApprovalPage() {
  return (
    <AuthLayout
      eyebrow="Status"
      title="Your gear is packed. We're waiting on basecamp."
      subtitle="Account approvals typically clear within one business day."
    >
      <div className="flex flex-col items-center text-center">
        <div className="flex h-14 w-14 items-center justify-center rounded-full bg-warning/10 text-warning">
          <Hourglass className="h-6 w-6" />
        </div>

        <h2 className="mt-5 font-display text-2xl font-medium tracking-tight">
          Awaiting approval
        </h2>
        <p className="mt-2 text-sm text-muted-foreground">
          An admin needs to approve your account before you can sign in. We&apos;ll
          notify you by email the moment it&apos;s ready.
        </p>

        <Button asChild variant="outline" className="mt-7 w-full">
          <Link href="/login">Back to sign in</Link>
        </Button>
      </div>
    </AuthLayout>
  );
}
