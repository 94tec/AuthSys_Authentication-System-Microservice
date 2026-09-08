import Link from "next/link";
import { CheckCircle2 } from "lucide-react";

export default function RegistrationSubmittedPage() {
  return (
    <div className="flex min-h-[70vh] items-center justify-center px-4">
      <div className="max-w-md text-center">
        <div className="flex h-16 w-16 items-center justify-center rounded-full bg-green-100 text-green-600 mx-auto">
          <CheckCircle2 className="h-8 w-8" />
        </div>
        <h1 className="mt-5 font-display text-3xl font-bold text-earth">
          Request submitted
        </h1>
        <p className="mt-3 text-stone">
          Your account request has been received. Our team will review it and send you
          an email once it's approved — usually within one business day.
        </p>
        <div className="mt-6 h-0.5 w-16 bg-savanna mx-auto" />
        <Link href="/tours" className="btn-secondary mt-6 inline-flex">
          Browse tours in the meantime
        </Link>
      </div>
    </div>
  );
}
