"use client";

import { useState } from "react";
import { useRouter, usePathname } from "next/navigation";
import { MessageCircle, X, LoaderCircle } from "lucide-react";
import { toast } from "sonner";
import { useAuthStore } from "@/store/auth-store";
import { tourApi } from "@/lib/tour-api";

interface EnquireButtonProps {
  tourId: string;
  tourName: string;
  className?: string;
}

export function EnquireButton({ tourId, tourName, className }: EnquireButtonProps) {
  const router = useRouter();
  const pathname = usePathname();
  const accessToken = useAuthStore((s) => s.accessToken);
  const user = useAuthStore((s) => s.user);
  const [open, setOpen] = useState(false);

  function handleClick(e: React.MouseEvent) {
    e.preventDefault();
    e.stopPropagation(); // important if this sits inside a <Link> card

    if (!accessToken) {
      router.push(`/login-required?next=${encodeURIComponent(pathname)}`);
      return;
    }
    setOpen(true);
  }

  return (
    <>
      <button
        onClick={handleClick}
        className={className ?? "btn-secondary text-sm px-4 py-2"}
        aria-haspopup="dialog"
      >
        <MessageCircle className="h-4 w-4" />
        Enquire
      </button>

      {open && (
        <EnquiryModal
          tourId={tourId}
          tourName={tourName}
          defaultEmail={user?.email}
          onClose={() => setOpen(false)}
        />
      )}
    </>
  );
}

function EnquiryModal({
  tourId,
  tourName,
  defaultEmail,
  onClose,
}: {
  tourId: string;
  tourName: string;
  defaultEmail?: string;
  onClose: () => void;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [form, setForm] = useState({
    fullName: "",
    email: defaultEmail ?? "",
    phone: "",
    preferredDate: "",
    numberOfGuests: "",
    message: "",
  });

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    try {
      await tourApi.enquire(tourId, {
        fullName: form.fullName,
        email: form.email,
        phone: form.phone || undefined,
        preferredDate: form.preferredDate || undefined,
        numberOfGuests: form.numberOfGuests ? Number(form.numberOfGuests) : undefined,
        message: form.message || undefined,
      });
      toast.success("Enquiry sent — our team will be in touch shortly.");
      onClose();
    } catch (err: any) {
      toast.error(err?.response?.data?.message ?? "Couldn't send your enquiry. Try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="enquiry-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      onClick={onClose}
    >
      <div
        className="card w-full max-w-md p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-4">
          <h2 id="enquiry-title" className="font-display text-xl font-semibold text-earth">
            Enquire about {tourName}
          </h2>
          <button onClick={onClose} aria-label="Close" className="btn-ghost p-1">
            <X className="h-4 w-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3">
          <input
            required
            placeholder="Full name"
            className="input w-full"
            value={form.fullName}
            onChange={(e) => setForm({ ...form, fullName: e.target.value })}
          />
          <input
            required
            type="email"
            placeholder="Email"
            className="input w-full"
            value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
          />
          <input
            placeholder="Phone (optional)"
            className="input w-full"
            value={form.phone}
            onChange={(e) => setForm({ ...form, phone: e.target.value })}
          />
          <div className="grid grid-cols-2 gap-3">
            <input
              type="date"
              className="input w-full"
              value={form.preferredDate}
              onChange={(e) => setForm({ ...form, preferredDate: e.target.value })}
            />
            <input
              type="number"
              min={1}
              placeholder="Guests"
              className="input w-full"
              value={form.numberOfGuests}
              onChange={(e) => setForm({ ...form, numberOfGuests: e.target.value })}
            />
          </div>
          <textarea
            placeholder="Anything specific you'd like us to know?"
            rows={3}
            className="input w-full"
            value={form.message}
            onChange={(e) => setForm({ ...form, message: e.target.value })}
          />
          <button type="submit" disabled={submitting} className="btn-primary w-full justify-center">
            {submitting ? <LoaderCircle className="h-4 w-4 animate-spin" /> : "Send enquiry"}
          </button>
        </form>
      </div>
    </div>
  );
}