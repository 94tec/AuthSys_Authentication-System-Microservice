"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { ChevronLeft, Calendar, Users, CreditCard, AlertCircle } from "lucide-react";
import { toast } from "sonner";
import { bookingApi } from "@/lib/booking-api";
import {
  bookingStatusBadgeClass, bookingStatusLabel,
  formatCurrency, formatDate, formatDateTime,
} from "@/lib/utils";
import type { ApiError, Booking } from "@/types";

export default function BookingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [booking, setBooking]     = useState<Booking | null>(null);
  const [loading, setLoading]     = useState(true);
  const [cancelling, setCancelling] = useState(false);
  const [showCancel, setShowCancel] = useState(false);

  const load = useCallback(async () => {
    try {
      const data = await bookingApi.myBookingById(id);
      setBooking(data);
    } catch (err) {
      toast.error((err as ApiError).message || "Booking not found.");
      router.replace("/bookings");
    } finally {
      setLoading(false);
    }
  }, [id, router]);

  useEffect(() => { load(); }, [load]);

  async function handleCancel() {
    if (!booking) return;
    setCancelling(true);
    try {
      const updated = await bookingApi.cancelMyBooking(booking.id);
      setBooking(updated);
      setShowCancel(false);
      toast.success("Booking cancelled.");
    } catch (err) {
      toast.error((err as ApiError).message || "Cancellation failed.");
    } finally {
      setCancelling(false);
    }
  }

  if (loading) {
    return (
      <div className="max-w-2xl space-y-4">
        <div className="skeleton h-6 w-32" />
        <div className="card p-6 space-y-4">
          <div className="skeleton h-7 w-1/2" />
          <div className="skeleton h-4 w-1/3" />
          <div className="skeleton h-4 w-1/4" />
          <div className="skeleton h-4 w-full" />
        </div>
      </div>
    );
  }

  if (!booking) return null;

  const canCancel = booking.status === "PENDING_PAYMENT" || booking.status === "CONFIRMED";

  return (
    <div className="max-w-2xl space-y-6 animate-fade-in">
      <button onClick={() => router.back()} className="btn-ghost -ml-2 text-sm">
        <ChevronLeft className="h-4 w-4" />
        My bookings
      </button>

      {/* Main card */}
      <div className="card overflow-hidden">
        {/* Horizon rule at top of card */}
        <div className="h-0.5 bg-savanna" />
        <div className="p-6">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <p className="eyebrow text-xs mb-1">Booking reference</p>
              <p className="data-value text-xs text-stone">{booking.id}</p>
              <h1 className="mt-3 font-display text-2xl font-bold text-earth">
                {booking.tourName}
              </h1>
            </div>
            <span className={`${bookingStatusBadgeClass(booking.status)} text-sm px-3 py-1`}>
              {bookingStatusLabel(booking.status)}
            </span>
          </div>

          <div className="mt-6 grid gap-4 sm:grid-cols-2">
            <Detail icon={<Calendar className="h-4 w-4" />} label="Tour date">
              {formatDate(booking.tourDate)}
            </Detail>
            <Detail icon={<Users className="h-4 w-4" />} label="Travelers">
              {booking.travelerCount} person{booking.travelerCount === 1 ? "" : "s"}
            </Detail>
            <Detail icon={<CreditCard className="h-4 w-4" />} label="Total">
              <span className="font-mono font-semibold text-savanna">
                {formatCurrency(booking.totalPrice, booking.currency)}
              </span>
              {" "}
              <span className="text-xs text-stone">
                ({formatCurrency(booking.pricePerTraveler, booking.currency)}/person)
              </span>
            </Detail>
            {booking.paymentReference && (
              <Detail icon={<CreditCard className="h-4 w-4" />} label="Payment ref">
                <span className="data-value">{booking.paymentReference}</span>
              </Detail>
            )}
          </div>

          {/* Travelers */}
          {booking.travelers?.length > 0 && (
            <div className="mt-6">
              <h2 className="text-sm font-semibold text-earth mb-3">Travelers</h2>
              <div className="space-y-2">
                {booking.travelers.map((t) => (
                  <div key={t.id} className="flex items-center gap-3 rounded-lg bg-dust px-3 py-2.5 text-sm">
                    <div className="flex h-7 w-7 items-center justify-center rounded-full bg-savanna/10 text-savanna text-xs font-medium">
                      {t.fullName.charAt(0).toUpperCase()}
                    </div>
                    <span className="text-earth">{t.fullName}</span>
                    {t.leadTraveler && (
                      <span className="ml-auto text-xs text-stone">Lead</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Special requests */}
          {booking.specialRequests && (
            <div className="mt-6 rounded-lg bg-dust p-4 text-sm">
              <p className="font-medium text-earth mb-1">Special requests</p>
              <p className="text-stone">{booking.specialRequests}</p>
            </div>
          )}

          {/* Cancellation info */}
          {booking.cancelledAt && (
            <div className="mt-6 rounded-lg bg-red-50 border border-red-100 p-4 text-sm">
              <p className="font-medium text-red-700 flex items-center gap-2">
                <AlertCircle className="h-4 w-4" />
                Cancelled {formatDateTime(booking.cancelledAt)}
              </p>
              {booking.cancellationReason && (
                <p className="mt-1 text-red-600">{booking.cancellationReason}</p>
              )}
            </div>
          )}

          <p className="mt-6 text-xs text-stone">
            Booked {formatDateTime(booking.createdDate)}
          </p>
        </div>
      </div>

      {/* Cancel action */}
      {canCancel && !showCancel && (
        <button onClick={() => setShowCancel(true)} className="btn-secondary text-sm">
          Cancel booking
        </button>
      )}

      {showCancel && (
        <div className="card border-red-200 p-5">
          <p className="font-medium text-earth">Cancel this booking?</p>
          <p className="mt-1 text-sm text-stone">This action cannot be undone.</p>
          <div className="mt-4 flex gap-3">
            <button
              onClick={handleCancel}
              disabled={cancelling}
              className="btn-danger text-sm"
            >
              {cancelling ? "Cancelling…" : "Yes, cancel"}
            </button>
            <button
              onClick={() => setShowCancel(false)}
              className="btn-secondary text-sm"
            >
              Keep booking
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function Detail({ icon, label, children }: {
  icon: React.ReactNode;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-2.5">
      <span className="mt-0.5 text-savanna">{icon}</span>
      <div>
        <p className="text-xs text-stone">{label}</p>
        <p className="text-sm text-earth">{children}</p>
      </div>
    </div>
  );
}
