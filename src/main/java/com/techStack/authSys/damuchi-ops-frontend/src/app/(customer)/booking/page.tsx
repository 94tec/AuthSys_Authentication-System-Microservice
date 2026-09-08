"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Calendar, ChevronRight, MapPin, Users } from "lucide-react";
import { toast } from "sonner";
import { bookingApi } from "@/lib/booking-api";
import {
  bookingStatusBadgeClass, bookingStatusLabel,
  formatCurrency, formatDateShort,
} from "@/lib/utils";
import type { ApiError, Booking } from "@/types";

function EmptyBookings() {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-full bg-savanna/10 text-savanna">
        <Calendar className="h-7 w-7" />
      </div>
      <h2 className="mt-5 font-display text-2xl font-semibold text-earth">
        No bookings yet
      </h2>
      <p className="mt-2 text-sm text-stone max-w-xs">
        You haven't booked any safaris. Explore our tours and find your wild place.
      </p>
      <Link href="/tours" className="btn-primary mt-6">
        Browse tours
      </Link>
    </div>
  );
}

export default function MyBookingsPage() {
  const [bookings, setBookings] = useState<Booking[]>([]);
  const [loading, setLoading]   = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await bookingApi.myBookings();
      setBookings(data);
    } catch (err) {
      toast.error((err as ApiError).message || "Couldn't load your bookings.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="skeleton h-8 w-48" />
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="card p-5 space-y-3">
            <div className="skeleton h-5 w-1/2" />
            <div className="skeleton h-4 w-1/3" />
            <div className="skeleton h-4 w-1/4" />
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-3xl font-bold text-earth">My bookings</h1>
        <p className="mt-1 text-sm text-stone">
          {bookings.length === 0
            ? "You have no bookings."
            : `${bookings.length} booking${bookings.length === 1 ? "" : "s"}`}
        </p>
      </div>

      {bookings.length === 0 ? (
        <EmptyBookings />
      ) : (
        <div className="space-y-4">
          {bookings.map((booking) => (
            <Link
              key={booking.id}
              href={`/bookings/${booking.id}`}
              className="card-hover flex items-center gap-4 p-5 group"
            >
              <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-savanna/10 text-savanna">
                <MapPin className="h-5 w-5" />
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <h3 className="font-semibold text-earth truncate">{booking.tourName}</h3>
                  <span className={bookingStatusBadgeClass(booking.status)}>
                    {bookingStatusLabel(booking.status)}
                  </span>
                </div>
                <div className="mt-1 flex items-center gap-4 text-sm text-stone">
                  <span className="flex items-center gap-1">
                    <Calendar className="h-3.5 w-3.5" />
                    {formatDateShort(booking.tourDate)}
                  </span>
                  <span className="flex items-center gap-1">
                    <Users className="h-3.5 w-3.5" />
                    {booking.travelerCount} traveler{booking.travelerCount === 1 ? "" : "s"}
                  </span>
                </div>
              </div>

              <div className="text-right shrink-0">
                <p className="font-mono font-semibold text-earth">
                  {formatCurrency(booking.totalPrice, booking.currency)}
                </p>
                <ChevronRight className="ml-auto mt-1 h-4 w-4 text-stone/50 group-hover:text-savanna transition-colors" />
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
