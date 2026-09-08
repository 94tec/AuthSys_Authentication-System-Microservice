"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  MapPin, Clock, Users, ChevronLeft,
  CheckCircle2, XCircle, Calendar
} from "lucide-react";
import { tourApi } from "@/lib/tour-api";
import { formatCurrency } from "@/lib/utils";
import type { TourPublic } from "@/types/index-types";

function Skeleton({ className }: { className?: string }) {
  return <div className={`skeleton ${className ?? ""}`} />;
}

export default function TourDetailPage() {
  const { slug } = useParams<{ slug: string }>();
  const router = useRouter();
  const [tour, setTour] = useState<TourPublic | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    tourApi.getBySlug(slug)
      .then(setTour)
      .catch(() => setError("Tour not found."))
      .finally(() => setLoading(false));
  }, [slug]);

  if (loading) {
    return (
      <div className="mx-auto max-w-4xl px-4 sm:px-6 py-10 space-y-6">
        <Skeleton className="h-72 w-full rounded-2xl" />
        <Skeleton className="h-8 w-2/3" />
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-4 w-5/6" />
      </div>
    );
  }

  if (error || !tour) {
    return (
      <div className="flex min-h-[50vh] flex-col items-center justify-center text-center">
        <p className="text-lg font-medium text-earth">{error ?? "Tour not found."}</p>
        <button onClick={() => router.push("/tours")} className="btn-secondary mt-4">
          Back to tours
        </button>
      </div>
    );
  }

  return (
    <article className="mx-auto max-w-4xl px-4 sm:px-6 py-8 animate-fade-in">
      {/* Back */}
      <button
        onClick={() => router.back()}
        className="btn-ghost mb-6 -ml-2 text-sm"
      >
        <ChevronLeft className="h-4 w-4" />
        All tours
      </button>

      {/* Cover image */}
      {tour.coverImageUrl && (
        <div className="relative mb-8 h-72 overflow-hidden rounded-2xl sm:h-96">
          <img
            src={tour.coverImageUrl}
            alt={tour.name}
            className="h-full w-full object-cover"
          />
          <div className="hero-overlay absolute inset-0" />
          {/* Horizon rule on the image */}
          <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-savanna" />
        </div>
      )}

      {/* Header */}
      <header className="mb-8">
        <p className="eyebrow mb-2 flex items-center gap-1.5">
          <MapPin className="h-3.5 w-3.5" />
          {tour.destination}
        </p>
        <h1 className="font-display text-4xl font-bold text-earth sm:text-5xl text-balance">
          {tour.name}
        </h1>
        {tour.tagline && (
          <p className="mt-3 text-lg text-stone italic">{tour.tagline}</p>
        )}

        <div className="mt-5 flex flex-wrap gap-5 text-sm text-stone">
          <span className="flex items-center gap-1.5">
            <Clock className="h-4 w-4 text-savanna" />
            {tour.durationDays} {tour.durationDays === 1 ? "day" : "days"}
          </span>
          <span className="flex items-center gap-1.5">
            <Users className="h-4 w-4 text-savanna" />
            Max group size: {tour.maxGroupSize}
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-savanna" />
            {tour.difficulty.charAt(0) + tour.difficulty.slice(1).toLowerCase()}
          </span>
          <span className="rounded-full bg-savanna/10 px-2.5 py-0.5 text-savanna font-medium">
            {tour.category}
          </span>
        </div>
      </header>

      {/* Body grid */}
      <div className="grid gap-8 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-8">
          {/* Description */}
          <section>
            <h2 className="font-display text-2xl font-semibold text-earth mb-3">
              About this tour
            </h2>
            <p className="text-stone leading-relaxed whitespace-pre-line">
              {tour.description}
            </p>
          </section>

          {/* Highlights */}
          {tour.highlights?.length > 0 && (
            <section>
              <h2 className="font-display text-2xl font-semibold text-earth mb-4">
                Highlights
              </h2>
              <ul className="space-y-2.5">
                {tour.highlights.map((h, i) => (
                  <li key={i} className="flex items-start gap-2.5 text-sm text-stone">
                    <span className="mt-0.5 h-1.5 w-1.5 rounded-full bg-savanna shrink-0" />
                    {h}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* What's included */}
          <div className="grid gap-6 sm:grid-cols-2">
            {tour.inclusions?.length > 0 && (
              <section>
                <h3 className="font-semibold text-earth mb-3 flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-600" />
                  What's included
                </h3>
                <ul className="space-y-2">
                  {tour.inclusions.map((item, i) => (
                    <li key={i} className="text-sm text-stone flex items-start gap-2">
                      <span className="mt-1 h-1 w-1 rounded-full bg-green-500 shrink-0" />
                      {item}
                    </li>
                  ))}
                </ul>
              </section>
            )}

            {tour.exclusions?.length > 0 && (
              <section>
                <h3 className="font-semibold text-earth mb-3 flex items-center gap-2">
                  <XCircle className="h-4 w-4 text-stone/60" />
                  Not included
                </h3>
                <ul className="space-y-2">
                  {tour.exclusions.map((item, i) => (
                    <li key={i} className="text-sm text-stone flex items-start gap-2">
                      <span className="mt-1 h-1 w-1 rounded-full bg-stone/40 shrink-0" />
                      {item}
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </div>
        </div>

        {/* Booking card — sticky sidebar */}
        <aside>
          <div className="card sticky top-24 p-6">
            {/* Horizon rule inside card */}
            <div className="horizon-rule mb-5 -mx-6 px-6 pt-0 pb-5 border-t-0">
              <p className="text-2xs text-stone uppercase tracking-widest font-mono">
                Book this tour
              </p>
            </div>

            <div className="mb-5">
              <p className="text-sm text-stone">From</p>
              <p className="price-tag text-3xl">
                {formatCurrency(tour.pricePerPerson, tour.currency)}
              </p>
              <p className="text-sm text-stone">per person</p>
            </div>

            <a
              href={`/bookings/new?tourId=${tour.id}`}
              className="btn-primary w-full justify-center text-base py-3"
            >
              <Calendar className="h-4 w-4" />
              Book now
            </a>

            <p className="mt-4 text-center text-xs text-stone">
              No payment taken until confirmed by our team.
            </p>
          </div>
        </aside>
      </div>
    </article>
  );
}
