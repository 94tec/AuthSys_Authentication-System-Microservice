import Link from "next/link";
import { Star, MapPin, Clock } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { CATEGORY_LABELS, DIFFICULTY_LABELS, type TourSummary } from "@/types/tour";

const DIFFICULTY_VARIANT: Record<string, "success" | "secondary" | "warning" | "destructive"> = {
  EASY: "success",
  MODERATE: "secondary",
  CHALLENGING: "warning",
  EXTREME: "destructive",
};

interface TourCardProps {
  tour: TourSummary;
}

export function TourCard({ tour }: TourCardProps) {
  return (
    <Link
      href="/register"
      className="group flex flex-col overflow-hidden rounded-xl border border-border bg-card transition-all hover:-translate-y-0.5 hover:shadow-md"
    >
      <div className="relative h-44 overflow-hidden bg-muted">
        {tour.coverImageUrl ? (
          <img
            src={tour.coverImageUrl}
            alt={tour.title}
            className="h-full w-full object-cover transition-transform duration-300 group-hover:scale-105"
            loading="lazy"
          />
        ) : (
          <div className="flex h-full w-full items-center justify-center bg-gradient-to-br from-expedition-moss/20 to-expedition-forest/30">
            <span className="font-display text-sm text-muted-foreground">
              {CATEGORY_LABELS[tour.category]}
            </span>
          </div>
        )}
        <Badge
          variant="secondary"
          className="absolute left-3 top-3 backdrop-blur-sm"
        >
          {CATEGORY_LABELS[tour.category]}
        </Badge>
        {tour.rating !== undefined && tour.rating > 0 && (
          <div className="absolute right-3 top-3 flex items-center gap-1 rounded-full bg-background/90 px-2 py-1 text-xs font-medium backdrop-blur-sm">
            <Star className="h-3 w-3 fill-accent text-accent" />
            {tour.rating.toFixed(1)}
          </div>
        )}
      </div>

      <div className="flex flex-1 flex-col p-4">
        <p className="flex items-center gap-1 text-xs text-muted-foreground">
          <MapPin className="h-3 w-3" />
          {tour.location}
        </p>
        <h3 className="mt-1.5 font-display text-base font-medium leading-snug tracking-tight text-foreground">
          {tour.title}
        </h3>

        <div className="mt-2.5 flex flex-wrap gap-1.5">
          <Badge variant={DIFFICULTY_VARIANT[tour.difficulty]} className="text-[10px]">
            {DIFFICULTY_LABELS[tour.difficulty]}
          </Badge>
          <Badge variant="outline" className="flex items-center gap-1 text-[10px]">
            <Clock className="h-2.5 w-2.5" />
            {tour.durationDays}d
          </Badge>
        </div>

        <div className="mt-auto flex items-end justify-between pt-4">
          <div>
            <p className="text-[11px] text-muted-foreground">From</p>
            <p className="font-display text-lg font-medium tracking-tight text-foreground">
              {tour.currency} {tour.price.toLocaleString()}
            </p>
          </div>
          <span className="text-sm font-medium text-accent transition-transform group-hover:translate-x-0.5">
            View →
          </span>
        </div>
      </div>
    </Link>
  );
}
