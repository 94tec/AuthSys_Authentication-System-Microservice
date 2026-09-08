// ─── Enums — mirror backend exactly ─────────────────────────────────────────

export type TourCategory =
  | "SAFARI"
  | "DAY_TRIP"
  | "CULTURAL"
  | "ADVENTURE"
  | "BEACH"
  | "MOUNTAIN"
  | "WILDLIFE"
  | "CITY_TOUR"
  | "PHOTOGRAPHY"
  | "FAMILY"
  | "CRUISE"
  | "LUXURY"
  | "HONEYMOON"
  | "GROUP";

export type TourDifficulty =
  | "EASY"
  | "MODERATE"
  | "CHALLENGING"
  | "STRENUOUS";

// ─── Display maps ────────────────────────────────────────────────────────────

export const CATEGORY_LABELS: Record<TourCategory, string> = {
  SAFARI:      "Safari",
  DAY_TRIP:    "Day Trip",
  CULTURAL:    "Cultural",
  ADVENTURE:   "Adventure",
  BEACH:       "Beach & Coast",
  MOUNTAIN:    "Mountain & Hiking",
  WILDLIFE:    "Wildlife",
  CITY_TOUR:   "City Tour",
  PHOTOGRAPHY: "Photography",
  FAMILY:      "Family",
  CRUISE:      "cruise",
  LUXURY:      "luxury",
  HONEYMOON:   "Honeymoon",
  GROUP:       "Group",
};

export const DIFFICULTY_LABELS: Record<TourDifficulty, string> = {
  EASY:        "Easy",
  MODERATE:    "Moderate",
  CHALLENGING: "Challenging",
  STRENUOUS:   "Strenuous",
};

// Category emoji used in cards and pills
export const CATEGORY_EMOJI: Record<TourCategory, string> = {
  SAFARI:      "🦁",
  DAY_TRIP:    "🌅",
  CULTURAL:    "🏛",
  ADVENTURE:   "🧗",
  BEACH:       "🌊",
  MOUNTAIN:    "⛰️",
  WILDLIFE:    "🐘",
  CITY_TOUR:   "🏙️",
  PHOTOGRAPHY: "📷",
  FAMILY:      "👨‍👩‍👧",
  CRUISE:      "🌊",
  LUXURY:      "🌊",
  HONEYMOON:   "🌊",
  GROUP:       "🌊"
};

export interface TourPublic {
  id: string;
  slug: string;
  name: string;
  tagline: string;
  description: string;
  destination: string;
  category: TourCategory;
  difficulty: TourDifficulty;
  durationDays: number;
  maxGroupSize: number;
  pricePerPerson: number;
  currency: string;
  coverImageUrl?: string;
  imageUrls: string[];
  highlights: string[];
  inclusions: string[];
  exclusions: string[];
  featured: boolean;
  totalBookings: number;
}

export interface TourAdmin extends TourPublic {
  active: boolean;
  deleted: boolean;
  createdBy: string;
  createdDate: string;
  lastModifiedDate: string;
}

// ─── API response shapes — match backend TourSummaryResponse exactly ─────────

/**
 * Maps backend TourSummaryResponse fields to frontend-friendly names.
 *
 * Backend field       → Frontend field
 * name                → name
 * slug                → slug
 * shortDescription    → shortDescription
 * pricePerPerson      → pricePerPerson
 * durationHours       → durationHours
 * formattedDuration   → formattedDuration
 * category            → category
 * categoryDisplayName → categoryDisplayName
 * difficulty          → difficulty
 * destination         → destination    (replaces old "location")
 * coverImageUrl       → coverImageUrl
 * featured            → featured
 * averageRating       → averageRating  (replaces old "rating")
 * totalReviews        → totalReviews
 */
// types/tour.ts
export interface TourSummary {
  id: string;
  name: string;
  slug: string;
  shortDescription: string | null;
  price: number;
  currency: string;
  durationHours: number;
  formattedDuration: string;
  category: TourCategory;
  categoryDisplayName: string;
  difficulty: TourDifficulty;
  destination: string;
  coverImageUrl: string | null;
  featured: boolean;
  averageRating: number | null;
  totalReviews: number;
  active: boolean;
}

// ─── Paginated response wrapper — matches Spring Page<T> ─────────────────────

export interface PagedResponse<T> {
  content:       T[];
  totalElements: number;
  totalPages:    number;
  number:        number;   // current page (0-indexed)
  size:          number;
}

// ─── Search / filter params ───────────────────────────────────────────────────

export interface TourSearchParams {
  page?:     number;
  size?:     number;
  category?: TourCategory;
  q?:        string;
}
