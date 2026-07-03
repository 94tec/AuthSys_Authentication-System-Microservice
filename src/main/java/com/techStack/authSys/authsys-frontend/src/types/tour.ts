// ─────────────────────────────────────────────────────────────────
// Tour types — mirrors your actual Tour entity (PostgreSQL/JPA)
// with idx_tour_slug constraint confirmed in startup log
// ─────────────────────────────────────────────────────────────────

export type TourCategory =
  | "SAFARI"
  | "BEACH"
  | "MOUNTAIN"
  | "CULTURAL"
  | "ADVENTURE"
  | "CITY"
  | "WILDLIFE"
  | "CRUISE";

export type TourDifficulty = "EASY" | "MODERATE" | "CHALLENGING" | "EXTREME";

export type TourStatus = "DRAFT" | "ACTIVE" | "INACTIVE" | "ARCHIVED";

// Mirrors Tour entity
export interface Tour {
  id: string;
  slug: string;
  title: string;
  description: string;
  category: TourCategory;
  difficulty: TourDifficulty;
  status: TourStatus;
  durationDays: number;
  price: number;
  currency: string;
  maxGroupSize: number;
  minGroupSize?: number;
  location: string;
  destination?: string;
  coverImageUrl?: string;
  galleryUrls?: string[];
  startDates?: string[];
  isActive: boolean;
  createdAt: string;
  updatedAt?: string;
  createdBy?: string;
  rating?: number;
  reviewCount?: number;
  // SaaS fields (will grow)
  organizationId?: string;
  metadata?: Record<string, unknown>;
}

// Mirrors TourSummaryResponse
export interface TourSummary {
  id: string;
  slug: string;
  title: string;
  category: TourCategory;
  difficulty: TourDifficulty;
  status: TourStatus;
  durationDays: number;
  price: number;
  currency: string;
  location: string;
  coverImageUrl?: string;
  isActive: boolean;
  rating?: number;
  reviewCount?: number;
}

// Mirrors TourResponse
export interface TourResponse extends Tour {}

// Mirrors CreateTourRequest
export interface TourCreateRequest {
  title: string;
  description: string;
  category: TourCategory;
  difficulty: TourDifficulty;
  durationDays: number;
  price: number;
  currency: string;
  maxGroupSize: number;
  minGroupSize?: number;
  location: string;
  destination?: string;
  coverImageUrl?: string;
  galleryUrls?: string[];
  startDates?: string[];
}

// Mirrors UpdateTourRequest
export interface TourUpdateRequest extends Partial<TourCreateRequest> {
  isActive?: boolean;
  status?: TourStatus;
}

export interface Page<T> {
  content: T[];
  totalElements: number;
  totalPages: number;
  pageNumber: number;
  pageSize: number;
  last: boolean;
  first: boolean;
}

export const CATEGORY_LABELS: Record<TourCategory, string> = {
  SAFARI: "Safari",
  BEACH: "Beach",
  MOUNTAIN: "Mountain",
  CULTURAL: "Cultural",
  ADVENTURE: "Adventure",
  CITY: "City",
  WILDLIFE: "Wildlife",
  CRUISE: "Cruise",
};

export const DIFFICULTY_LABELS: Record<TourDifficulty, string> = {
  EASY: "Easy",
  MODERATE: "Moderate",
  CHALLENGING: "Challenging",
  EXTREME: "Extreme",
};
