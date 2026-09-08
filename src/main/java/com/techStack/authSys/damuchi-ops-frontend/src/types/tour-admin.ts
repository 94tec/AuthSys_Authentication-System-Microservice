// Matches backend: TourCategory, TourDifficulty, TourPriceType, TourCurrency enums
// and CreateTourRequest / UpdateTourRequest / TourResponse / TourSummaryResponse DTOs.

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

export type TourDifficulty = "EASY" | "MODERATE" | "CHALLENGING" | "DIFFICULT" | "STRENUOUS";

export type TourPriceType = "PER_PERSON" | "PER_GROUP" | "PER_ROOM";

export type TourCurrency = "KES" | "USD" | "EUR" | "GBP";

export interface TourSummary {
    id: string;
    name: string;
    slug: string;
    shortDescription: string;
    category: TourCategory;
    destination: string;
    country: string;
    durationDays: number;
    difficulty: TourDifficulty;
    price: number;
    currency: TourCurrency;
    coverImage: string;
    averageRating: number;
    reviewCount: number;
    featured: boolean;
    active: boolean; // present on the entity; include if your TourSummaryResponse exposes it for admin use
}

export interface TourDetail {
    id: string;
    name: string;
    slug: string;
    shortDescription: string;
    description: string;
    category: TourCategory;

    destination: string;
    country: string;
    region?: string;
    meetingPoint?: string;

    durationDays: number;
    durationNights: number;
    difficulty: TourDifficulty;
    minimumAge?: number;
    maxGroupSize?: number;
    bestSeason?: string;

    price: number;
    currency: TourCurrency;
    priceType: TourPriceType;
    depositPercentage?: number;

    highlights: string[];
    itinerary: string[];
    inclusions: string[];
    exclusions: string[];
    requirements: string[];
    importantInformation?: string;

    coverImage: string;
    galleryImages: string[];
    videoUrl?: string;

    averageRating: number;
    reviewCount: number;

    active: boolean;
    featured: boolean;

    createdDate: string;
    updatedDate: string;
}

export interface CreateTourPayload {
    name: string;
    shortDescription: string;
    description: string;
    category: TourCategory;

    destination: string;
    country: string;
    region?: string;
    meetingPoint?: string;

    durationDays: number;
    durationNights: number;
    difficulty: TourDifficulty;
    minimumAge?: number;
    maxGroupSize?: number;
    bestSeason?: string;

    price: number;
    currency: TourCurrency;
    priceType: TourPriceType;
    depositPercentage?: number;

    highlights: string[];
    itinerary: string[];
    inclusions: string[];
    exclusions: string[];
    requirements: string[];
    importantInformation?: string;

    coverImage: string;
    galleryImages: string[];
    videoUrl?: string;

    active?: boolean;
    featured?: boolean;
}
export interface AvailabilitySummary {
    id: string;
    tourId: string;
    departureDate: string; // ISO date
    returnDate: string;
    capacity: number;
    bookedSeats: number;
    availableSeats: number;
    status: "OPEN" | "LIMITED" | "FULL" | "CLOSED" | "CANCELLED";
    priceOverride?: number;
    currency?: string;
}

export type UpdateTourPayload = Partial<CreateTourPayload>;

export interface PagedTours {
    content: TourSummary[];
    totalPages: number;
    totalElements: number;
    number: number;
}