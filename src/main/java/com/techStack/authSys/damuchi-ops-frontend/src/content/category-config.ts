import type { TourCategory } from "@/types/tour";

export interface CategoryPageConfig {
    title: string;
    description: string;
    /** Free-text search — use only when no real filter field applies. */
    search?: string;
    /** Theme filter. Must be a real TourCategory value — see the enum in tour-admin.ts. */
    category?: TourCategory;
    /** Exact match, case-insensitive — e.g. "Kenya". Preferred over `search` for country pages. */
    country?: string;
    /** Exact match, case-insensitive — e.g. "Maasai Mara". Preferred over `search` for place pages. */
    destination?: string;
}

export type CategoryConfigMap = Record<string, CategoryPageConfig>;

/**
 * ---------------------------------------------------------------------------
 * SAFARIS
 * ---------------------------------------------------------------------------
 * Country pages (kenya/tanzania/uganda/rwanda) show every tour in that
 * country regardless of theme, so they filter by `country`, not `category`.
 * "luxury", "family", "honeymoon" and "group" all map to real TourCategory
 * values.
 * ---------------------------------------------------------------------------
 */

export const SAFARI_CONFIG: CategoryConfigMap = {
    kenya: {
        title: "Kenya Safaris",
        description:
            "Discover Maasai Mara, Amboseli, Tsavo and Kenya's iconic wildlife experiences.",
        country: "Kenya",
    },

    tanzania: {
        title: "Tanzania Safaris",
        description:
            "Explore Serengeti, Ngorongoro Crater and world-famous migration routes.",
        country: "Tanzania",
    },

    uganda: {
        title: "Uganda Safaris",
        description:
            "Gorilla trekking, rainforest adventures and unforgettable wildlife.",
        country: "Uganda",
    },

    rwanda: {
        title: "Rwanda Gorilla Trekking",
        description:
            "Premium gorilla trekking and Volcanoes National Park experiences.",
        country: "Rwanda",
    },

    luxury: {
        title: "Luxury Safaris",
        description:
            "Private guides, premium lodges and luxury safari experiences.",
        category: "LUXURY",
    },

    family: {
        title: "Family Safaris",
        description:
            "Kid-friendly safaris and family-focused itineraries.",
        category: "FAMILY",
    },

    honeymoon: {
        title: "Honeymoon Safaris",
        description:
            "Romantic safari experiences designed for couples.",
        category: "HONEYMOON",
    },

    group: {
        title: "Group Safaris",
        description:
            "Shared departures and group travel packages.",
        category: "GROUP",
    },
};

/**
 * ---------------------------------------------------------------------------
 * HOTELS
 * ---------------------------------------------------------------------------
 * Hotels are represented through the tour catalogue/search layer only — do
 * not assign a TourCategory unless the backend actually defines one for
 * accommodation. All entries stay search-based on purpose.
 * ---------------------------------------------------------------------------
 */

export const HOTEL_CONFIG: CategoryConfigMap = {
    beach: {
        title: "Beach Hotels",
        description:
            "Luxury beach resorts and coastal stays across East Africa.",
        search: "beach",
    },

    lodges: {
        title: "Safari Lodges",
        description:
            "Stay close to nature in handpicked safari lodges.",
        search: "lodge",
    },

    city: {
        title: "City Hotels",
        description:
            "Business and leisure hotels in major East African cities.",
        search: "hotel",
    },

    luxury: {
        title: "Luxury Hotels",
        description:
            "Five-star properties and premium hospitality.",
        search: "luxury hotel",
    },

    // Added — referenced by NAV_LINKS but previously missing, so these links 404'd.
    family: {
        title: "Family Resorts",
        description:
            "Spacious, kid-friendly stays with facilities the whole family will use.",
        search: "family resort",
    },

    budget: {
        title: "Budget Stays",
        description:
            "Comfortable, affordable places to stay without the frills.",
        search: "budget",
    },
};

/**
 * ---------------------------------------------------------------------------
 * DESTINATIONS
 * ---------------------------------------------------------------------------
 * Country-level entries filter by `country`; specific-place entries filter
 * by `destination`. "diani" is left on `search` since the stored destination
 * value for Diani tours may read "Diani Beach" rather than "Diani" — switch
 * it to `destination` once you confirm the exact stored string.
 * ---------------------------------------------------------------------------
 */

export const DESTINATION_CONFIG: CategoryConfigMap = {
    kenya: {
        title: "Kenya Destinations",
        description:
            "Wildlife, coastlines and cultural experiences throughout Kenya.",
        country: "Kenya",
    },

    tanzania: {
        title: "Tanzania Destinations",
        description:
            "From Serengeti plains to Zanzibar beaches.",
        country: "Tanzania",
    },

    uganda: {
        title: "Uganda Destinations",
        description:
            "Rainforests, gorillas and adventure travel.",
        country: "Uganda",
    },

    rwanda: {
        title: "Rwanda Destinations",
        description:
            "Volcanoes, gorillas and vibrant city experiences.",
        country: "Rwanda",
    },

    // Added — referenced by NAV_LINKS but previously missing, so these links 404'd.
    zanzibar: {
        title: "Zanzibar",
        description:
            "Spice Island beaches, Stone Town history and dhow sunset cruises.",
        destination: "Zanzibar",
    },

    "maasai-mara": {
        title: "Maasai Mara",
        description:
            "Kenya's flagship reserve, home to the Great Migration and the Big Five.",
        destination: "Maasai Mara",
    },

    serengeti: {
        title: "Serengeti",
        description:
            "Endless plains and the heart of the wildebeest migration in Tanzania.",
        destination: "Serengeti",
    },

    diani: {
        title: "Diani Beach",
        description:
            "White-sand beaches and coral reefs on Kenya's south coast.",
        search: "Diani",
    },
};

/**
 * ---------------------------------------------------------------------------
 * EXPERIENCES
 * ---------------------------------------------------------------------------
 * Only assign `category` where the value actually exists in TourCategory
 * (WILDLIFE, MOUNTAIN, BEACH, CULTURAL, ADVENTURE, PHOTOGRAPHY, FAMILY,
 * LUXURY, HONEYMOON, GROUP, CRUISE, DAY_TRIP). Everything else stays on
 * `search`.
 * ---------------------------------------------------------------------------
 */

export const EXPERIENCE_CONFIG: CategoryConfigMap = {
    cultural: {
        title: "Cultural Experiences",
        description:
            "Authentic local communities, traditions and heritage.",
        category: "CULTURAL",
    },

    beach: {
        title: "Beach Experiences",
        description:
            "Island escapes, dhow cruises and ocean adventures.",
        category: "BEACH",
    },

    mountain: {
        title: "Mountain Adventures",
        description:
            "Summits, trekking routes and alpine experiences.",
        category: "MOUNTAIN",
    },

    safari: {
        title: "Wildlife Experiences",
        description:
            "Big Five safaris and unforgettable game drives.",
        // Was "SAFARI", which isn't a real TourCategory value — WILDLIFE is
        // the actual enum entry this page's title and copy describe.
        category: "WILDLIFE",
    },

    // Added — referenced by NAV_LINKS but previously missing, so these links 404'd.
    "gorilla-trekking": {
        title: "Gorilla Trekking",
        description:
            "Face-to-face encounters with mountain gorillas in Rwanda and Uganda.",
        search: "gorilla trekking",
    },

    "game-drives": {
        title: "Game Drives",
        description:
            "Classic open-vehicle safaris in search of the Big Five.",
        search: "game drive",
        category: "WILDLIFE",
    },

    "beach-holidays": {
        title: "Beach Holidays",
        description:
            "Relax on the coast after the dust of the savanna.",
        category: "BEACH",
    },

    "cultural-tours": {
        title: "Cultural Tours",
        description:
            "Visit local communities and learn living traditions firsthand.",
        category: "CULTURAL",
    },

    hiking: {
        title: "Mountain Hiking",
        description:
            "Trekking routes from day hikes to multi-day summit attempts.",
        category: "MOUNTAIN",
    },

    "boat-cruises": {
        title: "Boat Cruises",
        description:
            "Dhow sails, lake crossings and coastal cruises.",
        category: "CRUISE",
    },

    "day-trips": {
        title: "Day Trips",
        description:
            "Short, self-contained outings that don't need an overnight stay.",
        category: "DAY_TRIP",
    },
};

/**
 * Safely retrieve a configuration using a dynamic route slug.
 *
 * This prevents:
 *
 *     No index signature with a parameter of type 'string'
 *
 * when using:
 *
 *     CONFIG[params.slug]
 */
export function getCategoryConfig(
    config: CategoryConfigMap,
    slug: string,
): CategoryPageConfig | undefined {
    return config[slug];
}