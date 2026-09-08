import type {
  TourSummary,
  PagedResponse,
  TourCategory,
} from "@/types/tour";

const BASE = process.env.NEXT_PUBLIC_API_URL;

/**
 * tourApi — public, unauthenticated read access to the tour catalogue.
 * Maps 1:1 to the confirmed public endpoints on TourController:
 *
 *   GET /api/tours               → getTours (page, size, category, country, destination)
 *   GET /api/tours/featured      → getFeaturedTours
 *   GET /api/tours/search?q=     → searchTours (q, page, size)
 *   GET /api/tours/{slug}        → getTourBySlug
 *
 * There is no "/public/tours" prefix on the real backend — don't add one
 * back in. Admin/staff mutations live in tourAdminApi.ts, not here.
 * Backend returns Spring Page<TourSummaryResponse> for list/search:
 * { content, totalElements, totalPages, number, size }
 */
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  if (!BASE) {
    throw { message: "NEXT_PUBLIC_API_URL is not set", statusCode: 0 };
  }

  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
    next: { revalidate: 60 },
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw {
      message: body.message ?? `Request failed: ${res.status}`,
      statusCode: res.status,
      code: body.code,
    };
  }

  const contentType = res.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    throw {
      message: `Expected JSON from ${BASE}${path} but got ${contentType || "unknown"} — check NEXT_PUBLIC_API_URL and that the API is running.`,
      statusCode: res.status,
    };
  }

  return res.json();
}

export const tourApi = {
  /**
   * Paginated active-tour listing with optional category/country/destination
   * filters. If a search query is provided, delegates to searchTours instead
   * — callers don't need to branch on this themselves.
   */
  getTours(opts: {
    page?: number;
    size?: number;
    category?: TourCategory;
    q?: string;
    country?: string;
    destination?: string;
    signal?: AbortSignal;
  } = {}): Promise<PagedResponse<TourSummary>> {
    const { page = 0, size = 12, category, q, country, destination, signal } = opts;
    if (q && q.trim()) {
      return tourApi.searchTours(q, page, size, signal);
    }
    const params = new URLSearchParams({ page: String(page), size: String(size) });
    if (category) params.set("category", category);
    if (country) params.set("country", country);
    if (destination) params.set("destination", destination);
    return request(`/tours?${params}`, { signal });
  },

  /**
   * Featured tours for the homepage.
   * Backend returns Flux<TourSummaryResponse> — received as array.
   */
  getFeaturedTours(signal?: AbortSignal): Promise<TourSummary[]> {
    return request("/tours/featured", { signal });
  },

  /**
   * Keyword search across name, destination, description.
   * Backend param is "q" — required, no default.
   */
  searchTours(
      q: string,
      page = 0,
      size = 12,
      signal?: AbortSignal,
  ): Promise<PagedResponse<TourSummary>> {
    const params = new URLSearchParams({
      q: q.trim(),
      page: String(page),
      size: String(size),
    });
    return request(`/tours/search?${params}`, { signal });
  },

  /**
   * Tour detail by slug.
   */
  getTourBySlug(slug: string, signal?: AbortSignal): Promise<TourSummary> {
    return request(`/tours/${slug}`, { signal });
  },
};