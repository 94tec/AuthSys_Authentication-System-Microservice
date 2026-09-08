import { apiClient } from "@/lib/api-client";
import type {
    PagedTours,
    TourDetail,
    CreateTourPayload,
    UpdateTourPayload,
    TourCategory,
    AvailabilitySummary
} from "@/types/tour-admin";

export interface RevenueSummary {
    actualRevenue: number;
    expectedRevenue: number;
    toursSold: number;
    enquiryCount: number;
}

export interface RevenueDashboardResponse {
    today: RevenueSummary;
    thisWeek: RevenueSummary;
    thisMonth: RevenueSummary;
    lastMonth: RevenueSummary;
    monthOverMonthChangePercent: number;
}

export interface ListToursOptions {
    page?: number;
    size?: number;
    category?: TourCategory;
    /** Exact match, case-insensitive — e.g. "Kenya". */
    country?: string;
    /** Exact match, case-insensitive — e.g. "Maasai Mara". */
    destination?: string;
    signal?: AbortSignal;
}

// Base path confirmed against the real TourController: everything lives
// under /api/tours (no separate /admin/tours prefix) — write access is
// gated by @PreAuthorize on the backend, not by a different path.
export const tourAdminApi = {
    async listTours(options: ListToursOptions = {}): Promise<PagedTours> {
        const { page = 0, size = 20, category, country, destination, signal } = options;

        const response = await apiClient.get<PagedTours>("/tours", {
            params: {
                page,
                size,
                ...(category ? { category } : {}),
                ...(country ? { country } : {}),
                ...(destination ? { destination } : {}),
            },
            signal,
        });
        return response.data;
    },

    /**
     * Free-text search box — NOT for category/country nav pages (use
     * listTours for those). Backend param is "q", required, no default —
     * sending "query" instead returns 400.
     *
     * NOTE: the backend endpoint takes no category filter, so this can't be
     * combined with a category at the same time. If you need "search within
     * a category", that has to be added to TourController#searchTours /
     * TourService#searchTours first.
     */
    async searchTours(query: string, page = 0, size = 20, signal?: AbortSignal): Promise<PagedTours> {
        const response = await apiClient.get<PagedTours>("/tours/search", {
            params: { q: query, page, size },
            signal,
        });
        return response.data;
    },

    // lib/tour-admin-api.ts
    async getTour(id: string): Promise<TourDetail> {
        const response = await apiClient.get<TourDetail>(`/tours/id/${id}`);
        return response.data;
    },

    async createTour(payload: CreateTourPayload): Promise<TourDetail> {
        const response = await apiClient.post<TourDetail>("/tours", payload);
        return response.data;
    },

    async updateTour(id: string, payload: UpdateTourPayload): Promise<TourDetail> {
        const response = await apiClient.patch<TourDetail>(`/tours/${id}`, payload);
        return response.data;
    },

    async publishTour(id: string): Promise<TourDetail> {
        const response = await apiClient.patch<TourDetail>(`/tours/${id}/publish`, {});
        return response.data;
    },

    async deleteTour(id: string): Promise<void> {
        await apiClient.delete(`/tours/${id}`);
    },

    async getUpcomingAvailability(tourId: string): Promise<AvailabilitySummary[]> {
        const response = await apiClient.get<AvailabilitySummary[]>(`/tours/${tourId}/availability`);
        return response.data;
    },


    async revenue(): Promise<RevenueDashboardResponse> {
        const response = await apiClient.get<RevenueDashboardResponse>(
            "/admin/dashboard/revenue",
        );
        return response.data;
    },

};