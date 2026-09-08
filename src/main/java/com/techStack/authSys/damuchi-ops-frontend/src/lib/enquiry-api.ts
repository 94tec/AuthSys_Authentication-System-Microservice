// lib/enquiry-api.ts

import { apiClient } from "@/lib/api-client";
import type {
    EnquiryResponse,
    EnquirySummaryResponse,
    EnquiryDetailResponse,
    EnquiryDashboardSummary,
    CreateEnquiryRequest,
    UpdateEnquiryStatusRequest,
    AssignEnquiryRequest,
    CreateQuoteRequest,
    QuoteResponse,
    TourEnquiryStatus,
    PagedResponse, AcceptQuoteRequest,
} from "@/types/enquiry-types";

/**
 * Enquiry API client.
 *
 * createEnquiry requires auth (isAuthenticated()) and is scoped to a
 * specific tour — the backend route is POST /api/tours/{tourId}/enquiries,
 * NOT a flat /enquiries. tourId is a path segment, never part of the body.
 *
 * Everything under "Admin dashboard" requires ADMIN/SUPER_ADMIN/MANAGER/
 * OPERATOR on the backend (AdminEnquiryController), some methods further
 * restricted to ADMIN/SUPER_ADMIN/MANAGER only (assign) — the backend is
 * the source of truth for these checks; the UI should still hide actions
 * the current user's role can't perform.
 */

interface AdminListEnquiriesParams {
    page?: number;
    size?: number;
    status?: TourEnquiryStatus;
    assignedTo?: string;
    tourId?: string;
    search?: string;
}

export const enquiryApi = {
    // ── Public / customer-authenticated ────────────────────────────────

    async createEnquiry(tourId: string, payload: CreateEnquiryRequest): Promise<EnquiryResponse> {
        const response = await apiClient.post<EnquiryResponse>(
            `/tours/${tourId}/enquiries`,
            payload,
        );
        return response.data;
    },

    /** Staff-only: list enquiries for one tour. */
    async listForTour(tourId: string, page = 0, size = 20): Promise<PagedResponse<EnquiryResponse>> {
        const response = await apiClient.get<PagedResponse<EnquiryResponse>>(
            `/tours/${tourId}/enquiries`,
            { params: { page, size } },
        );
        return response.data;
    },

    // ── Admin dashboard (/api/admin/enquiries) ─────────────────────────

    async adminSearch(params: AdminListEnquiriesParams = {}): Promise<PagedResponse<EnquirySummaryResponse>> {
        const { page = 0, size = 20, status, assignedTo, tourId, search } = params;
        const response = await apiClient.get<PagedResponse<EnquirySummaryResponse>>("/admin/enquiries", {
            params: {
                page,
                size,
                ...(status ? { status } : {}),
                ...(assignedTo ? { assignedTo } : {}),
                ...(tourId ? { tourId } : {}),
                ...(search ? { search } : {}),
            },
        });
        return response.data;
    },

    async adminGetDetail(id: string): Promise<EnquiryDetailResponse> {
        const response = await apiClient.get<EnquiryDetailResponse>(`/admin/enquiries/${id}`);
        return response.data;
    },

    async adminDashboardSummary(): Promise<EnquiryDashboardSummary> {
        const response = await apiClient.get<EnquiryDashboardSummary>("/admin/enquiries/dashboard/summary");
        return response.data;
    },

    async adminUpdateStatus(id: string, payload: UpdateEnquiryStatusRequest): Promise<EnquiryDetailResponse> {
        const response = await apiClient.patch<EnquiryDetailResponse>(`/admin/enquiries/${id}/status`, payload);
        return response.data;
    },

    /** ADMIN/SUPER_ADMIN/MANAGER only on the backend — hide this action for OPERATOR in the UI. */
    async adminAssign(id: string, payload: AssignEnquiryRequest): Promise<void> {
        await apiClient.patch(`/admin/enquiries/${id}/assign`, payload);
    },

    async adminAddNote(id: string, note: string): Promise<void> {
        // Backend expects a raw string body, not a JSON object.
        await apiClient.post(`/admin/enquiries/${id}/notes`, note, {
            headers: { "Content-Type": "text/plain" },
        });
    },

    // ── Quotes ──────────────────────────────────────────────────────────

    async adminCreateQuote(id: string, payload: CreateQuoteRequest): Promise<QuoteResponse> {
        const response = await apiClient.post<QuoteResponse>(`/admin/enquiries/${id}/quotes`, payload);
        return response.data;
    },

    async downloadQuotePdf(enquiryId: string, quoteId: string, asAdmin: boolean): Promise<Blob> {
        const path = asAdmin
            ? `/admin/enquiries/${enquiryId}/quotes/${quoteId}/pdf`
            : `/me/enquiries/${enquiryId}/quotes/${quoteId}/pdf`;
        const response = await apiClient.get(path, { responseType: "blob" });
        return response.data;
    },

    async adminSendQuote(id: string, quoteId: string): Promise<QuoteResponse> {
        const response = await apiClient.post<QuoteResponse>(`/admin/enquiries/${id}/quotes/${quoteId}/send`);
        return response.data;
    },

    // ── Staff queues ────────────────────────────────────────────────────

    async adminUnassignedQueue(page = 0, size = 20): Promise<PagedResponse<EnquirySummaryResponse>> {
        const response = await apiClient.get<PagedResponse<EnquirySummaryResponse>>(
            "/admin/enquiries/queue/unassigned",
            { params: { page, size } },
        );
        return response.data;
    },

    async adminOverdueFollowUpQueue(page = 0, size = 20): Promise<PagedResponse<EnquirySummaryResponse>> {
        const response = await apiClient.get<PagedResponse<EnquirySummaryResponse>>(
            "/admin/enquiries/queue/overdue-followup",
            { params: { page, size } },
        );
        return response.data;
    },

    async adminUpcomingDeparturesQueue(days = 14, page = 0, size = 20): Promise<PagedResponse<EnquirySummaryResponse>> {
        const response = await apiClient.get<PagedResponse<EnquirySummaryResponse>>(
            "/admin/enquiries/queue/departures-upcoming",
            { params: { days, page, size } },
        );
        return response.data;
    },

    // ── Customer self-service (/api/me/enquiries) ──────────────────────

    async myEnquiries(status?: TourEnquiryStatus, page = 0, size = 20): Promise<PagedResponse<EnquirySummaryResponse>> {
        const response = await apiClient.get<PagedResponse<EnquirySummaryResponse>>("/me/enquiries", {
            params: { status, page, size },
        });
        return response.data;
    },

    async myEnquiryDetail(id: string): Promise<EnquiryDetailResponse> {
        const response = await apiClient.get<EnquiryDetailResponse>(`/me/enquiries/${id}`);
        return response.data;
    },
    async acceptQuote(enquiryId: string, quoteId: string, payload: AcceptQuoteRequest): Promise<QuoteResponse> {
        const response = await apiClient.post<QuoteResponse>(
            `/me/enquiries/${enquiryId}/quotes/${quoteId}/accept`,
            payload,
        );
        return response.data;
    },
};