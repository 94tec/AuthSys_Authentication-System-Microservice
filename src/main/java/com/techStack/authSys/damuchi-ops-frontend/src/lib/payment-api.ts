// lib/payment-api.ts (full replacement)
import { apiClient } from "@/lib/api-client";
import type { PagedResponse } from "@/types/enquiry-types";
import type {
    BookingCreatedResponse,
    CreateBookingPayload,
    PaymentChannel,
    PaymentSubmissionResponse,
} from "@/types/payment-types";

export type PaymentQueueView = "pending" | "awaiting-booking";

export const paymentApi = {
    // ── Customer ──
    async submitPayment(
        enquiryId: string,
        quoteId: string,
        payload: { channel: PaymentChannel; referenceCode: string; amountPaid: number; payerName?: string },
    ): Promise<PaymentSubmissionResponse> {
        const response = await apiClient.post<PaymentSubmissionResponse>(
            `/me/enquiries/${enquiryId}/quotes/${quoteId}/payment-submissions`, payload,
        );
        return response.data;
    },

    async listMine(enquiryId: string): Promise<PaymentSubmissionResponse[]> {
        const response = await apiClient.get<PaymentSubmissionResponse[]>(
            `/me/enquiries/${enquiryId}/payment-submissions`,
        );
        return response.data;
    },

    // ── Admin ──
    async adminList(view: PaymentQueueView, page = 0, size = 50): Promise<PagedResponse<PaymentSubmissionResponse>> {
        const response = await apiClient.get<PagedResponse<PaymentSubmissionResponse>>(
            "/admin/payment-submissions", { params: { view, page, size } },
        );
        return response.data;
    },

    async adminVerify(id: string): Promise<PaymentSubmissionResponse> {
        const response = await apiClient.post<PaymentSubmissionResponse>(`/admin/payment-submissions/${id}/verify`);
        return response.data;
    },

    async adminReject(id: string, reason: string): Promise<PaymentSubmissionResponse> {
        const response = await apiClient.post<PaymentSubmissionResponse>(
            `/admin/payment-submissions/${id}/reject`, { reason },
        );
        return response.data;
    },

    async adminCreateBooking(submissionId: string, payload: CreateBookingPayload): Promise<BookingCreatedResponse> {
        const response = await apiClient.post<BookingCreatedResponse>(
            `/admin/payment-submissions/${submissionId}/create-booking`, payload,
        );
        return response.data;
    },
};