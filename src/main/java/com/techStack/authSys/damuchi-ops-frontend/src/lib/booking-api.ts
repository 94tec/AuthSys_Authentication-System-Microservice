import { apiClient } from "@/lib/api-client";
import type { ApiResponse, Booking, BookingStats, BookingStatus, CreateBookingRequest } from "@/types";

export const bookingApi = {
  // ── Customer ────────────────────────────────────────────────────────────────
  create: async (req: CreateBookingRequest): Promise<Booking> => {
    const res = await apiClient.post<ApiResponse<Booking>>("/bookings", req);
    return res.data.data;
  },

  myBookings: async (): Promise<Booking[]> => {
    const res = await apiClient.get<Booking[]>("/bookings/me");
    return res.data;
  },

  myActiveBookings: async (): Promise<Booking[]> => {
    const res = await apiClient.get<Booking[]>("/bookings/me/active");
    return res.data;
  },

  myBookingById: async (id: string): Promise<Booking> => {
    const res = await apiClient.get<Booking>(`/bookings/me/${id}`);
    return res.data;
  },

  cancelMyBooking: async (id: string, reason?: string): Promise<Booking> => {
    const res = await apiClient.post<Booking>(
      `/bookings/me/${id}/cancel`,
      null,
      { params: { reason: reason ?? "Customer requested cancellation" } }
    );
    return res.data;
  },

  // ── Staff ───────────────────────────────────────────────────────────────────
  all: async (status?: BookingStatus): Promise<Booking[]> => {
    const res = await apiClient.get<Booking[]>("/bookings", {
      params: status ? { status } : undefined,
    });
    return res.data;
  },

  byDate: async (date: string): Promise<Booking[]> => {
    const res = await apiClient.get<Booking[]>("/bookings/by-date", { params: { date } });
    return res.data;
  },

  byTour: async (tourId: string): Promise<Booking[]> => {
    const res = await apiClient.get<Booking[]>(`/bookings/by-tour/${tourId}`);
    return res.data;
  },

  confirm: async (id: string, paymentReference: string): Promise<Booking> => {
    const res = await apiClient.post<ApiResponse<Booking>>(
      `/bookings/${id}/confirm`,
      null,
      { params: { paymentReference } }
    );
    return res.data.data;
  },

  staffCancel: async (id: string, reason: string): Promise<Booking> => {
    const res = await apiClient.post<Booking>(
      `/bookings/${id}/cancel`,
      null,
      { params: { reason } }
    );
    return res.data;
  },

  complete: async (id: string): Promise<Booking> => {
    const res = await apiClient.post<ApiResponse<Booking>>(`/bookings/${id}/complete`);
    return res.data.data;
  },

  refund: async (id: string, refundReference: string): Promise<Booking> => {
    const res = await apiClient.post<ApiResponse<Booking>>(
      `/bookings/${id}/refund`,
      null,
      { params: { refundReference } }
    );
    return res.data.data;
  },

  stats: async (): Promise<BookingStats> => {
    const res = await apiClient.get<BookingStats>("/bookings/stats");
    return res.data;
  },
};
