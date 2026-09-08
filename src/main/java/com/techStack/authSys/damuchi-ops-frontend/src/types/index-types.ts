// ── Auth ──────────────────────────────────────────────────────────────────────

export type Role =
    | "SUPER_ADMIN"
    | "ADMIN"
    | "MANAGER"
    | "OPERATOR"
    | "USER"
    | "GUEST";

export interface User {
    id: string;
    email: string;
    displayName: string;
    roles: Role[];
    permissions: string[];
    status: "ACTIVE" | "PENDING_APPROVAL" | "DISABLED";
    profilePhotoUrl?: string;
}

export interface TokenPair {
    accessToken: string;
    refreshToken: string;
}

export interface AuthTokens {
    accessToken: string;
    refreshToken: string;
}

export interface LoginRequest {
    email: string;
    password: string;
}

export interface RegisterRequest {
    email: string;
    password: string;
    confirmPassword: string;
    displayName: string;
    roles: ["USER"];
}

// ── Availability ──────────────────────────────────────────────────────────────

export type AvailabilityStatus = "OPEN" | "SOLD_OUT" | "BLOCKED" | "UNAVAILABLE";

export interface AvailabilitySlot {
    id: string;
    tourId: string;
    date: string;           // ISO date "YYYY-MM-DD"
    totalSlots: number;
    availableSlots: number;
    status: AvailabilityStatus;
    bookingDeadline?: string;
}

export interface AvailabilityCalendar {
    tourId: string;
    month: string;          // "YYYY-MM"
    slots: AvailabilitySlot[];
}

// ── Bookings ──────────────────────────────────────────────────────────────────

export type BookingStatus =
    | "PENDING_PAYMENT"
    | "CONFIRMED"
    | "CANCELLED"
    | "COMPLETED"
    | "REFUNDED";

export interface Traveler {
    id: string;
    fullName: string;
    nationality?: string;
    dietaryNotes?: string;
    leadTraveler: boolean;
}

export interface Booking {
    id: string;
    customerId: string;
    customerEmail: string;
    customerName: string;
    tourId: string;
    tourName: string;
    tourDate: string;
    travelerCount: number;
    travelers: Traveler[];
    pricePerTraveler: number;
    totalPrice: number;
    currency: string;
    status: BookingStatus;
    statusDescription: string;
    paymentReference?: string;
    paidAt?: string;
    cancelledAt?: string;
    cancellationReason?: string;
    refundReference?: string;
    refundedAt?: string;
    specialRequests?: string;
    createdDate: string;
    lastModifiedDate: string;
}

export interface CreateBookingRequest {
    tourId: string;
    availabilityId: string;
    travelerCount: number;
    travelers: {
        fullName: string;
        dateOfBirth?: string;
        passportNumber?: string;
        nationality?: string;
        dietaryNotes?: string;
    }[];
    specialRequests?: string;
}

export interface BookingStats {
    pendingPayment: number;
    confirmed: number;
    completed: number;
    cancelled: number;
    refunded: number;
}

// ── API wrapper ───────────────────────────────────────────────────────────────

export interface ApiResponse<T> {
    success: boolean;
    message: string;
    data: T;
    timestamp?: string;
}

export interface ApiError {
    message: string;
    status?: number;
    errorCode?: string;
}

export interface Page<T> {
    content: T[];
    totalElements: number;
    totalPages: number;
    number: number;
    size: number;
    first: boolean;
    last: boolean;
}
