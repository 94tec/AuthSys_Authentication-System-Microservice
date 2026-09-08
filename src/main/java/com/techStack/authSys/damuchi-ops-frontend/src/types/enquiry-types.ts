// types/enquiry-types.ts

// ── Enums (mirror backend Java enums exactly — keep in sync) ──────────────

/** Matches com.techStack.authSys.tour.models.TourEnquiryStatus */
export type TourEnquiryStatus =
    | "NEW"
    | "CONTACTED"
    | "QUOTED"
    | "CONVERTED"
    | "COMPLETED"
    | "LOST"
    | "ARCHIVED";

/** Matches com.techStack.authSys.tour.models.PreferredContact */
export type PreferredContact = "EMAIL" | "PHONE" | "WHATSAPP";

/** Matches com.techStack.authSys.tour.models.QuoteStatus */
export type QuoteStatus = "DRAFT" | "SENT" | "ACCEPTED" | "DECLINED" | "EXPIRED";

/** Matches com.techStack.authSys.tour.models.ActorType */
export type ActorType = "ADMIN" | "CUSTOMER" | "SYSTEM";

/** Matches com.techStack.authSys.tour.models.ActivityAction */
export type ActivityAction =
    | "STATUS_CHANGED"
    | "ASSIGNED"
    | "QUOTE_CREATED"
    | "QUOTE_SENT"
    | "QUOTE_ACCEPTED"
    | "QUOTE_DECLINED"
    | "NOTE_ADDED"
    | "APPRECIATION_SENT";

/**
 * Client-side mirror of EnquiryStatusTransitions.ALLOWED on the backend.
 * The server is the real enforcement point — this exists purely so the
 * status dropdown doesn't offer moves that will just 409. Keep in sync
 * with com.techStack.authSys.tour.services.EnquiryStatusTransitions.
 */
export const ENQUIRY_STATUS_TRANSITIONS: Record<TourEnquiryStatus, TourEnquiryStatus[]> = {
    NEW: ["CONTACTED", "LOST"],
    CONTACTED: ["QUOTED", "LOST"],
    QUOTED: ["CONVERTED", "LOST"],
    CONVERTED: ["COMPLETED"],
    COMPLETED: ["ARCHIVED"],
    LOST: ["ARCHIVED"],
    ARCHIVED: [],
};

// ── Requests ────────────────────────────────────────────────────────────

/**
 * Matches CreateEnquiryRequest. NOTE: tourId is NOT part of this payload —
 * it's a path segment on POST /api/tours/{tourId}/enquiries, and userId is
 * derived server-side from the JWT, never sent by the client.
 */
export interface CreateEnquiryRequest {
    fullName: string;
    email: string;
    phone?: string;
    preferredContact?: PreferredContact;
    preferredDate?: string; // ISO date (yyyy-MM-dd)
    flexibleDates?: boolean;
    groupSizeAdults?: number;
    groupSizeChildren?: number;
    budgetRange?: string;
    requirements?: string;
    source?: string;
    consent?: boolean;
}

/** Matches UpdateEnquiryStatusRequest (admin). */
export interface UpdateEnquiryStatusRequest {
    status: TourEnquiryStatus;
    note?: string;
}

/** Matches AssignEnquiryRequest (admin). staffId is a Firebase UID string, not a UUID. */
export interface AssignEnquiryRequest {
    staffId: string;
}

/**
 * Matches CreateQuoteRequest (admin). `currency` isn't pinned to a literal
 * union here since TourCurrency's actual enum values weren't confirmed —
 * replace `string` with a proper union once confirmed.
 */
export interface CreateQuoteRequest {
    pricePerAdult: number;
    pricePerChild?: number;
    totalPrice: number;
    currency: string;
    validUntil: string;
    inclusionsNote?: string;
    internalNote?: string;
    adultCount: number;
    childCount: number;
}

/** Matches CustomerEnquiryController.AcceptQuoteRequest. */
export interface AcceptQuoteRequest {
    termsAccepted: boolean;
}

// ── Responses ───────────────────────────────────────────────────────────

/** Matches EnquiryResponse — returned by POST /api/tours/{tourId}/enquiries. */
export interface EnquiryResponse {
    id: string;
    tourId: string;
    tourName: string;
    fullName: string;
    email: string;
    phone?: string;
    preferredContact?: PreferredContact;
    preferredDate?: string;
    groupSizeAdults?: number;
    groupSizeChildren?: number;
    budgetRange?: string;
    requirements?: string;
    status: TourEnquiryStatus;
    createdDate: string;
    lastModifiedDate: string;
}

/** Matches EnquirySummaryResponse — used in admin list/queue views. */
export interface EnquirySummaryResponse {
    id: string;
    tourId: string;
    tourName: string;
    fullName: string;
    email: string;
    status: TourEnquiryStatus;
    assignedTo?: string;
    createdDate: string;
    lastModifiedDate: string;
}

/** Matches QuoteResponse. */
export interface QuoteResponse {
    id: string;
    enquiryId: string;
    adultCount: number;
    childCount: number;
    pricePerAdult: number;
    pricePerChild?: number;
    totalPrice: number;
    currency: string;
    validUntil: string;
    inclusionsNote?: string;
    status: QuoteStatus;
    sentAt?: string;
    respondedAt?: string;
}
/** Matches ActivityLogResponse (backed by the enquiry_events table). */
export interface ActivityLogResponse {
    id: string;
    actorType: ActorType;
    actorId?: string;
    action: ActivityAction;
    fromStatus?: TourEnquiryStatus;
    toStatus?: TourEnquiryStatus;
    note?: string;
    createdDate: string;
}

/**
 * Matches EnquiryDetailResponse — admin + customer detail views. Includes
 * the full trip request (preferredContact, groupSize, budgetRange,
 * requirements) which the earlier version of this DTO omitted.
 */
export interface EnquiryDetailResponse {
    id: string;
    tourId: string;
    tourName: string;
    fullName: string;
    email: string;
    phone?: string;
    preferredContact?: PreferredContact;
    preferredDate?: string;
    flexibleDates?: boolean;
    groupSizeAdults?: number;
    groupSizeChildren?: number;
    budgetRange?: string;
    requirements?: string;
    status: TourEnquiryStatus;
    assignedTo?: string;
    travelStartDate?: string;
    travelEndDate?: string;
    bookingReference?: string;
    appreciationSentAt?: string;
    quotes: QuoteResponse[];
    activity: ActivityLogResponse[];
    createdDate: string;
    lastModifiedDate: string;
}

/** Matches EnquiryDashboardSummary. */
export interface EnquiryDashboardSummary {
    newCount: number;
    contactedCount: number;
    quotedCount: number;
    convertedCount: number;
    completedCount: number;
    lostCount: number;
    unassignedCount: number;
    overdueFollowUpCount: number;
    upcomingDeparturesCount: number;
    pendingAppreciationCount: number;
}

/**
 * Spring Data's Page<T> serializes with more fields than this in practice
 * (pageable, sort, first/last, etc.) — this is the minimal subset actually
 * used by the admin dashboard today. Widen it if you start relying on the
 * others.
 */
export interface PagedResponse<T> {
    content: T[];
    totalPages: number;
    totalElements: number;
    number: number;
}