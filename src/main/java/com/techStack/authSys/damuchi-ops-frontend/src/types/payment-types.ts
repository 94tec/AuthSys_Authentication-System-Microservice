// types/payment-types.ts

export type PaymentChannel = "MPESA" | "BANK_TRANSFER";
export type PaymentSubmissionStatus = "PENDING_VERIFICATION" | "VERIFIED" | "REJECTED";


export interface PaymentSubmissionResponse {
    isBalancePayment: boolean;
    id: string;
    quoteId: string;
    enquiryId: string;
    tourId: string;
    customerName: string;
    tourName: string;
    channel: PaymentChannel;
    referenceCode: string;
    amountPaid: number;
    quoteTotal: number;
    currency: string;
    adultCount: number;
    childCount: number;
    payerName?: string;
    status: PaymentSubmissionStatus;
    verifiedBy?: string;
    verifiedAt?: string;
    rejectionReason?: string;
    bookingReference?: string;
    createdDate: string;
}

export interface TravelerInfo {
    fullName: string;
    dateOfBirth?: string;
    passportNumber?: string;
    nationality?: string;
    dietaryNotes?: string;
}

export interface CreateBookingPayload {
    availabilityId: string;
    pickupLocation?: string;
    pickupTime?: string; // "HH:mm"
    specialInstructions?: string;
    travelers: TravelerInfo[];
}

export interface BookingCreatedResponse {
    bookingId: string;
    bookingReference: string;
    tourName: string;
    travelStartDate: string;
    travelEndDate: string;
    pickupLocation?: string;
    pickupTime?: string;
    totalPrice: number;
    currency: string;
}