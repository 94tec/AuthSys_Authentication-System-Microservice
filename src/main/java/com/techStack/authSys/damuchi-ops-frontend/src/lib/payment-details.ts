// lib/payment-details.ts
// ⚠️ These values also live in QuotePdfService (backend). Keep both in sync,
// or move them to backend config and serve them from one endpoint later.
export const PAYMENT_DETAILS = {
    mpesa: { paybill: "522522", account: "2037863" },
    bank: {
        name: "KCB Bank Kenya",
        accountName: "Damuchi Tours",
        accountNumber: "1091234323",
        branch: "Mtwapa",
        swift: "KCBLKENX", // ⚠️ placeholder, confirm the real SWIFT/BIC with KCB
    },
    depositPercent: 30,
} as const;

// Same wording as the terms printed on the quote PDF.
export const PAYMENT_TERMS = [
    `A ${PAYMENT_DETAILS.depositPercent}% deposit is due within 72 hours of accepting the quote to confirm your booking.`,
    "The remaining balance is due no later than 14 days before your travel start date.",
    "Bookings made within 14 days of travel require full payment upfront.",
    "Your booking is confirmed only after our team verifies your payment. Submitting a reference is not confirmation.",
    "Quoted prices are valid until the date shown on the quote.",
];