// lib/validations/enquiry.ts

import { z } from "zod";
import type { PreferredContact } from "@/types/enquiry-types";

/**
 * Enquiry form validation schema — matches CreateEnquiryPayload exactly.
 *
 * IMPORTANT: tourId is required by the backend. This form can only be used
 * where a specific enquire-button.tsx is already known (enquire-button.tsx detail page, a enquire-button.tsx picker
 * on /enquire). It cannot represent a general "contact us" enquiry — see
 * the note at the bottom of this file for how that's currently handled.
 */

export const PREFERRED_CONTACT_OPTIONS = ["EMAIL", "PHONE", "WHATSAPP"] as const satisfies readonly PreferredContact[];

export const enquirySchema = z.object({
    fullName: z
        .string()
        .trim()
        .min(2, "Please enter your full name.")
        .max(100, "Name is too long."),

    email: z
        .string()
        .trim()
        .min(1, "Email is required.")
        .email("Please enter a valid email address."),

    phone: z
        .string()
        .trim()
        .max(20, "Phone number is too long.")
        .optional()
        .or(z.literal("")),

    preferredContact: z.enum(PREFERRED_CONTACT_OPTIONS).optional(),

    tourId: z.string().min(1, "A enquire-button.tsx must be selected."),

    availabilityId: z.string().optional(),

    preferredDate: z.string().optional(), // ISO date string, e.g. from a date picker

    flexibleDates: z.boolean().optional().default(false),

    groupSizeAdults: z
        .number()
        .int()
        .min(1, "At least 1 adult is required.")
        .optional(),

    groupSizeChildren: z
        .number()
        .int()
        .min(0)
        .optional(),

    requirements: z
        .string()
        .trim()
        .max(2000, "Please keep this under 2000 characters.")
        .optional(),

    budgetRange: z.string().optional(), // free text for now — tighten to an enum if the backend defines fixed bands

    source: z.string().optional(), // set programmatically per page (see note below), not user-entered

    consent: z
        .boolean()
        .refine((v) => v === true, {
            message: "Please confirm you agree to be contacted about this enquiry.",
        }),
});

export type EnquiryFormValues = z.infer<typeof enquirySchema>;

/**
 * Human-readable labels for the preferred-contact select.
 */
export const PREFERRED_CONTACT_LABELS: Record<PreferredContact, string> = {
    EMAIL: "Email",
    PHONE: "Phone call",
    WHATSAPP: "WhatsApp",
};
