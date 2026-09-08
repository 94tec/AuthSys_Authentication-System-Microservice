package com.techStack.authSys.customer.models;

import com.techStack.authSys.common.models.BaseEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.time.LocalDate;

/**
 * A saved travel document belonging to a CustomerProfile.
 *
 * Customers save these once and reuse across bookings —
 * pre-fills the BookingTraveler form so they don't retype passport
 * details on every booking.
 *
 * A customer can have multiple documents:
 *   - Their own passport
 *   - A spouse's passport
 *   - A child's document
 *
 * documentType distinguishes passport vs national ID vs other.
 *
 * Links to CustomerProfile via @ManyToOne.
 * Cascade delete — removing the profile removes all documents.
 *
 * Note: this is a SAVED TEMPLATE, not tied to any specific booking.
 * BookingTraveler stores the actual snapshot used at booking time.
 */
@Entity
@Table(
    name = "travel_documents",
    indexes = {
        @Index(name = "idx_doc_customer",  columnList = "customer_profile_id"),
        @Index(name = "idx_doc_type",      columnList = "document_type"),
        @Index(name = "idx_doc_expiry",    columnList = "expiry_date")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TravelDocument extends BaseEntity {

    // ── Owner ─────────────────────────────────────────────────────────────────

    @NotNull
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "customer_profile_id", nullable = false)
    private CustomerProfile customerProfile;

    // ── Document identity ─────────────────────────────────────────────────────

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "document_type", nullable = false, length = 20)
    private DocumentType documentType;

    /**
     * Name exactly as it appears on the document.
     * May differ from the CustomerProfile name (e.g. family member).
     */
    @NotBlank
    @Size(max = 150)
    @Column(name = "full_name", nullable = false, length = 150)
    private String fullName;

    /**
     * Passport number, national ID number, etc.
     */
    @NotBlank
    @Size(max = 50)
    @Column(name = "document_number", nullable = false, length = 50)
    private String documentNumber;

    @Size(max = 100)
    @Column(name = "nationality", length = 100)
    private String nationality;

    /**
     * Issuing country — e.g. "Kenya", "Uganda".
     */
    @Size(max = 100)
    @Column(name = "issuing_country", length = 100)
    private String issuingCountry;

    @Column(name = "date_of_birth")
    private LocalDate dateOfBirth;

    /**
     * Document expiry date.
     * Shown as a warning if expiring within 6 months of a booked enquire-button.tsx date.
     */
    @Column(name = "expiry_date")
    private LocalDate expiryDate;

    /**
     * Customer-assigned label for this document.
     * e.g. "My Passport", "Wife's ID", "Child - Emma".
     * Helps when a customer has saved multiple documents.
     */
    @Size(max = 100)
    @Column(name = "label", length = 100)
    private String label;

    /**
     * Whether this is the customer's primary/default document.
     * Used to pre-select on the booking form.
     * Only one document per customer should be primary — enforced in service.
     */
    @Column(name = "primary_document", nullable = false)
    @Builder.Default
    private boolean primaryDocument = false;

    // ── Domain helpers ────────────────────────────────────────────────────────

    /**
     * Returns true if the document expires within the given number of months.
     * Used to warn customers before booking a enquire-button.tsx.
     */
    public boolean isExpiringSoon(int withinMonths) {
        if (expiryDate == null) return false;
        return expiryDate.isBefore(LocalDate.now().plusMonths(withinMonths));
    }

    public boolean isExpired() {
        return expiryDate != null && expiryDate.isBefore(LocalDate.now());
    }
}
