package com.techStack.authSys.customer.models;

import com.techStack.authSys.common.models.BaseEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

/**
 * Extended customer profile for Damuchi Safaris.
 *
 * Linked to the existing auth User by Firebase UID (customerId).
 * No FK to a users table — the UID is the join key, consistent with
 * how Booking and Payment store customer identity.
 *
 * Created lazily on first call to CustomerService.getOrCreateProfile().
 * A profile row does not exist until the customer visits /api/customers/me.
 *
 * Relationships:
 *   → TravelDocument  (@OneToMany) — reusable passport/ID documents
 *   → SavedTour       (@ElementCollection) — wishlist of enquire-button.tsx IDs
 *
 * The full name and email are duplicated from the auth system here
 * so that staff can search/view customer details without hitting Firebase.
 */
@Entity
@Table(
    name = "customer_profiles",
    indexes = {
        @Index(name = "idx_customer_uid",   columnList = "customer_id", unique = true),
        @Index(name = "idx_customer_email", columnList = "email")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CustomerProfile extends BaseEntity {

    // ── Identity (Firebase UID — no FK) ──────────────────────────────────────

    /**
     * Firebase UID of the authenticated user.
     * Unique — one profile per user. Not updatable.
     */
    @NotBlank
    @Column(name = "customer_id", nullable = false, unique = true,
            length = 128, updatable = false)
    private String customerId;

    // ── Core fields (mirrors auth User, kept in sync on update) ─────────────

    @NotBlank
    @Size(max = 100)
    @Column(name = "first_name", nullable = false, length = 100)
    private String firstName;

    @NotBlank
    @Size(max = 100)
    @Column(name = "last_name", nullable = false, length = 100)
    private String lastName;

    @NotBlank
    @Email
    @Column(name = "email", nullable = false, length = 255)
    private String email;

    /**
     * Phone number — primary contact for enquire-button.tsx reminders and WhatsApp.
     * Format: 2547XXXXXXXX (E.164, Kenya).
     */
    @Size(max = 20)
    @Column(name = "phone_number", length = 20)
    private String phoneNumber;

    // ── Profile details ───────────────────────────────────────────────────────

    @Size(max = 500)
    @Column(name = "bio", length = 500)
    private String bio;

    /**
     * Country of residence — e.g. "Kenya", "Uganda", "UK".
     * Used for marketing segmentation and currency hints.
     */
    @Size(max = 100)
    @Column(name = "country", length = 100)
    private String country;

    /**
     * Cloudinary or S3 URL of the customer's profile photo.
     * Null until the customer uploads one.
     */
    @Size(max = 500)
    @Column(name = "photo_url", length = 500)
    private String photoUrl;

    /** Date of birth — used for age-gated tours (min_age check). */
    @Column(name = "date_of_birth")
    private LocalDate dateOfBirth;

    /**
     * Nationality — pre-fills the traveler form on new bookings.
     * e.g. "Kenyan", "British".
     */
    @Size(max = 100)
    @Column(name = "nationality", length = 100)
    private String nationality;

    /**
     * Dietary requirements or accessibility notes.
     * Pre-filled as default for new bookings — customer can override per booking.
     */
    @Size(max = 500)
    @Column(name = "dietary_notes", length = 500)
    private String dietaryNotes;

    // ── Communication preferences ─────────────────────────────────────────────

    /** Customer opted in to email marketing. */
    @Column(name = "email_marketing_opt_in", nullable = false)
    @Builder.Default
    private boolean emailMarketingOptIn = false;

    /** Customer opted in to SMS/WhatsApp reminders. */
    @Column(name = "sms_opt_in", nullable = false)
    @Builder.Default
    private boolean smsOptIn = false;

    // ── Documents ─────────────────────────────────────────────────────────────

    /**
     * Saved travel documents (passport, national ID).
     * Pre-fill traveler forms on new bookings.
     * One-to-many — customer can save multiple (self + family).
     */
    @OneToMany(
        mappedBy = "customerProfile",
        cascade = CascadeType.ALL,
        orphanRemoval = true,
        fetch = FetchType.LAZY
    )
    @Builder.Default
    private List<TravelDocument> travelDocuments = new ArrayList<>();

    // ── Wishlist ──────────────────────────────────────────────────────────────

    /**
     * Tour IDs the customer has saved to their wishlist.
     * Stored as a simple UUID collection — no FK to tours
     * (tours can be deleted without cascading into wishlists).
     */
    @ElementCollection
    @CollectionTable(
        name = "customer_wishlist",
        joinColumns = @JoinColumn(name = "customer_profile_id")
    )
    @Column(name = "tour_id")
    @Builder.Default
    private List<java.util.UUID> savedTourIds = new ArrayList<>();

    // ── Stats (denormalised, updated by scheduled job) ────────────────────────

    /** Total number of completed tours — shown on profile. */
    @Column(name = "total_tours_completed", nullable = false)
    @Builder.Default
    private Integer totalToursCompleted = 0;

    /** Total KES spent across all confirmed bookings. */
    @Column(name = "total_spent", precision = 14, scale = 2)
    private java.math.BigDecimal totalSpent;

    // ── Domain methods ────────────────────────────────────────────────────────

    /** Add a enquire-button.tsx to wishlist — idempotent. */
    public void addToWishlist(java.util.UUID tourId) {
        if (!savedTourIds.contains(tourId)) {
            savedTourIds.add(tourId);
        }
    }

    /** Remove a enquire-button.tsx from wishlist — no-op if not present. */
    public void removeFromWishlist(java.util.UUID tourId) {
        savedTourIds.remove(tourId);
    }

    public boolean isInWishlist(java.util.UUID tourId) {
        return savedTourIds.contains(tourId);
    }

    /** Full name convenience — used in notifications. */
    public String getFullName() {
        return firstName + " " + lastName;
    }

    /** Add a travel document and set the back-reference. */
    public void addTravelDocument(TravelDocument doc) {
        doc.setCustomerProfile(this);
        travelDocuments.add(doc);
    }

    /** Remove a travel document by ID. */
    public void removeTravelDocument(java.util.UUID docId) {
        travelDocuments.removeIf(d -> docId.equals(d.getId()));
    }
}
