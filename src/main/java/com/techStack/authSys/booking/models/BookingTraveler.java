package com.techStack.authSys.booking.models;

import com.techStack.authSys.common.models.BaseEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.time.LocalDate;

@Entity
@Table(
        name = "booking_travelers",
        indexes = {
                @Index(
                        name = "idx_booking_travelers_booking_id",
                        columnList = "booking_id"
                )
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BookingTraveler extends BaseEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "booking_id",
            nullable = false,
            foreignKey = @ForeignKey(name = "fk_traveler_booking")
    )
    private Booking booking;

    @NotBlank(message = "Traveler full name is required")
    @Size(max = 255)
    @Column(name = "full_name", nullable = false, length = 255)
    private String fullName;

    @Column(name = "date_of_birth")
    private LocalDate dateOfBirth;

    @Size(max = 50)
    @Column(name = "passport_number", length = 50)
    private String passportNumber;

    @Size(max = 100)
    @Column(name = "nationality", length = 100)
    private String nationality;

    @Size(max = 500)
    @Column(name = "dietary_notes", length = 500)
    private String dietaryNotes;

    /**
     * Marks the traveler who made the booking —
     * typically the authenticated customer themselves.
     * Always exactly one lead per booking (enforced by BookingService).
     */
    @Column(name = "is_lead_traveler", nullable = false)
    @Builder.Default
    private boolean leadTraveler = false;
}