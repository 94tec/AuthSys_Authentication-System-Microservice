package com.techStack.authSys.models.user;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * PostgreSQL persistence model — relational anchor only.
 *
 * Responsibility: links Firebase Auth → relational data.
 * Permissions, roles, and security state live in Firestore (UserDocument).
 *
 * Keep this lean — only fields needed for SQL joins and queries.
 */
@Entity
@Table(
    name = "users",
    indexes = {
        @Index(name = "idx_users_firebase_uid", columnList = "firebase_uid"),
        @Index(name = "idx_users_email",        columnList = "email"),
        @Index(name = "idx_users_username",     columnList = "username")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    /**
     * Firebase Auth UID — cross-system key.
     * Nullable during migration; will be NOT NULL once all users migrated.
     */
    @Column(name = "firebase_uid", unique = true, length = 128)
    private String firebaseUid;

    @Column(name = "email", nullable = false, unique = true, length = 255)
    private String email;

    @Column(name = "username", unique = true, length = 50)
    private String username;

    @Column(name = "phone_number", length = 20)
    private String phoneNumber;

    @Column(name = "first_name", length = 50)
    private String firstName;

    @Column(name = "last_name", length = 50)
    private String lastName;

    @Column(name = "profile_picture_url")
    private String profilePictureUrl;

    @Column(name = "status", length = 30)
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private UserStatus status = UserStatus.PENDING_APPROVAL;

    @Column(name = "approval_level", length = 20)
    @Enumerated(EnumType.STRING)
    private ApprovalLevel approvalLevel;

    @Column(name = "is_enabled", nullable = false)
    @Builder.Default
    private boolean enabled = false;

    @Column(name = "account_locked", nullable = false)
    @Builder.Default
    private boolean accountLocked = false;

    @Column(name = "account_disabled", nullable = false)
    @Builder.Default
    private boolean accountDisabled = false;

    @Column(name = "email_verified", nullable = false)
    @Builder.Default
    private boolean emailVerified = false;

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    /* =========================
       Business Methods
       ========================= */

    public void recordLogin(Instant now) {
        this.lastLoginAt = now;
    }

    public void deactivate() {
        this.enabled = false;
        this.status  = UserStatus.DEACTIVATED;
    }

    public boolean hasFirebaseAccount() {
        return firebaseUid != null && !firebaseUid.isBlank();
    }

    public String getFullName() {
        if (firstName == null && lastName == null) return email;
        return String.format("%s %s",
            firstName != null ? firstName : "",
            lastName  != null ? lastName  : "").trim();
    }

    @Override
    public String toString() {
        return String.format("UserEntity[id=%s, email=%s, status=%s]",
            id, email, status);
    }
}