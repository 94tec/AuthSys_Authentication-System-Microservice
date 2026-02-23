package com.techStack.authSys.models.user;

import com.techStack.authSys.models.security.SecurityMetadata;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

/**
 * Assembles the User domain model from its two persistence sources.
 *
 * UserEntity  (PostgreSQL) + UserDocument (Firestore) → User (domain)
 *
 * Called by UserService after loading both records.
 * Also provides the reverse: domain → persistence model updates.
 */
@Component
public class UserAssembler {

    /**
     * Assemble a User domain model from both persistence sources.
     * UserDocument is the primary source — UserEntity fills in
     * relational fields only available in PostgreSQL.
     */
    public User assemble(UserDocument doc, UserEntity entity) {
        User user = User.builder()
                // Identity — from document (richer source)
                .id(doc.getId())
                .firebaseUid(doc.getId())
                .email(doc.getEmail())
                .firstName(doc.getFirstName())
                .lastName(doc.getLastName())
                .username(doc.getUsername())
                .identityNo(doc.getIdentityNo())
                .phoneNumber(doc.getPhoneNumber())
                .profilePictureUrl(doc.getProfilePictureUrl())
                .bio(doc.getBio())
                .userProfileId(doc.getUserProfileId())
                .department(doc.getDepartment())
                // Roles & permissions
                .roleNames(new ArrayList<>(doc.getRoleNames()))
                .additionalPermissions(new ArrayList<>(doc.getAdditionalPermissions()))
                .requestedRoleNames(new ArrayList<>(doc.getRequestedRoleNames()))
                .attributes(doc.getAttributes())
                // Account state
                .status(doc.getUserStatus())
                .enabled(doc.isEnabled())
                .accountLocked(doc.isAccountLocked())
                .accountDisabled(doc.isAccountDisabled())
                .emailVerified(doc.isEmailVerified())
                .phoneVerified(doc.isPhoneVerified())
                .forcePasswordChange(doc.isForcePasswordChange())
                // Approval
                .approvalLevel(doc.getApprovalLevelEnum())
                .approvedAt(doc.getApprovedAt())
                .approvedBy(doc.getApprovedBy())
                .rejectedAt(doc.getRejectedAt())
                .rejectedBy(doc.getRejectedBy())
                .rejectionReason(doc.getRejectionReason())
                // Security
                .mfaEnabled(doc.isMfaEnabled())
                .mfaRequired(doc.isMfaRequired())
                .failedLoginAttempts(doc.getFailedLoginAttempts())
                .loginAttempts(doc.getLoginAttempts())
                .lastLogin(doc.getLastLogin())
                .lastLoginIp(doc.getLastLoginIp())
                .lastLoginUserAgent(doc.getLastLoginUserAgent())
                // Password
                .passwordLastChanged(doc.getPasswordLastChanged())
                .passwordExpiresAt(doc.getPasswordExpiresAt())
                //.passwordCompromised(doc.isPasswordCompromised())
                .firstTimeSetupCompleted(doc.isFirstTimeSetupCompleted())
                .temporaryPasswordLocked(doc.isTemporaryPasswordLocked())
                // Audit
                .createdAt(doc.getCreatedAt())
                .createdBy(doc.getCreatedBy())
                .updatedAt(doc.getUpdatedAt())
                .build();

        // Rebuild SecurityMetadata from flat fields in UserDocument
        user.setSecurityMetadata(buildSecurityMetadata(doc));

        return user;
    }

    /**
     * Rebuild SecurityMetadata from flat Firestore fields.
     * SecurityMetadata lives in memory only — never persisted as an object.
     */
    private SecurityMetadata buildSecurityMetadata(UserDocument doc) {
        return SecurityMetadata.builder()
                .failedLoginAttempts(doc.getFailedLoginAttempts())
                .lastLoginAt(doc.getLastLogin())
                .lastLoginIp(doc.getLastLoginIp())
                .lastLoginCountry(doc.getLastLoginCountry())
                .lastLoginCity(doc.getLastLoginCity())
                .lastLoginDeviceId(doc.getLastLoginDeviceId())
                .lastLoginUserAgent(doc.getLastLoginUserAgent())
                .accountLockedUntil(doc.getAccountLockedUntil())
                .lockReason(doc.getLockReason())
                .lockType(doc.getLockType() != null
                        ? SecurityMetadata.LockType.valueOf(doc.getLockType()) : null)
                .riskScore(doc.getRiskScore())
                .riskLevel(doc.getRiskLevel() != null
                        ? SecurityMetadata.RiskLevel.valueOf(doc.getRiskLevel()) : null)
                .riskExplanation(doc.getRiskExplanation())
                .riskScoreUpdatedAt(doc.getRiskScoreUpdatedAt())
                .knownDeviceFingerprints(new ArrayList<>(doc.getKnownDeviceFingerprints()))
                .mfaEnabled(doc.isMfaEnabled())
                .passwordLastChangedAt(doc.getPasswordLastChanged())
                .passwordCompromised(doc.isPasswordCompromised())
                .compromiseSource(doc.getCompromiseSource())
                .build();
    }

    /**
     * Apply domain model changes back to UserDocument for Firestore persistence.
     * Called when security state or account state changes in the domain.
     */
    public void applyToDocument(User user, UserDocument doc) {
        doc.setUserStatus(user.getStatus());
        doc.setEnabled(user.isEnabled());
        doc.setAccountLocked(user.isAccountLocked());
        doc.setFailedLoginAttempts(user.getFailedLoginAttempts());
        doc.setLoginAttempts(user.getLoginAttempts());
        doc.setLastLogin(user.getLastLogin());
        doc.setLastLoginIp(user.getLastLoginIp());
        doc.setLastLoginUserAgent(user.getLastLoginUserAgent());
        doc.setApprovalLevelEnum(user.getApprovalLevel());
        doc.setApprovedAt(user.getApprovedAt());
        doc.setApprovedBy(user.getApprovedBy());
        doc.setRejectedAt(user.getRejectedAt());
        doc.setRejectedBy(user.getRejectedBy());
        doc.setRejectionReason(user.getRejectionReason());

        // Sync SecurityMetadata flat fields back to document
        SecurityMetadata meta = user.getSecurityMetadata();
        if (meta != null) {
            doc.setAccountLockedUntil(meta.getAccountLockedUntil());
            doc.setLockReason(meta.getLockReason());
            doc.setLockType(meta.getLockType() != null
                    ? meta.getLockType().name() : null);
            doc.setRiskScore(meta.getRiskScore());
            doc.setRiskLevel(meta.getRiskLevel() != null
                    ? meta.getRiskLevel().name() : null);
            doc.setRiskExplanation(meta.getRiskExplanation());
            doc.setKnownDeviceFingerprints(
                    new ArrayList<>(meta.getKnownDeviceFingerprints()));
        }
    }
}
