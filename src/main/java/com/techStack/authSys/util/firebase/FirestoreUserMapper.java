package com.techStack.authSys.util.firebase;

import com.google.cloud.Timestamp;
import com.google.cloud.firestore.DocumentSnapshot;
import com.techStack.authSys.models.user.ApprovalLevel;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.*;

/**
 * Firestore User Mapper
 *
 * Maps between Firestore documents and User domain objects.
 *
 * Fix summary:
 *   1. knownDeviceFingerprints — User has no such field. That field belongs to
 *      UserDocument (flat List<String>) and SecurityMetadata (in-memory). Removed
 *      from mapToUser() and userToMap() entirely. Callers that need device
 *      fingerprints should read them from UserDocument via UserAssembler.
 *
 *   2. getMapObject() returned Map<String,Object> but User.attributes is
 *      Map<String,String>. Replaced with getStringMap() which casts each value
 *      via toString(), matching Firestore's own constraint that attribute maps
 *      must be Map<String,String>.
 *
 *   3. parseTimestampToInstant() had a duplicate branch: "Case 1: Firestore Timestamp"
 *      and "Case 2: com.google.cloud.Timestamp" tested the same class because
 *      com.google.cloud.Timestamp IS Timestamp (same import). Case 2 was dead code
 *      and is removed.
 */
@Slf4j
public class FirestoreUserMapper {

    /* =========================
       Main Mapping Methods
       ========================= */

    /**
     * Maps Firestore document data to User object with safe type conversions.
     */
    public static User mapToUser(Map<String, Object> data) {
        if (data == null || data.isEmpty()) {
            log.debug("Empty or null data provided for user mapping");
            return null;
        }

        try {
            User user = new User();

            // ==================== CORE IDENTITY ====================
            user.setId(getString(data, "id"));
            user.setEmail(getString(data, "email"));
            user.setFirstName(getString(data, "firstName"));
            user.setLastName(getString(data, "lastName"));
            user.setUsername(getString(data, "username"));
            user.setIdentityNo(getString(data, "identityNo"));
            user.setPhoneNumber(getString(data, "phoneNumber"));
            user.setDepartment(getString(data, "department"));

            // ==================== BOOLEAN FIELDS ====================
            user.setEnabled(getBoolean(data, "enabled", true));
            user.setEmailVerified(getBoolean(data, "emailVerified", false));
            user.setForcePasswordChange(getBoolean(data, "forcePasswordChange", false));
            user.setAccountLocked(getBoolean(data, "accountLocked", false));
            user.setAccountDisabled(getBoolean(data, "accountDisabled", false));
            user.setMfaEnabled(getBoolean(data, "mfaEnabled", false));
            user.setMfaRequired(getBoolean(data, "mfaRequired", false));

            // ==================== STATUS & APPROVAL ====================
            user.setStatus(getUserStatus(data, "status"));
            user.setApprovalLevel(getApprovalLevel(data, "approvalLevel"));

            // ==================== ROLES & PERMISSIONS ====================
            user.setRoleNames(getStringList(data, "roleNames"));
            user.setAdditionalPermissions(getStringList(data, "additionalPermissions"));

            // ==================== NUMERIC FIELDS ====================
            user.setLoginAttempts(getInteger(data, "loginAttempts", 0));
            user.setFailedLoginAttempts(getInteger(data, "failedLoginAttempts", 0));

            // ==================== SECURITY & AUDIT ====================
            user.setCreatedBy(getString(data, "createdBy"));
            user.setOtpSecret(getString(data, "otpSecret"));
            user.setLastLoginIp(getString(data, "lastLoginIp"));
            user.setLastLoginUserAgent(getString(data, "lastLoginUserAgent"));

            // ==================== PROFILE ====================
            user.setProfilePictureUrl(getString(data, "profilePictureUrl"));
            user.setBio(getString(data, "bio"));
            user.setUserProfileId(getString(data, "userProfileId"));

            // ==================== VERIFICATION TOKENS ====================
            user.setVerificationTokenHash(getString(data, "verificationTokenHash"));
            user.setPasswordResetTokenHash(getString(data, "passwordResetTokenHash"));

            // ==================== APPROVAL FIELDS ====================
            user.setApprovedBy(getString(data, "approvedBy"));
            user.setRejectedBy(getString(data, "rejectedBy"));
            user.setRejectionReason(getString(data, "rejectionReason"));

            // ==================== TIMESTAMPS ====================
            user.setCreatedAt(parseTimestampToInstant(data, "createdAt"));
            user.setUpdatedAt(parseTimestampToInstant(data, "updatedAt"));
            user.setLastLogin(parseTimestampToInstant(data, "lastLogin"));
            user.setPasswordLastChanged(parseTimestampToInstant(data, "passwordLastChanged"));
            user.setPasswordExpiresAt(parseTimestampToInstant(data, "passwordExpiresAt"));
            user.setVerificationTokenExpiresAt(parseTimestampToInstant(data, "verificationTokenExpiresAt"));
            user.setPasswordResetTokenExpiresAt(parseTimestampToInstant(data, "passwordResetTokenExpiresAt"));
            user.setApprovedAt(parseTimestampToInstant(data, "approvedAt"));
            user.setRejectedAt(parseTimestampToInstant(data, "rejectedAt"));

            // ==================== COLLECTIONS ====================
            // Fix: User.attributes is Map<String,String> — use getStringMap(), not getMapObject()
            // Fix: User has no knownDeviceFingerprints field — removed entirely
            user.setAttributes(getStringMap(data, "attributes"));

            log.debug("Successfully mapped user with ID: {}", user.getId());
            return user;

        } catch (Exception e) {
            log.error("❌ Error mapping data to User: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Maps DocumentSnapshot to User object.
     */
    public static User documentToUser(DocumentSnapshot doc) {
        if (doc == null || !doc.exists()) {
            log.debug("Document does not exist or is null");
            return null;
        }

        try {
            User user = mapToUser(doc.getData());
            if (user != null && user.getId() == null) {
                user.setId(doc.getId());
            }
            return user;
        } catch (Exception e) {
            log.error("❌ Error mapping document {} to User: {}",
                    doc.getId(), e.getMessage(), e);
            return null;
        }
    }

    /**
     * Batch mapping utility.
     */
    public static List<User> mapToUsers(List<DocumentSnapshot> documents) {
        if (documents == null || documents.isEmpty()) {
            return Collections.emptyList();
        }

        List<User> users = new ArrayList<>();
        for (DocumentSnapshot doc : documents) {
            User user = documentToUser(doc);
            if (user != null) {
                users.add(user);
            }
        }
        return users;
    }

    /* =========================
       Reverse Mapping (User → Map)
       ========================= */

    /**
     * Reverse mapper: User to Map (for save/update operations).
     */
    public static Map<String, Object> userToMap(User user) {
        if (user == null) {
            return Collections.emptyMap();
        }

        Map<String, Object> data = new HashMap<>();

        // ==================== CORE IDENTITY ====================
        putIfNotNull(data, "id", user.getId());
        putIfNotNull(data, "email", user.getEmail());
        putIfNotNull(data, "firstName", user.getFirstName());
        putIfNotNull(data, "lastName", user.getLastName());
        putIfNotNull(data, "username", user.getUsername());
        putIfNotNull(data, "identityNo", user.getIdentityNo());
        putIfNotNull(data, "phoneNumber", user.getPhoneNumber());
        putIfNotNull(data, "department", user.getDepartment());

        // ==================== BOOLEAN FIELDS ====================
        data.put("enabled", user.isEnabled());
        data.put("emailVerified", user.isEmailVerified());
        data.put("forcePasswordChange", user.isForcePasswordChange());
        data.put("accountLocked", user.isAccountLocked());
        data.put("accountDisabled", user.isAccountDisabled());
        data.put("mfaEnabled", user.isMfaEnabled());
        data.put("mfaRequired", user.isMfaRequired());

        // ==================== STATUS & APPROVAL ====================
        if (user.getStatus() != null) {
            data.put("status", user.getStatus().name());
        }
        if (user.getApprovalLevel() != null) {
            data.put("approvalLevel", user.getApprovalLevel().name());
        }

        // ==================== ROLES & PERMISSIONS ====================
        data.put("roleNames", user.getRoleNames() != null
                ? user.getRoleNames() : new ArrayList<>());
        data.put("additionalPermissions", user.getAdditionalPermissions() != null
                ? user.getAdditionalPermissions() : new ArrayList<>());

        // ==================== NUMERIC FIELDS ====================
        data.put("loginAttempts", user.getLoginAttempts());
        data.put("failedLoginAttempts", user.getFailedLoginAttempts());

        // ==================== SECURITY & AUDIT ====================
        putIfNotNull(data, "createdBy", user.getCreatedBy());
        putIfNotNull(data, "otpSecret", user.getOtpSecret());
        putIfNotNull(data, "lastLoginIp", user.getLastLoginIp());
        putIfNotNull(data, "lastLoginUserAgent", user.getLastLoginUserAgent());

        // ==================== PROFILE ====================
        putIfNotNull(data, "profilePictureUrl", user.getProfilePictureUrl());
        putIfNotNull(data, "bio", user.getBio());
        putIfNotNull(data, "userProfileId", user.getUserProfileId());

        // ==================== VERIFICATION TOKENS ====================
        putIfNotNull(data, "verificationTokenHash", user.getVerificationTokenHash());
        putIfNotNull(data, "passwordResetTokenHash", user.getPasswordResetTokenHash());

        // ==================== APPROVAL FIELDS ====================
        putIfNotNull(data, "approvedBy", user.getApprovedBy());
        putIfNotNull(data, "rejectedBy", user.getRejectedBy());
        putIfNotNull(data, "rejectionReason", user.getRejectionReason());

        // ==================== TIMESTAMPS ====================
        putTimestamp(data, "createdAt", user.getCreatedAt());
        putTimestamp(data, "updatedAt", user.getUpdatedAt());
        putTimestamp(data, "lastLogin", user.getLastLogin());
        putTimestamp(data, "passwordLastChanged", user.getPasswordLastChanged());
        putTimestamp(data, "passwordExpiresAt", user.getPasswordExpiresAt());
        putTimestamp(data, "verificationTokenExpiresAt", user.getVerificationTokenExpiresAt());
        putTimestamp(data, "passwordResetTokenExpiresAt", user.getPasswordResetTokenExpiresAt());
        putTimestamp(data, "approvedAt", user.getApprovedAt());
        putTimestamp(data, "rejectedAt", user.getRejectedAt());

        // ==================== COLLECTIONS ====================
        // Fix: User has no getKnownDeviceFingerprints() — removed entirely
        if (user.getAttributes() != null) {
            data.put("attributes", user.getAttributes());
        }

        return data;
    }

    /* =========================
       Safe Type Extractors
       ========================= */

    private static String getString(Map<String, Object> data, String key) {
        Object value = data.get(key);
        return value != null ? value.toString() : null;
    }

    private static boolean getBoolean(Map<String, Object> data, String key, boolean defaultValue) {
        Object value = data.get(key);
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        return defaultValue;
    }

    private static int getInteger(Map<String, Object> data, String key, int defaultValue) {
        Object value = data.get(key);
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        return defaultValue;
    }

    @SuppressWarnings("unchecked")
    private static List<String> getStringList(Map<String, Object> data, String key) {
        Object value = data.get(key);
        if (value == null) return new ArrayList<>();

        if (value instanceof List) {
            try {
                List<Object> list = (List<Object>) value;
                List<String> result = new ArrayList<>();
                for (Object item : list) {
                    if (item != null) result.add(item.toString());
                }
                return result;
            } catch (ClassCastException e) {
                log.warn("⚠️ Failed to cast {} to List: {}", key, e.getMessage());
            }
        }
        return new ArrayList<>();
    }

    /**
     * Extracts a Map<String,String> from Firestore data.
     *
     * Fix: replaces the old getMapObject() which returned Map<String,Object>.
     * User.attributes is Map<String,String> (Firestore constraint — no Object values).
     * Each value is converted via toString() to satisfy the type, matching
     * how UserDocument.attributes is declared and how the ABAC system reads it.
     */
    @SuppressWarnings("unchecked")
    private static Map<String, String> getStringMap(Map<String, Object> data, String key) {
        Object value = data.get(key);
        if (value == null) return new HashMap<>();

        if (value instanceof Map) {
            try {
                Map<Object, Object> raw = (Map<Object, Object>) value;
                Map<String, String> result = new HashMap<>();
                raw.forEach((k, v) -> {
                    if (k != null && v != null) {
                        result.put(k.toString(), v.toString());
                    }
                });
                return result;
            } catch (ClassCastException e) {
                log.warn("⚠️ Failed to cast {} to Map: {}", key, e.getMessage());
            }
        }
        return new HashMap<>();
    }

    private static UserStatus getUserStatus(Map<String, Object> data, String key) {
        String statusStr = getString(data, key);
        if (statusStr == null) return UserStatus.PENDING_APPROVAL;

        try {
            return UserStatus.valueOf(statusStr.toUpperCase());
        } catch (IllegalArgumentException e) {
            log.warn("⚠️ Invalid status value: {}, defaulting to PENDING_APPROVAL", statusStr);
            return UserStatus.PENDING_APPROVAL;
        }
    }

    private static ApprovalLevel getApprovalLevel(Map<String, Object> data, String key) {
        String levelStr = getString(data, key);
        if (levelStr == null) return null;

        try {
            return ApprovalLevel.valueOf(levelStr.toUpperCase());
        } catch (IllegalArgumentException e) {
            log.warn("⚠️ Invalid approval level value: {}", levelStr);
            return null;
        }
    }

    /* =========================
       Timestamp Conversion
       ========================= */

    /**
     * Parse Firestore Timestamp to Instant.
     *
     * Fix: removed duplicate "Case 2: com.google.cloud.Timestamp" branch —
     * com.google.cloud.Timestamp IS the same class as the imported Timestamp,
     * so the second instanceof check was unreachable dead code.
     */
    private static Instant parseTimestampToInstant(Map<String, Object> data, String key) {
        Object value = data.get(key);
        if (value == null) return null;

        // Firestore Timestamp (com.google.cloud.Timestamp)
        if (value instanceof Timestamp ts) {
            return Instant.ofEpochSecond(ts.getSeconds(), ts.getNanos());
        }

        // Already an Instant
        if (value instanceof Instant instant) {
            return instant;
        }

        // ISO-8601 String (backward compatibility)
        if (value instanceof String str) {
            try {
                return Instant.parse(str);
            } catch (Exception e) {
                log.debug("⚠️ Failed to parse Instant from string for {}: {}", key, value);
                return null;
            }
        }

        // Epoch milliseconds as Long or Number
        if (value instanceof Long l) {
            return Instant.ofEpochMilli(l);
        }
        if (value instanceof Number n) {
            return Instant.ofEpochMilli(n.longValue());
        }

        log.debug("⚠️ Unsupported timestamp type for {}: {}", key, value.getClass().getName());
        return null;
    }

    /**
     * Convert Instant to Firestore Timestamp for saving.
     */
    private static void putTimestamp(Map<String, Object> data, String key, Instant instant) {
        if (instant != null) {
            data.put(key, Timestamp.ofTimeSecondsAndNanos(
                    instant.getEpochSecond(),
                    instant.getNano()
            ));
        }
    }

    private static void putIfNotNull(Map<String, Object> data, String key, Object value) {
        if (value != null) {
            data.put(key, value);
        }
    }
}