package com.techStack.authSys.util;

import com.google.cloud.Timestamp;
import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.GeoPoint;
import com.google.cloud.firestore.QueryDocumentSnapshot;
import com.techStack.authSys.models.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.*;

/**
 * Enhanced Firestore-to-User mapper that handles all timestamp formats from your code
 */
public class FirestoreUserMapper {

    private static final Logger logger = LoggerFactory.getLogger(FirestoreUserMapper.class);

    /**
     * Maps Firestore document data to User object with safe type conversions
     */
    public static User mapToUser(Map<String, Object> data) {
        if (data == null || data.isEmpty()) {
            logger.debug("Empty or null data provided for user mapping");
            return null;
        }

        try {
            User user = new User();

            // Basic Info
            user.setId(getString(data, "id"));
            user.setEmail(getString(data, "email"));
            user.setFirstName(getString(data, "firstName"));
            user.setLastName(getString(data, "lastName"));
            user.setUsername(getString(data, "username"));
            user.setIdentityNo(getString(data, "identityNo"));
            user.setPhoneNumber(getString(data, "phoneNumber"));
            user.setDepartment(getString(data, "department"));

            // Boolean fields
            user.setEnabled(getBoolean(data, "enabled", true));
            user.setEmailVerified(getBoolean(data, "emailVerified", false));
            user.setForcePasswordChange(getBoolean(data, "forcePasswordChange", false));
            user.setAccountLocked(getBoolean(data, "accountLocked", false));
            user.setMfaRequired(getBoolean(data, "mfaRequired", false));

            // Status field
            user.setStatus(getUserStatus(data, "status"));

            // Lists - FIXED: Handle null values properly
            user.setRoleNames(getStringList(data, "roleNames"));
            user.setPermissions(getStringList(data, "permissions"));

            // Numeric fields
            user.setLoginAttempts(getInteger(data, "loginAttempts", 0));
            user.setFailedLoginAttempts(getInteger(data, "failedLoginAttempts", 0));

            // Security & audit fields
            user.setCreatedBy(getString(data, "createdBy"));
            user.setOtpSecret(getString(data, "otpSecret"));
            user.setLastPasswordChangeDate(getString(data, "lastPasswordChangeDate"));
            user.setDeviceFingerprint(getString(data, "deviceFingerprint"));
            user.setLastLoginIp(getString(data, "lastLoginIp"));
            user.setLastLoginIpAddress(getString(data, "lastLoginIpAddress"));

            // Profile fields
            user.setProfilePictureUrl(getString(data, "profilePictureUrl"));
            user.setBio(getString(data, "bio"));
            user.setUserProfileId(getString(data, "userProfileId"));

            // Verification tokens
            user.setVerificationToken(getString(data, "verificationToken"));
            user.setVerificationTokenHash(getString(data, "verificationTokenHash"));
            user.setPasswordResetToken(getString(data, "passwordResetToken"));

            // Timestamps - CRITICAL: Handle Firestore Timestamp format from your save method
            user.setCreatedAt(parseTimestampToInstant(data, "createdAt"));
            user.setUpdatedAt(parseTimestampToInstant(data, "updatedAt"));
            user.setLastLogin(parseTimestampToInstant(data, "lastLogin"));
            user.setLastLoginTimestamp(parseToTimestamp(data, "lastLoginTimestamp"));
            user.setVerificationTokenExpiresAt(parseTimestampToInstant(data, "verificationTokenExpiresAt"));

            // Additional fields from your model
            user.setUserAgent(getString(data, "userAgent"));
            user.setAccountNonLocked(getBoolean(data, "accountNonLocked", true));
            user.setCredentialsNonExpired(getBoolean(data, "credentialsNonExpired", true));
            user.setAccountNonExpired(getBoolean(data, "accountNonExpired", true));

            logger.debug("Successfully mapped user with ID: {}", user.getId());
            return user;

        } catch (Exception e) {
            logger.error("❌ Error mapping data to User: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Maps DocumentSnapshot to User object
     */
    public static User documentToUser(DocumentSnapshot doc) {
        if (doc == null || !doc.exists()) {
            logger.debug("Document does not exist or is null");
            return null;
        }

        try {
            User user = mapToUser(doc.getData());
            if (user != null && user.getId() == null) {
                // Fallback to document ID if not in data
                user.setId(doc.getId());
            }
            return user;
        } catch (Exception e) {
            logger.error("❌ Error mapping document {} to User: {}",
                    doc.getId(), e.getMessage(), e);
            return null;
        }
    }

    // ==================== SAFE TYPE EXTRACTORS ====================

    private static String getString(Map<String, Object> data, String key) {
        Object value = data.get(key);
        return (value != null) ? value.toString() : null;
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

        if (value == null) {
            return new ArrayList<>();
        }

        if (value instanceof List) {
            try {
                List<Object> list = (List<Object>) value;
                List<String> stringList = new ArrayList<>();
                for (Object item : list) {
                    if (item != null) {
                        stringList.add(item.toString());
                    }
                }
                return stringList;
            } catch (ClassCastException e) {
                logger.warn("⚠️ Failed to cast {} to List: {}", key, e.getMessage());
                return new ArrayList<>();
            }
        }

        return new ArrayList<>();
    }

    private static User.Status getUserStatus(Map<String, Object> data, String key) {
        String statusStr = getString(data, key);
        if (statusStr == null) {
            return User.Status.PENDING_APPROVAL;
        }

        try {
            return User.Status.valueOf(statusStr.toUpperCase());
        } catch (IllegalArgumentException e) {
            logger.warn("⚠️ Invalid status value: {}, defaulting to PENDING_APPROVAL", statusStr);
            return User.Status.PENDING_APPROVAL;
        }
    }

    /**
     * Parse Firestore Timestamp to Instant (for your save method)
     */
    private static Instant parseTimestampToInstant(Map<String, Object> data, String key) {
        Object value = data.get(key);

        if (value == null) {
            return null;
        }

        // Case 1: Firestore Timestamp (what you're saving)
        if (value instanceof Timestamp) {
            Timestamp ts = (Timestamp) value;
            return Instant.ofEpochSecond(ts.getSeconds(), ts.getNanos());
        }

        // Case 2: com.google.cloud.Timestamp (alternative)
        if (value instanceof com.google.cloud.Timestamp) {
            com.google.cloud.Timestamp ts = (com.google.cloud.Timestamp) value;
            return Instant.ofEpochSecond(ts.getSeconds(), ts.getNanos());
        }

        // Case 3: Already an Instant
        if (value instanceof Instant) {
            return (Instant) value;
        }

        // Case 4: String (ISO format - for backward compatibility)
        if (value instanceof String) {
            try {
                return Instant.parse((String) value);
            } catch (Exception e) {
                logger.debug("⚠️ Failed to parse Instant from string for {}: {}", key, value);
                return null;
            }
        }

        // Case 5: Long (epoch milliseconds)
        if (value instanceof Long) {
            return Instant.ofEpochMilli((Long) value);
        }

        logger.debug("⚠️ Unsupported timestamp type for {}: {}", key, value.getClass().getName());
        return null;
    }

    /**
     * Parse to com.google.cloud.Timestamp for lastLoginTimestamp field
     */
    private static Timestamp parseToTimestamp(Map<String, Object> data, String key) {
        Object value = data.get(key);

        if (value == null) {
            return null;
        }

        // Case 1: Already Firestore Timestamp
        if (value instanceof Timestamp) {
            return (Timestamp) value;
        }

        // Case 2: com.google.cloud.Timestamp
        if (value instanceof com.google.cloud.Timestamp) {
            com.google.cloud.Timestamp ts = (com.google.cloud.Timestamp) value;
            return Timestamp.ofTimeSecondsAndNanos(ts.getSeconds(), ts.getNanos());
        }

        // Case 3: Instant
        if (value instanceof Instant) {
            Instant instant = (Instant) value;
            return Timestamp.ofTimeSecondsAndNanos(instant.getEpochSecond(), instant.getNano());
        }

        // Case 4: String
        if (value instanceof String) {
            try {
                Instant instant = Instant.parse((String) value);
                return Timestamp.ofTimeSecondsAndNanos(instant.getEpochSecond(), instant.getNano());
            } catch (Exception e) {
                logger.debug("⚠️ Failed to parse Timestamp from string for {}: {}", key, value);
                return null;
            }
        }

        return null;
    }

    /**
     * Batch mapping utility
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

    /**
     * Reverse mapper: User to Map (for save/update operations)
     */
    public static Map<String, Object> userToMap(User user) {
        if (user == null) {
            return Collections.emptyMap();
        }

        Map<String, Object> data = new HashMap<>();

        // Basic Info
        data.put("id", user.getId());
        data.put("email", user.getEmail());
        data.put("firstName", user.getFirstName());
        data.put("lastName", user.getLastName());
        data.put("username", user.getUsername());
        data.put("identityNo", user.getIdentityNo());
        data.put("phoneNumber", user.getPhoneNumber());
        data.put("department", user.getDepartment());

        // Boolean fields
        data.put("enabled", user.isEnabled());
        data.put("emailVerified", user.isEmailVerified());
        data.put("forcePasswordChange", user.isForcePasswordChange());
        data.put("accountLocked", user.isAccountLocked());
        data.put("mfaRequired", user.isMfaRequired());

        // Status
        if (user.getStatus() != null) {
            data.put("status", user.getStatus().name());
        }

        // Lists
        data.put("roleNames", user.getRoleNames() != null ? user.getRoleNames() : new ArrayList<>());
        data.put("permissions", user.getPermissions() != null ? user.getPermissions() : new ArrayList<>());

        // Numeric fields
        data.put("loginAttempts", user.getLoginAttempts());
        data.put("failedLoginAttempts", user.getFailedLoginAttempts());

        // Security & audit
        data.put("createdBy", user.getCreatedBy());
        data.put("otpSecret", user.getOtpSecret());
        data.put("lastPasswordChangeDate", user.getLastPasswordChangeDate());
        data.put("deviceFingerprint", user.getDeviceFingerprint());
        data.put("lastLoginIp", user.getLastLoginIp());
        data.put("lastLoginIpAddress", user.getLastLoginIpAddress());

        // Profile
        data.put("profilePictureUrl", user.getProfilePictureUrl());
        data.put("bio", user.getBio());
        data.put("userProfileId", user.getUserProfileId());

        // Verification tokens
        data.put("verificationToken", user.getVerificationToken());
        data.put("verificationTokenHash", user.getVerificationTokenHash());
        data.put("passwordResetToken", user.getPasswordResetToken());

        // Timestamps - Always save as Firestore Timestamp
        if (user.getCreatedAt() != null) {
            data.put("createdAt", Timestamp.ofTimeSecondsAndNanos(
                    user.getCreatedAt().getEpochSecond(),
                    user.getCreatedAt().getNano()
            ));
        }

        if (user.getUpdatedAt() != null) {
            data.put("updatedAt", Timestamp.ofTimeSecondsAndNanos(
                    user.getUpdatedAt().getEpochSecond(),
                    user.getUpdatedAt().getNano()
            ));
        }

        if (user.getLastLogin() != null) {
            data.put("lastLogin", Timestamp.ofTimeSecondsAndNanos(
                    user.getLastLogin().getEpochSecond(),
                    user.getLastLogin().getNano()
            ));
        }

        if (user.getLastLoginTimestamp() != null) {
            data.put("lastLoginTimestamp", user.getLastLoginTimestamp());
        }

        if (user.getVerificationTokenExpiresAt() != null) {
            data.put("verificationTokenExpiresAt", Timestamp.ofTimeSecondsAndNanos(
                    user.getVerificationTokenExpiresAt().getEpochSecond(),
                    user.getVerificationTokenExpiresAt().getNano()
            ));
        }

        // Additional fields
        data.put("userAgent", user.getUserAgent());
        data.put("accountNonLocked", user.isAccountNonLocked());
        data.put("credentialsNonExpired", user.isCredentialsNonExpired());
        data.put("accountNonExpired", user.isAccountNonExpired());

        return data;
    }
}