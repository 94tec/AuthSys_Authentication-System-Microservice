package com.techStack.authSys.constants;

import java.time.Duration;
import java.util.regex.Pattern;

public final class SecurityConstants {

    private SecurityConstants() {}

    // JWT Configuration
    public static final int ACCESS_TOKEN_TTL_SECONDS = 900; // 15 minutes
    public static final int REFRESH_TOKEN_TTL_SECONDS = 604800; // 7 days
    public static final String TOKEN_TYPE = "Bearer";
    public static final String JWT_ISSUER = "authsys";

    // Rate Limiting
    public static final int REGISTER_RATE_LIMIT = 5;
    public static final int LOGIN_RATE_LIMIT = 10;
    public static final int VERIFY_OTP_RATE_LIMIT = 3;
    public static final Duration RATE_LIMIT_WINDOW = Duration.ofMinutes(1);

    // Account Locking
    public static final int MAX_LOGIN_ATTEMPTS = 5;
    public static final Duration ACCOUNT_LOCK_DURATION = Duration.ofMinutes(30);

    // Password Policy
    public static final int MIN_PASSWORD_LENGTH = 12;
    public static final int PASSWORD_HISTORY_COUNT = 5;
    public static final int PASSWORD_EXPIRY_DAYS = 90;

    // OTP
    public static final int OTP_LENGTH = 6;
    public static final Duration OTP_TTL = Duration.ofMinutes(5);

    // Session
    public static final int MAX_CONCURRENT_SESSIONS = 3;
    public static final Duration SESSION_IDLE_TIMEOUT = Duration.ofHours(24);

    // Collection names
    public static final String COLLECTION_USERS = "users";
    public static final String COLLECTION_USER_PROFILES = "user_profiles";
    public static final String COLLECTION_USER_PASSWORD_HISTORY = "user_password_history";
    public static final String COLLECTION_USER_PERMISSIONS = "user_permissions";
    public static final String COLLECTION_AUTH_LOGS = "auth_logs";
    public static final String COLLECTION_REGISTRATION_METADATA = "registration_metadata";

    // Fixed document IDs for easy retrieval
    public static final String PROFILE_DOC_ID = "profile";
    public static final String ACTIVE_PERMISSIONS_DOC_ID = "active_permissions";

    public static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}$",
            Pattern.CASE_INSENSITIVE
    );

    public static final Pattern STRONG_PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$"
    );

    public static final Pattern KENYAN_ID_PATTERN = Pattern.compile("\\d{8}");

    public static final Pattern KENYAN_PHONE_PATTERN = Pattern.compile("\\+254[17]\\d{8}");

    /* =========================
       Field Constants
       ========================= */
    public static final String THROTTLE_COLLECTION = "registration_throttle";

    public static final String FIELD_EMAIL = "email";
    public static final String FIELD_PASSWORD = "password";
    public static final String FIELD_FIRST_NAME = "firstName";
    public static final String FIELD_LAST_NAME = "lastName";
    public static final String FIELD_IDENTITY_NO = "identityNo";
    public static final String FIELD_PHONE_NUMBER = "phoneNumber";
    public static final String FIELD_PAYLOAD = "payload";

    /* =========================
       Error Code Constants
       ========================= */

    public static final String ERROR_REQUEST_INVALID = "REQUEST_INVALID";
    public static final String ERROR_EMAIL_REQUIRED = "EMAIL_REQUIRED";
    public static final String ERROR_EMAIL_INVALID = "EMAIL_INVALID";
    public static final String ERROR_PASSWORD_REQUIRED = "PASSWORD_REQUIRED";
    public static final String ERROR_PASSWORD_WEAK = "PASSWORD_WEAK";
    public static final String ERROR_FIRSTNAME_REQUIRED = "FIRSTNAME_REQUIRED";
    public static final String ERROR_LASTNAME_REQUIRED = "LASTNAME_REQUIRED";
    public static final String ERROR_IDENTITY_NO_INVALID = "IDENTITY_NO_INVALID";
    public static final String ERROR_PHONE_NUMBER_INVALID = "PHONE_NUMBER_INVALID";
}
