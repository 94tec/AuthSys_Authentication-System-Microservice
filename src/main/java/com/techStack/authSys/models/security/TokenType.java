package com.techStack.authSys.models.security;
/**
 * Token type enum
 */
public enum TokenType {
    FIREBASE,
    CUSTOM_JWT,
    ACCESS,
    REFRESH,
    TEMPORARY,
    PASSWORD_RESET
}
