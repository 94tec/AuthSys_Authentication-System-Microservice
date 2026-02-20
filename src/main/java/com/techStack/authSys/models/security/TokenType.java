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
    TEMPORARY_LOGIN,
    PASSWORD_RESET,
    PERMISSIONS_GRANTED
}
