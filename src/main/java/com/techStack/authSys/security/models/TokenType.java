package com.techStack.authSys.security.models;
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
    PERMISSIONS_GRANTED,
}
