package com.techStack.authSys.exception;

public class FirebaseRestAuthException extends RuntimeException {
    private final String errorCode;

    public FirebaseRestAuthException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
