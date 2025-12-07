package com.techStack.authSys.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.time.Instant;

@Getter
public class AccountLockedException extends CustomException {
    private final int lockoutMinutes;
    private final Instant unlockTime;

    public AccountLockedException(int lockoutMinutes, Instant unlockTime) {
        super(HttpStatus.LOCKED,
                String.format("Account locked due to multiple failed attempts. Try again in %d minutes.", lockoutMinutes));
        this.lockoutMinutes = lockoutMinutes;
        this.unlockTime = unlockTime;
    }

    public AccountLockedException(int lockoutMinutes, Instant unlockTime, Throwable cause) {
        super(HttpStatus.LOCKED,
                String.format("Account locked due to multiple failed attempts. Try again in %d minutes.", lockoutMinutes),
                cause);
        this.lockoutMinutes = lockoutMinutes;
        this.unlockTime = unlockTime;
    }
}