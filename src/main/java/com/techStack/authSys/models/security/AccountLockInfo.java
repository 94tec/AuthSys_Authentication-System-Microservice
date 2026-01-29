package com.techStack.authSys.models.security;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.Instant;

@Data
@AllArgsConstructor
public class AccountLockInfo {
    private String reason;
    private Instant lockedAt;
}
