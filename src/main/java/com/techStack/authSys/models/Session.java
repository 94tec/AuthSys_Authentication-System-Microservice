package com.techStack.authSys.models;

import com.google.cloud.Timestamp;
import com.google.cloud.spring.data.firestore.Document;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.time.Instant;

@Getter
@Builder
@RequiredArgsConstructor
@AllArgsConstructor
@Document(collectionName = "sessions")
public class Session {
    private String id;
    private String userId;
    private String ipAddress;
    private String deviceFingerprint;
    private String accessToken;
    private String refreshToken;
    private Instant createdAt;
    private Instant accessTokenExpiry;
    private Instant refreshTokenExpiry;
    private SessionStatus status;
    private Instant lastActivity;
    private Timestamp firestoreExpiresAt;

}
