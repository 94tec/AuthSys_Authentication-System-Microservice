package com.techStack.authSys.models.user;

import com.google.cloud.firestore.annotation.DocumentId;
import com.google.cloud.spring.data.firestore.Document;
import lombok.*;
import org.springframework.lang.NonNull;

import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Document(collectionName = "user_password_history")
public class UserPasswordHistory {

    @DocumentId
    private String id;

    //@NonNull
    private String password;

    @NonNull
    private String userId;

    @NonNull
    @Builder.Default
    private Instant createdAt = Instant.now();
    private Instant changedAt;
    private String changedByIp;
    private String changedByUserAgent;

    public static UserPasswordHistory create(String encryptedPassword, String userId, String ip, String userAgent) {
        return UserPasswordHistory.builder()
                .password(encryptedPassword)
                .userId(userId)
                .changedByIp(ip)
                .changedByUserAgent(userAgent)
                // createdAt and timestamp are automatically set via Builder.Default
                .build();
    }
    
}