package com.techStack.authSys.dto;

import lombok.*;

import java.util.Date;

@Data
@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class AuthTokenDTO {
    private String id;
    private String token;
    private String userId;
    private Date createdAt;
    private Date expirationDate;
    private boolean revoked;
}
