package com.techStack.authSys.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class FirebaseTokenDTO {
    private String uid;
    private Map<String, Object> claims;
    private String email;
    private boolean emailVerified;
}
