package com.techStack.authSys.service;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
public class FirebaseRoleService {

    public void assignRoleToUser(String uid, String role) throws FirebaseAuthException {
        UserRecord userRecord = FirebaseAuth.getInstance().getUser(uid);

        Map<String, Object> claims = new HashMap<>();
        claims.put("role", role); // Assign role as a custom claim

        FirebaseAuth.getInstance().setCustomUserClaims(uid, claims);
        log.info("Assigned role '{}' to user: {}", role, userRecord.getEmail());
    }

    public String getUserRole(String uid) throws FirebaseAuthException {
        UserRecord userRecord = FirebaseAuth.getInstance().getUser(uid);
        return (String) userRecord.getCustomClaims().get("role");
    }
}

