package com.techStack.authSys.service.firebase;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class FirebaseClaimsService {

    private static final Logger logger = LoggerFactory.getLogger(FirebaseClaimsService.class);
    private final PermissionProvider permissionProvider;

    public FirebaseClaimsService(PermissionProvider permissionProvider) {
        this.permissionProvider = permissionProvider;
    }

    public void setClaims(String uid, Roles role) throws FirebaseAuthException {
        Map<String, Object> claims = new HashMap<>();

        // Set role
        claims.put("roles", Collections.singleton(role.name()));

        // Set permissions
        List<String> permissions = permissionProvider.getPermissionsForRole(role)
                .stream()
                .map(Enum::name)
                .collect(Collectors.toList());
        claims.put("permissions", permissions);

        FirebaseAuth.getInstance().setCustomUserClaims(uid, claims);
        logger.info("Set Firebase custom claims for user {}: {}", uid, claims);
    }
    public Mono<Void> setClaimsReactive(String userId, Roles role) {
        return Mono.fromRunnable(() -> {
            try {
                setClaims(userId, role); // your existing sync method
            } catch (FirebaseAuthException e) {
                throw new RuntimeException("Failed to set Firebase claims", e);
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

}

