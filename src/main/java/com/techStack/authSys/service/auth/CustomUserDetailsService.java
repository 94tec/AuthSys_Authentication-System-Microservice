package com.techStack.authSys.service.auth;

import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserAssembler;
import com.techStack.authSys.models.user.UserDocument;
import com.techStack.authSys.repository.authorization.FirestoreUserPermissionsRepository;
import com.techStack.authSys.repository.user.UserDocumentRepository;
import com.techStack.authSys.security.context.CustomUserDetails;
import com.techStack.authSys.service.authorization.PermissionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Reactive UserDetailsService for Spring Security WebFlux.
 *
 * loadUserByUsername() receives the Firebase UID
 * (passed by FirebaseAuthenticationManager).
 *
 * Fix summary:
 *   - PermissionResolutionService did not exist; replaced with PermissionService
 *     which owns all permission resolution (resolveEffectivePermissions / hasPermission).
 *   - FirestoreUserPermissionsRepository.findByFirebaseUid() is reactive (returns
 *     Mono<FirestoreUserPermissions>), not blocking (returns Optional). The old
 *     buildAuthorities() called it synchronously with .ifPresent() — this would
 *     block or silently drop the result on a non-blocking thread. Authority
 *     building is now fully reactive and chained into the main pipeline.
 *   - user.setAuthorities() does not exist on User — User builds authorities
 *     dynamically from roleNames + additionalPermissions in getAuthorities().
 *     The assembled User already carries the correct role names from the document,
 *     so role-based ROLE_* authorities are covered automatically.
 *     Permission authorities are resolved via PermissionService and passed
 *     directly into CustomUserDetails, not pushed back onto User.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements ReactiveUserDetailsService {

    private final UserDocumentRepository       userDocumentRepository;
    private final UserAssembler                userAssembler;
    private final FirestoreUserPermissionsRepository permissionsRepo;
    private final PermissionService            permissionService;

    /**
     * @param username Firebase UID
     */
    @Override
    public Mono<UserDetails> findByUsername(String username) {
        return Mono.fromCallable(() -> userDocumentRepository.findById(username))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(optDoc -> {
                    if (optDoc.isEmpty()) {
                        return Mono.error(new UsernameNotFoundException(
                                "User not found: " + username));
                    }

                    UserDocument doc  = optDoc.get();
                    User         user = userAssembler.assembleFromDocumentOnly(doc);

                    // Resolve the full effective permission set reactively,
                    // then combine with role-based ROLE_* authorities.
                    return buildAuthorities(username, user)
                            .map(authorities -> {
                                List<String> permissions = authorities.stream()
                                        .map(SimpleGrantedAuthority::getAuthority)
                                        .filter(a -> !a.startsWith("ROLE_"))
                                        .toList();

                                return (UserDetails) new CustomUserDetails(
                                        user,
                                        doc.getRoleNames(),
                                        permissions
                                );
                            });
                });
    }

    /**
     * Builds the full GrantedAuthority set for a user reactively.
     *
     * Sources:
     *   1. ROLE_{roleName}  — from roleNames on the assembled User
     *   2. Permission strings — from PermissionService.resolveEffectivePermissions(),
     *      which unions role-based permissions (Firestore) + additionalPermissions
     *      already on the User object.
     *
     * PermissionService.resolveEffectivePermissions() is synchronous/cached, so
     * this stays on the boundedElastic scheduler inherited from the caller.
     *
     * @param firebaseUid the user's Firebase UID (used for logging)
     * @param user        the fully assembled User domain object
     * @return Mono emitting the complete authority set
     */
    private Mono<Set<SimpleGrantedAuthority>> buildAuthorities(
            String firebaseUid,
            User   user
    ) {
        return Mono.fromCallable(() -> {
            Set<SimpleGrantedAuthority> authorities = new HashSet<>();

            // 1. Role authorities
            List<String> roleNames = user.getRoleNames();
            if (roleNames != null) {
                roleNames.forEach(role ->
                        authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
            }

            // 2. Effective permission authorities (role perms + user-specific grants)
            //    resolveEffectivePermissions is @Cacheable — fast after first call.
            Set<String> effectivePerms = permissionService.resolveEffectivePermissions(user);
            effectivePerms.forEach(perm ->
                    authorities.add(new SimpleGrantedAuthority(perm)));

            log.debug("Built {} authorities for user {} (roles={}, perms={})",
                    authorities.size(), firebaseUid,
                    roleNames != null ? roleNames.size() : 0,
                    effectivePerms.size());

            return authorities;
        }).subscribeOn(Schedulers.boundedElastic());
    }
}