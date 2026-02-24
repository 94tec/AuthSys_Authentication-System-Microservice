package com.techStack.authSys.service.firebase;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.*;

/**
 * Firebase Claims Service
 *
 * Sets custom claims on Firebase Auth tokens for a user.
 * Claims are embedded in the Firebase ID token and read by clients.
 *
 * Claims set:
 *   - roles:       list of role name strings e.g. ["ADMIN"]
 *   - permissions: list of permission full names e.g. ["portfolio:view", "user:read"]
 *
 * Migration note:
 *   The original called permissionProvider.getPermissionsForRole(role)
 *   and then streamed .map(Enum::name) on the result, expecting Set<Permissions>.
 *   getPermissionsForRole() now returns Set<String> directly — the enum mapping
 *   chain is removed. The result is passed straight into the claims map.
 *
 * Note on Firebase custom claims size limit:
 *   Firebase enforces a hard 1KB limit on custom claims. If a role resolves to
 *   many permissions (e.g. SUPER_ADMIN with *:* wildcard), this limit may be hit.
 *   In that case, omit permissions from Firebase claims and resolve them from
 *   your own JWT at token generation time. Firebase claims should carry only
 *   the role name(s) for lightweight identity; full permissions live in your JWT.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class FirebaseClaimsService {

    private final FirebaseAuth firebaseAuth;
    private final PermissionProvider permissionProvider;

    // -------------------------------------------------------------------------
    // Synchronous claims setter
    // -------------------------------------------------------------------------

    /**
     * Sets custom claims on a Firebase Auth user record.
     *
     * Claims are embedded in the user's next Firebase ID token after this call.
     * The current token is not affected — the client must re-authenticate or
     * force a token refresh for the new claims to appear.
     *
     * @param uid  Firebase Auth UID
     * @param role the role to set claims for
     * @throws FirebaseAuthException if the Firebase Admin SDK call fails
     */
    public void setClaims(String uid, Roles role) throws FirebaseAuthException {
        // getPermissionsForRole() now returns Set<String> — no .map(Enum::name) needed
        Set<String> permissions = permissionProvider.getPermissionsForRole(role);

        Map<String, Object> claims = new HashMap<>();
        claims.put("roles",       Collections.singletonList(role.name()));
        claims.put("permissions", new ArrayList<>(permissions));

        firebaseAuth.setCustomUserClaims(uid, claims);

        log.info("Set Firebase custom claims for uid {} — role={}, permissions={}",
                uid, role.name(), permissions.size());
    }

    /**
     * Sets custom claims for multiple roles.
     *
     * Merges permissions across all roles — each role's permission set is
     * unioned into a single deduplicated list. Useful for users with multiple roles.
     *
     * @param uid   Firebase Auth UID
     * @param roles the set of roles to set claims for
     * @throws FirebaseAuthException if the Firebase Admin SDK call fails
     */
    public void setClaims(String uid, Set<Roles> roles) throws FirebaseAuthException {
        List<String> roleNames  = roles.stream().map(Roles::name).toList();
        Set<String>  allPerms   = new HashSet<>();

        roles.forEach(role ->
                allPerms.addAll(permissionProvider.getPermissionsForRole(role)));

        Map<String, Object> claims = new HashMap<>();
        claims.put("roles",       roleNames);
        claims.put("permissions", new ArrayList<>(allPerms));

        firebaseAuth.setCustomUserClaims(uid, claims);

        log.info("Set Firebase custom claims for uid {} — roles={}, permissions={}",
                uid, roleNames, allPerms.size());
    }

    // -------------------------------------------------------------------------
    // Reactive wrapper
    // -------------------------------------------------------------------------

    /**
     * Reactive variant of {@link #setClaims(String, Roles)}.
     *
     * Wraps the blocking Firebase Admin SDK call in a boundedElastic scheduler.
     * Used in the reactive registration pipeline (RoleAssignmentService).
     *
     * @param uid  Firebase Auth UID
     * @param role the role to set claims for
     * @return Mono completing when claims are set, or error if Firebase call fails
     */
    public Mono<Void> setClaimsReactive(String uid, Roles role) {
        return Mono.fromRunnable(() -> {
                    try {
                        setClaims(uid, role);
                    } catch (FirebaseAuthException e) {
                        throw new RuntimeException(
                                "Failed to set Firebase claims for uid " + uid
                                        + " role " + role.name() + ": " + e.getMessage(), e);
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    /**
     * Reactive variant of {@link #setClaims(String, Set)}.
     *
     * @param uid   Firebase Auth UID
     * @param roles the set of roles to set claims for
     * @return Mono completing when claims are set
     */
    public Mono<Void> setClaimsReactive(String uid, Set<Roles> roles) {
        return Mono.fromRunnable(() -> {
                    try {
                        setClaims(uid, roles);
                    } catch (FirebaseAuthException e) {
                        throw new RuntimeException(
                                "Failed to set Firebase claims for uid " + uid
                                        + " roles " + roles + ": " + e.getMessage(), e);
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    // -------------------------------------------------------------------------
    // Claims clearing
    // -------------------------------------------------------------------------

    /**
     * Clears all custom claims for a user.
     * Called on user deactivation or role removal.
     *
     * @param uid Firebase Auth UID
     * @throws FirebaseAuthException if the Firebase Admin SDK call fails
     */
    public void clearClaims(String uid) throws FirebaseAuthException {
        firebaseAuth.setCustomUserClaims(uid, null);
        log.info("Cleared Firebase custom claims for uid: {}", uid);
    }

    /**
     * Reactive variant of {@link #clearClaims(String)}.
     */
    public Mono<Void> clearClaimsReactive(String uid) {
        return Mono.fromRunnable(() -> {
                    try {
                        clearClaims(uid);
                    } catch (FirebaseAuthException e) {
                        throw new RuntimeException(
                                "Failed to clear Firebase claims for uid " + uid
                                        + ": " + e.getMessage(), e);
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }
}