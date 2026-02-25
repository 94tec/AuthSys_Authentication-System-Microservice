package com.techStack.authSys.controller.admin;

import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.UserDocument;
import com.techStack.authSys.repository.authorization.FirestoreRolePermissionsRepository;
import com.techStack.authSys.repository.authorization.FirestoreUserPermissionsRepository;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import com.techStack.authSys.repository.user.UserDocumentRepository;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Admin Role Permission Controller
 *
 * Manages role and permission assignments.
 *
 * Migration note (Step 4):
 *   Permissions no longer read from the frozen Permissions enum.
 *   All permission data comes from Firestore:
 *     - permissions/           → available permission strings
 *     - role_permissions/      → role → permission mappings
 *     - user_permissions/      → per-user grants and denials
 *
 *   Grant/revoke now writes to FirestoreUserPermissions.grants/denials
 *   instead of the in-memory PermissionService cache.
 *
 * Blocking note:
 *   All Mono.fromCallable() blocks run on Schedulers.boundedElastic(),
 *   so blocking repository calls (*Blocking variants) are safe inside them.
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/access")
@RequiredArgsConstructor
@Tag(
        name = "Role & Permission Management",
        description = """
        Role-Based Access Control (RBAC) administration.

        **Role Hierarchy:**
        1. **SUPER_ADMIN** (Level 100) — Full system access
        2. **ADMIN** (Level 90)        — User management, role assignments
        3. **DESIGNER** (Level 70)     — Portfolio publish, content creation
        4. **MANAGER** (Level 50)      — Team management, analytics
        5. **USER** (Level 10)         — Standard access
        6. **GUEST** (Level 1)         — Read-only access

        **Permission System:**
        - Permissions are namespaced strings: "portfolio:publish", "order:view_all"
        - Role permissions defined in permissions.yaml → seeded to Firestore on startup
        - Per-user grants/denials stored in Firestore user_permissions/{uid}
        - Effective permissions = role_permissions(roles) + grants - denials
        - Denials always win over grants

        **Access Control:**
        - SUPER_ADMIN: Full access to all endpoints
        - ADMIN: Read-only access to roles/permissions
        - Role assignment requires SUPER_ADMIN
        """
)
public class AdminRolePermissionController {

    /* =========================
       Dependencies
       ========================= */

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final PermissionProvider permissionProvider;
    private final FirestoreRolePermissionsRepository rolePermissionsRepo;
    private final FirestoreUserPermissionsRepository userPermissionsRepo;
    private final UserDocumentRepository userDocumentRepo;
    private final Clock clock;

    /* =========================
       GET ROLES & PERMISSIONS
       ========================= */

    @Operation(
            summary = "Get All Roles and Their Permissions",
            description = """
            Retrieve complete role-permission mapping from Firestore.

            Returns all system roles and their resolved permission sets.
            Data sourced from Firestore role_permissions/ collection,
            seeded from permissions.yaml on startup.

            **Access Required:** ADMIN or SUPER_ADMIN
            """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Role permissions retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                      "success": true,
                      "data": {
                        "SUPER_ADMIN": ["user:create", "user:delete", "portfolio:publish", "system:backup"],
                        "ADMIN":       ["user:create", "user:read", "user:assign_roles"],
                        "DESIGNER":    ["portfolio:view", "portfolio:create", "portfolio:publish"],
                        "MANAGER":     ["user:read", "portfolio:view", "portfolio:analytics"],
                        "USER":        ["portfolio:view"],
                        "GUEST":       []
                      },
                      "timestamp": "2025-01-15T14:30:00Z"
                    }
                    """)
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403", description = "Insufficient permissions"
            )
    })
    @GetMapping("/roles")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> getAllRolePermissions() {
        Instant requestTime = clock.instant();
        log.info("Fetching all role permissions at {}", requestTime);

        return Mono.fromCallable(() -> {
            Map<String, List<String>> rolePermissions = Arrays.stream(Roles.values())
                    .collect(Collectors.toMap(
                            Roles::name,
                            // FIX: use blocking variant — we are inside boundedElastic
                            role -> rolePermissionsRepo.findByRoleNameBlocking(role.name())
                    ));

            return ResponseEntity.ok(Map.of(
                    "success",   true,
                    "data",      rolePermissions,
                    "source",    "firestore",
                    "timestamp", requestTime.toString()
            ));
        }).subscribeOn(Schedulers.boundedElastic());
    }

    @Operation(
            summary = "Get All Available Permissions",
            description = """
            Retrieve all permission strings from Firestore permissions/ collection.

            Permissions are namespaced strings seeded from permissions.yaml:
            - user:create, user:read, user:update, user:delete, user:assign_roles
            - portfolio:view, portfolio:create, portfolio:edit, portfolio:publish, portfolio:analytics
            - order:create, order:view_all, order:view_own, order:process_refund
            - payment:process, payment:refund
            - system:backup, system:config

            **Access Required:** ADMIN or SUPER_ADMIN
            """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Permissions retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                      "success": true,
                      "data": [
                        "user:create", "user:read", "user:assign_roles",
                        "portfolio:view", "portfolio:create", "portfolio:publish",
                        "order:create", "order:view_all",
                        "payment:process", "payment:refund"
                      ],
                      "total": 10,
                      "timestamp": "2025-01-15T14:30:00Z"
                    }
                    """)
                    )
            )
    })
    @GetMapping("/permissions")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> getAllPermissions() {
        Instant requestTime = clock.instant();
        log.info("Fetching all permissions at {}", requestTime);

        return Mono.fromCallable(() -> {
            List<String> permissions = loadAllPermissionsFromFirestore();

            return ResponseEntity.ok(Map.of(
                    "success",   true,
                    "data",      permissions,
                    "total",     permissions.size(),
                    "timestamp", requestTime.toString()
            ));
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /* =========================
       ROLE ASSIGNMENT
       ========================= */

    @Operation(
            summary = "Assign Role to User",
            description = """
            Assign a role to a user.

            Updates both the Firestore user_permissions/{uid} document
            (roles list) and the UserDocument roles field.

            **Access Required:** SUPER_ADMIN only

            Available roles: ADMIN, DESIGNER, MANAGER, USER, GUEST
            (SUPER_ADMIN cannot be assigned via API)
            """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Role assigned successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                      "success": true,
                      "message": "Role assigned successfully",
                      "data": {
                        "userId": "firebase-uid-123",
                        "role": "DESIGNER",
                        "assignedAt": "2025-01-15T14:30:00Z"
                      }
                    }
                    """)
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400", description = "Invalid role name or user not found"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403", description = "Requires SUPER_ADMIN"
            )
    })
    @PostMapping("/roles/assign")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> assignRoleToUser(
            @Parameter(description = "Firebase UID of the user", required = true, example = "firebase-uid-123")
            @RequestParam String userId,

            @Parameter(description = "Role name (ADMIN, DESIGNER, MANAGER, USER, GUEST)", required = true, example = "DESIGNER")
            @RequestParam String roleName) {

        Instant assignmentTime = clock.instant();
        log.info("Assigning role '{}' to user {} at {}", roleName, userId, assignmentTime);

        return Mono.fromCallable(() -> Roles.fromName(roleName))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(optRole -> {
                    if (optRole.isEmpty()) {
                        return Mono.just(ResponseEntity.badRequest()
                                .body(Map.<String, Object>of(
                                        "success", false,
                                        "message", "Invalid role name: " + roleName
                                )));
                    }

                    Roles role = optRole.get();

                    // Block SUPER_ADMIN assignment via API
                    if (role == Roles.SUPER_ADMIN) {
                        return Mono.just(ResponseEntity.badRequest()
                                .body(Map.<String, Object>of(
                                        "success", false,
                                        "message", "SUPER_ADMIN cannot be assigned via API."
                                )));
                    }

                    return Mono.fromCallable(() -> {
                        // 1 — Verify user exists
                        Optional<UserDocument> userDoc = userDocumentRepo.findById(userId);
                        if (userDoc.isEmpty()) {
                            throw new IllegalArgumentException("User not found: " + userId);
                        }

                        // 2 — Add role to UserDocument
                        UserDocument doc = userDoc.get();
                        doc.addRole(role.name());
                        userDocumentRepo.save(doc);

                        // 3 — Add role to FirestoreUserPermissions
                        // FIX: use *Blocking variants — inside Mono.fromCallable on boundedElastic
                        var permsOpt = userPermissionsRepo.findByFirebaseUidBlocking(userId);
                        if (permsOpt.isPresent()) {
                            var perms = permsOpt.get();
                            perms.addRole(role.name());
                            userPermissionsRepo.saveBlocking(perms);
                        } else {
                            // Create default document first, then add role
                            var perms = userPermissionsRepo.createDefaultBlocking(userId);
                            perms.addRole(role.name());
                            userPermissionsRepo.saveBlocking(perms);
                        }

                        return ResponseEntity.ok(Map.<String, Object>of(
                                "success",    true,
                                "message",    "Role assigned successfully",
                                "data", Map.of(
                                        "userId",     userId,
                                        "role",       roleName,
                                        "assignedAt", assignmentTime.toString()
                                )
                        ));
                    }).subscribeOn(Schedulers.boundedElastic());
                })
                .onErrorResume(e -> {
                    log.error("Failed to assign role at {}: {}", assignmentTime, e.getMessage());
                    return Mono.just(ResponseEntity.badRequest()
                            .body(Map.<String, Object>of(
                                    "success",   false,
                                    "message",   e.getMessage(),
                                    "timestamp", clock.instant().toString()
                            )));
                });
    }

    /* =========================
       PERMISSION GRANT / REVOKE
       ========================= */

    @Operation(
            summary = "Grant Permission to User",
            description = """
            Grant an additional permission to a user beyond their role defaults.

            Writes to FirestoreUserPermissions.grants list for the user.
            Takes effect immediately on next request — no re-login required.

            Effective permissions = role_permissions(roles) + grants - denials
            Denials always win over grants.

            Permission format: "namespace:action" e.g. "portfolio:publish"

            **Access Required:** SUPER_ADMIN only
            """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Permission granted successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                      "success": true,
                      "message": "Permission granted successfully",
                      "data": {
                        "userId": "firebase-uid-123",
                        "permission": "portfolio:publish",
                        "grantedAt": "2025-01-15T14:30:00Z"
                      }
                    }
                    """)
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400", description = "Invalid permission format or user not found"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403", description = "Requires SUPER_ADMIN"
            )
    })
    @PostMapping("/permissions/grant")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> grantPermissionToUser(
            @Parameter(description = "Firebase UID of the user", required = true, example = "firebase-uid-123")
            @RequestParam String userId,

            @Parameter(description = "Permission string e.g. portfolio:publish", required = true, example = "portfolio:publish")
            @RequestParam String permission) {

        Instant grantTime = clock.instant();
        log.info("Granting permission '{}' to user {} at {}", permission, userId, grantTime);

        if (!isValidPermissionFormat(permission)) {
            return Mono.just(ResponseEntity.badRequest()
                    .body(Map.<String, Object>of(
                            "success", false,
                            "message", "Invalid permission format. Expected 'namespace:action' e.g. 'portfolio:publish'."
                    )));
        }

        return Mono.fromCallable(() -> {
                    // Verify user exists
                    if (userDocumentRepo.findById(userId).isEmpty()) {
                        throw new IllegalArgumentException("User not found: " + userId);
                    }

                    // FIX: use *Blocking variants inside boundedElastic Mono.fromCallable
                    var permsOpt = userPermissionsRepo.findByFirebaseUidBlocking(userId);
                    if (permsOpt.isPresent()) {
                        var perms = permsOpt.get();
                        perms.grant(permission);
                        userPermissionsRepo.saveBlocking(perms);
                    } else {
                        var perms = userPermissionsRepo.createDefaultBlocking(userId);
                        perms.grant(permission);
                        userPermissionsRepo.saveBlocking(perms);
                    }

                    // Also update PermissionProvider in-memory cache for immediate effect
                    permissionProvider.addPermission(userId, permission);

                    return ResponseEntity.ok(Map.<String, Object>of(
                            "success", true,
                            "message", "Permission granted successfully",
                            "data", Map.of(
                                    "userId",     userId,
                                    "permission", permission,
                                    "grantedAt",  grantTime.toString()
                            )
                    ));
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> {
                    log.error("Failed to grant permission at {}: {}", grantTime, e.getMessage());
                    return Mono.just(ResponseEntity.badRequest()
                            .body(Map.<String, Object>of(
                                    "success",   false,
                                    "message",   e.getMessage(),
                                    "timestamp", clock.instant().toString()
                            )));
                });
    }

    @Operation(
            summary = "Revoke Permission from User",
            description = """
            Remove an additional permission from a user.

            Two behaviours depending on where the permission comes from:

            1. If it was an explicit grant → removed from grants list.
            2. If it comes from the user's role → added to denials list,
               which strips it from effective permissions.

            Denials always win — even if a future role grants this permission,
            the denial will suppress it until explicitly removed.

            **Access Required:** SUPER_ADMIN only
            """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Permission revoked successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                      "success": true,
                      "message": "Permission revoked successfully",
                      "data": {
                        "userId": "firebase-uid-123",
                        "permission": "portfolio:publish",
                        "revokedAt": "2025-01-15T14:30:00Z",
                        "method": "grant_removed"
                      }
                    }
                    """)
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400", description = "Invalid permission or user not found"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403", description = "Requires SUPER_ADMIN"
            )
    })
    @PostMapping("/permissions/revoke")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> revokePermissionFromUser(
            @Parameter(description = "Firebase UID of the user", required = true, example = "firebase-uid-123")
            @RequestParam String userId,

            @Parameter(description = "Permission string e.g. portfolio:publish", required = true, example = "portfolio:publish")
            @RequestParam String permission) {

        Instant revokeTime = clock.instant();
        log.info("Revoking permission '{}' from user {} at {}", permission, userId, revokeTime);

        if (!isValidPermissionFormat(permission)) {
            return Mono.just(ResponseEntity.badRequest()
                    .body(Map.<String, Object>of(
                            "success", false,
                            "message", "Invalid permission format. Expected 'namespace:action'."
                    )));
        }

        return Mono.fromCallable(() -> {
                    if (userDocumentRepo.findById(userId).isEmpty()) {
                        throw new IllegalArgumentException("User not found: " + userId);
                    }

                    String method = "not_found";

                    // FIX: use *Blocking variant inside boundedElastic Mono.fromCallable
                    var permsOpt = userPermissionsRepo.findByFirebaseUidBlocking(userId);

                    if (permsOpt.isPresent()) {
                        var perms = permsOpt.get();

                        if (perms.getGrants() != null
                                && perms.getGrants().contains(permission)) {
                            // Was an explicit grant — remove it
                            perms.getGrants().remove(permission);
                            method = "grant_removed";
                        } else {
                            // Comes from role — add to denials to suppress it
                            perms.deny(permission);
                            method = "denial_added";
                        }

                        userPermissionsRepo.saveBlocking(perms);
                    }

                    // Sync in-memory cache
                    permissionProvider.removePermission(userId, permission);

                    return ResponseEntity.ok(Map.<String, Object>of(
                            "success", true,
                            "message", "Permission revoked successfully",
                            "data", Map.of(
                                    "userId",     userId,
                                    "permission", permission,
                                    "revokedAt",  revokeTime.toString(),
                                    "method",     method
                            )
                    ));
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> {
                    log.error("Failed to revoke permission at {}: {}", revokeTime, e.getMessage());
                    return Mono.just(ResponseEntity.badRequest()
                            .body(Map.<String, Object>of(
                                    "success",   false,
                                    "message",   e.getMessage(),
                                    "timestamp", clock.instant().toString()
                            )));
                });
    }

    /* =========================
       PERMISSION RELOAD
       ========================= */

    @Operation(
            summary = "Reload Permissions from Configuration",
            description = """
            Re-run the PermissionSeeder — reads permissions.yaml and
            re-writes all permissions and role_permissions to Firestore.

            Uses SetOptions.merge() so manual Firestore edits are preserved.
            Safe to run in production.

            When to use:
            - After updating permissions.yaml to add a new permission namespace
            - After changing role-permission mappings in YAML
            - To verify Firestore is in sync with YAML configuration

            Does NOT affect per-user grants or denials in user_permissions/.

            **Access Required:** SUPER_ADMIN only
            """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Permissions reloaded from YAML to Firestore",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                      "success": true,
                      "message": "Permissions reloaded from YAML to Firestore",
                      "reloadedAt": "2025-01-15T14:30:00Z"
                    }
                    """)
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "500", description = "Reload failed — Firestore or YAML error"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403", description = "Requires SUPER_ADMIN"
            )
    })
    @PostMapping("/reload")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> reloadPermissions() {
        Instant reloadTime = clock.instant();
        log.warn("Reloading permissions from YAML to Firestore at {}", reloadTime);

        return Mono.fromRunnable(permissionProvider::reloadPermissions)
                .subscribeOn(Schedulers.boundedElastic())
                .thenReturn(ResponseEntity.ok(Map.<String, Object>of(
                        "success",    true,
                        "message",    "Permissions reloaded from YAML to Firestore",
                        "reloadedAt", reloadTime.toString()
                )))
                .onErrorResume(e -> {
                    log.error("Reload failed at {}: {}", reloadTime, e.getMessage());
                    return Mono.just(ResponseEntity.status(500)
                            .body(Map.<String, Object>of(
                                    "success",   false,
                                    "message",   "Reload failed: " + e.getMessage(),
                                    "timestamp", clock.instant().toString()
                            )));
                });
    }

    /* =========================
       USER PERMISSION INSPECT
       ========================= */

    @Operation(
            summary = "Inspect Effective Permissions for a User",
            description = """
            View the full permission breakdown for a specific user:
            - Their current roles
            - Role-based permissions (from Firestore role_permissions/)
            - Explicit grants (extras beyond role)
            - Explicit denials (stripped from role)
            - Final effective permission set

            Useful for debugging permission issues and audit reviews.

            **Access Required:** ADMIN or SUPER_ADMIN
            """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @GetMapping("/users/{userId}/permissions")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> inspectUserPermissions(
            @Parameter(description = "Firebase UID", required = true)
            @PathVariable String userId) {

        Instant requestTime = clock.instant();
        log.info("Inspecting permissions for user {} at {}", userId, requestTime);

        return Mono.fromCallable(() -> {
                    // 1 — Check user exists
                    Optional<UserDocument> userDocOpt = userDocumentRepo.findById(userId);
                    if (userDocOpt.isEmpty()) {
                        return ResponseEntity.badRequest()
                                .body(Map.<String, Object>of(
                                        "success", false,
                                        "message", "User not found: " + userId
                                ));
                    }

                    UserDocument doc = userDocOpt.get();

                    // 2 — Load permissions document
                    // FIX: use *Blocking variant inside boundedElastic Mono.fromCallable
                    var permsOpt = userPermissionsRepo.findByFirebaseUidBlocking(userId);
                    if (permsOpt.isEmpty()) {
                        return ResponseEntity.ok(Map.<String, Object>of(
                                "success", true,
                                "userId",  userId,
                                "email",   doc.getEmail(),
                                "roles",   doc.getRoleNames(),
                                "grants",  List.of(),
                                "denials", List.of(),
                                "rolePermissions", Map.of(),
                                "effectivePermissions", List.of()
                        ));
                    }

                    var perms = permsOpt.get();

                    // 3 — Resolve role permissions per role
                    // FIX: use blocking variant here too
                    Map<String, List<String>> rolePermsBreakdown = perms.getRoles().stream()
                            .collect(Collectors.toMap(
                                    role -> role,
                                    role -> rolePermissionsRepo.findByRoleNameBlocking(role)
                            ));

                    // 4 — Compute effective (flat)
                    Set<String> effective = new HashSet<>();
                    rolePermsBreakdown.values().forEach(effective::addAll);
                    if (perms.getGrants() != null) effective.addAll(perms.getGrants());
                    if (perms.getDenials() != null) effective.removeAll(perms.getDenials());

                    return ResponseEntity.ok(Map.<String, Object>of(
                            "success",              true,
                            "userId",               userId,
                            "email",                doc.getEmail(),
                            "roles",                perms.getRoles(),
                            "grants",               perms.getGrants() != null ? perms.getGrants() : List.of(),
                            "denials",              perms.getDenials() != null ? perms.getDenials() : List.of(),
                            "rolePermissions",      rolePermsBreakdown,
                            "effectivePermissions", new ArrayList<>(effective),
                            "timestamp",            requestTime.toString()
                    ));
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    /* =========================
       PRIVATE HELPERS
       ========================= */

    /**
     * Validates permission string format: "namespace:action"
     * e.g. "portfolio:publish", "user:read", "order:view_all"
     */
    private boolean isValidPermissionFormat(String permission) {
        if (permission == null || permission.isBlank()) return false;
        String[] parts = permission.split(":");
        return parts.length == 2
                && !parts[0].isBlank()
                && !parts[1].isBlank();
    }

    /**
     * Loads all permission full names from Firestore by collecting across all roles.
     *
     * FIX: removed the dead `FirestoreTemplate.class.cast(null)` placeholder, which
     * would throw ClassNotFoundException or return null and could silently break
     * the /permissions endpoint. The actual implementation below it was always correct.
     *
     * Returns sorted list for consistent UI display.
     */
    private List<String> loadAllPermissionsFromFirestore() {
        try {
            return Arrays.stream(Roles.values())
                    .flatMap(role -> rolePermissionsRepo
                            .findByRoleNameBlocking(role.name()).stream())
                    .distinct()
                    .sorted()
                    .collect(Collectors.toList());

        } catch (Exception e) {
            log.error("Failed to load permissions from Firestore", e);
            return List.of();
        }
    }
}