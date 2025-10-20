package com.techStack.authSys.controller;

import com.techStack.authSys.dto.UserPermissionsDTO;
import com.techStack.authSys.exception.InvalidTokenException;
import com.techStack.authSys.models.User;
import com.techStack.authSys.repository.PermissionProvider;
import com.techStack.authSys.repository.RateLimiterService;
import com.techStack.authSys.security.CustomUserDetails;
import com.techStack.authSys.service.AdminManagementService;
import com.techStack.authSys.service.FirebaseServiceAuth;
import com.techStack.authSys.service.JwtService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin")
public class AdminManagementController {

    private final AdminManagementService adminManagementService;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final PermissionProvider permissionProvider;
    private final RateLimiterService.SessionService sessionService;
    private final JwtService jwtService;

    public AdminManagementController(AdminManagementService adminManagementService,
                                     FirebaseServiceAuth firebaseServiceAuth,
                                     PermissionProvider permissionProvider,
                                     RateLimiterService.SessionService sessionService,
                                     JwtService jwtService) {
        this.adminManagementService = adminManagementService;
        this.firebaseServiceAuth = firebaseServiceAuth;
        this.permissionProvider = permissionProvider;
        this.sessionService = sessionService;
        this.jwtService = jwtService;
    }

    @GetMapping("/users/{userId}/permissions")
    public Mono<UserPermissionsDTO> getUserPermissions(@PathVariable String userId) {
        return firebaseServiceAuth.getUserById(userId)
                .map(user -> {
                    List<String> permissions = permissionProvider.resolveEffectivePermissions(user).stream().toList();
                    List<String> roles = user.getRoleNames(); // Assuming it's already a list of strings
                    return new UserPermissionsDTO(userId, roles, permissions);
                });
    }
    @GetMapping("/")
    public Flux<User> getUsers(
            @RequestParam Optional<String> role,
            @RequestParam Optional<String> status,
            @RequestParam Optional<String> email,
            @RequestParam Optional<Instant> createdAfter,
            @RequestParam Optional<Instant> createdBefore
    ) {
        return adminManagementService.findUsersWithFilters(role, status, email, createdAfter, createdBefore);
    }

    @PutMapping("/users/{userId}/approve")
    public Mono<Void> approveUser(@PathVariable String userId, @PathVariable String performedById) {
        return adminManagementService.approvePendingUser(userId, performedById);
    }

    @PutMapping("/users/{userId}/reject")
    public Mono<Void> rejectUser(@PathVariable String userId, @PathVariable String performedById) {
        return adminManagementService.rejectPendingUser(userId, performedById);
    }
    @PutMapping("/users/{userId}/suspend")
    public Mono<Void> suspendUser(@PathVariable String userId, @PathVariable String performedById) {
        return adminManagementService.suspendUser(userId, performedById);
    }

    @PutMapping("/admin/users/{userId}/reactivate")
    public Mono<Void> reactivateUser(@PathVariable String userId, @PathVariable String performedById) {
        return adminManagementService.reactivateUser(userId, performedById);
    }
    @PostMapping("/admin/users/{userId}/force-reset-password")
    public Mono<Void> forcePasswordReset(@PathVariable String userId, @PathVariable String ipAddress) {
        return adminManagementService.initiateForcedPasswordReset(userId, ipAddress);
    }

    @DeleteMapping("/users/{userId}/sessions")
    public Mono<Void> forceLogout(@PathVariable String userId) {
        return sessionService.invalidateUserSessions(userId);
    }

    @GetMapping("/hello")
    //@PreAuthorize("hasAnyRole('SUPER_ADMIN')")
    public Mono<String> adminHello(ServerWebExchange exchange) {
        String token = extractToken(exchange);

        return jwtService.validateToken(token, "access")
                .map(claims -> "Hello Admin!") // ✅ If valid, return success message
                .onErrorResume(e -> Mono.error(new InvalidTokenException("Invalid token", e))); // ✅ On error, throw custom exception
    }

    // Extract the token from Authorization header
    private String extractToken(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7); // Remove "Bearer " prefix
        }
        return null; // Return null if no token is found
    }

    @GetMapping("/user/hello")
    public String userHello() {
        return "Hello User!";
    }

    // Admin endpoint (example of granular access control)
    @GetMapping("/dashboard")
    public Mono<String> adminDashboard(ServerWebExchange exchange) {
        String token = extractToken(exchange);

        return jwtService.validateToken(token, "access")
                .map(claims -> "Welcome to the admin dashboard") // ✅ If valid, return success message
                .onErrorResume(e -> Mono.error(new InvalidTokenException("Invalid token", e))); // ✅ On error, throw custom exception
    }
    // Temporary endpoint for testing
    @GetMapping("/debug/user-roles")
    public Mono<Map<String, Object>> getUserRoles(@AuthenticationPrincipal CustomUserDetails user) {
        return Mono.just(Map.of(
                "userId", user.getUser(),
                "roles", user.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList())
        ));
    }

}

