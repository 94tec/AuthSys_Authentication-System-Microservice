package com.techStack.authSys.notification.controller;

import com.techStack.authSys.auth.context.CustomUserDetails;
import com.techStack.authSys.common.dto.ApiResponse;
import com.techStack.authSys.notification.dto.response.NotificationLogResponse;
import com.techStack.authSys.notification.dto.response.NotificationStatsResponse;
import com.techStack.authSys.notification.service.NotificationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * NotificationController — /api/notifications/**
 *
 * USER (authenticated customer):
 *   GET /api/notifications/me               in-app notification bell feed
 *
 * MANAGER, ADMIN, SUPER_ADMIN (staff):
 *   GET /api/notifications/reference/{id}   all notifications for a booking/payment
 *
 * ADMIN, SUPER_ADMIN:
 *   GET /api/notifications/admin/all        full log — paginated
 *   GET /api/notifications/admin/stats      delivery health dashboard
 *   POST /api/notifications/admin/retry     manually trigger retry of failed rows
 */
@RestController
@RequestMapping("/api/notifications")
@RequiredArgsConstructor
@Tag(name = "Notifications", description = "Notification log and delivery monitoring")
public class NotificationController {

    private final NotificationService notificationService;

    // ── USER: in-app bell ─────────────────────────────────────────────────────

    @GetMapping("/me")
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Customer notification history — in-app bell feed")
    public Mono<Page<NotificationLogResponse>> getMyNotifications(
            @RequestParam(defaultValue = "0")  int page,
            @RequestParam(defaultValue = "20") int size,
            @AuthenticationPrincipal CustomUserDetails user) {
        return notificationService.getMyNotifications(user.getUserId(), page, size);
    }

    // ── STAFF: reference lookup ───────────────────────────────────────────────

    @GetMapping("/reference/{referenceId}")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "All notifications for a booking or payment ID — staff customer service")
    public Flux<NotificationLogResponse> getByReference(@PathVariable String referenceId) {
        return notificationService.getByReference(referenceId);
    }

    // ── ADMIN: full log ───────────────────────────────────────────────────────

    @GetMapping("/admin/all")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Full notification log — paginated, newest first")
    public Mono<Page<NotificationLogResponse>> getAllNotifications(
            @RequestParam(defaultValue = "0")  int page,
            @RequestParam(defaultValue = "50") int size) {
        return notificationService.getAllNotifications(page, size);
    }

    // ── ADMIN: delivery health stats ──────────────────────────────────────────

    @GetMapping("/admin/stats")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Notification delivery health — pending, sent, failed, recent failures")
    public Mono<ResponseEntity<ApiResponse<NotificationStatsResponse>>> getStats() {
        return notificationService.getStats()
            .map(stats -> ResponseEntity.ok(
                new ApiResponse<>(true, "Notification statistics", stats)));
    }

    // ── ADMIN: manual retry ───────────────────────────────────────────────────

    @PostMapping("/admin/retry")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Manually trigger retry of all FAILED notifications within retry window")
    public Mono<ResponseEntity<ApiResponse<Integer>>> retryFailed() {
        return notificationService.retryFailed()
            .map(count -> ResponseEntity.ok(
                new ApiResponse<>(true, "Retried " + count + " notifications", count)));
    }
}
