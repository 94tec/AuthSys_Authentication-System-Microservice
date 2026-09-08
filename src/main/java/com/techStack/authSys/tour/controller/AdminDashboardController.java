package com.techStack.authSys.tour.controller;

import com.techStack.authSys.tour.dto.response.RevenueDashboardResponse;
import com.techStack.authSys.tour.services.RevenueDashboardService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/admin/dashboard")
@RequiredArgsConstructor
public class AdminDashboardController {

    private final RevenueDashboardService revenueDashboardService;

    @GetMapping("/revenue")
    @PreAuthorize("hasAnyRole('ADMIN','SUPER_ADMIN','MANAGER')")
    public Mono<RevenueDashboardResponse> revenue() {
        return revenueDashboardService.getRevenueDashboard();
    }
}