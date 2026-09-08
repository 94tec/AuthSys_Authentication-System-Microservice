package com.techStack.authSys.security.incident;

import com.techStack.authSys.security.models.IncidentSeverity;
import com.techStack.authSys.security.models.SecurityIncident;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/admin/security/incidents")
@RequiredArgsConstructor
@PreAuthorize("hasRole('SUPER_ADMIN')")
@Validated
public class SecurityIncidentController {

    private final SecurityIncidentService incidentService;

    @GetMapping
    public Mono<ResponseEntity<Page<SecurityIncident>>> getOpenIncidents(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size,
            @RequestParam(required = false) IncidentSeverity severity
    ) {
        PageRequest pageable = PageRequest.of(page, size);
        Mono<Page<SecurityIncident>> result = severity != null
                ? incidentService.getBySeverity(severity, pageable)
                : incidentService.getOpenIncidents(pageable);
        return result.map(ResponseEntity::ok);
    }

    @GetMapping("/summary")
    public Mono<ResponseEntity<Map<String, Long>>> getSummary() {
        return incidentService.getIncidentCounts().map(ResponseEntity::ok);
    }

    @PostMapping("/{incidentId}/resolve")
    public Mono<ResponseEntity<SecurityIncident>> resolve(
            @PathVariable UUID incidentId,
            @RequestParam @NotBlank String notes
    ) {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getName())
                .flatMap(resolverId -> incidentService.resolve(incidentId, resolverId, notes))
                .map(ResponseEntity::ok);
    }
}