package com.techStack.authSys.security.incident;

import com.techStack.authSys.notification.service.NotificationService;
import com.techStack.authSys.security.models.IncidentSeverity;
import com.techStack.authSys.security.models.IncidentType;
import com.techStack.authSys.security.models.SecurityIncident;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * Central place every other service reports security-relevant events to.
 * SUPER_ADMIN reads/resolves through SecurityIncidentController.
 *
 * Design notes:
 * - raise() correlates repeated events (same type+IP or type+user within a
 *   correlation window) into ONE incident with an incrementing occurrenceCount,
 *   instead of flooding the table with duplicate rows.
 * - CRITICAL and HIGH severity incidents trigger an immediate notification to
 *   SUPER_ADMIN via the existing NotificationService (email/SMS/WhatsApp already wired).
 * - Never throws — a failure to log a security event must never block the
 *   request that triggered it. Errors are logged and swallowed.
 * - The correlate-and-increment step in doRaise() is retried on optimistic
 *   lock conflicts (see SecurityIncident.version) since concurrent calls to
 *   raise() for the same type+IP/user are expected under real attack traffic
 *   and a lost update here would silently under-count occurrenceCount and
 *   delay the >=5 auto-escalation to CRITICAL.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityIncidentService {

    private static final int CORRELATION_WINDOW_MINUTES = 15;
    private static final int MAX_RAISE_RETRIES = 3;

    private final SecurityIncidentRepository incidentRepository;
    private final NotificationService notificationService;
    private final Clock clock;

    public void raise(IncidentType type, IncidentSeverity severity, String description,
                      String userId, String ipAddress, String userAgent) {
        Mono.fromRunnable(() -> raiseBlocking(type, severity, description, userId, ipAddress, userAgent))
                .subscribeOn(Schedulers.boundedElastic())
                .doOnError(e -> log.error("Failed to raise security incident [{}]: {}", type, e.getMessage()))
                .onErrorResume(e -> Mono.empty())
                .subscribe();
    }

    private void raiseBlocking(IncidentType type, IncidentSeverity severity, String description,
                               String userId, String ipAddress, String userAgent) {
        for (int attempt = 1; attempt <= MAX_RAISE_RETRIES; attempt++) {
            try {
                doRaise(type, severity, description, userId, ipAddress, userAgent);
                return;
            } catch (ObjectOptimisticLockingFailureException e) {
                log.debug("Optimistic lock conflict raising incident [{} / {}], retry {}/{}",
                        type, ipAddress != null ? ipAddress : userId, attempt, MAX_RAISE_RETRIES);
            }
        }
        // Swallowed by raise()'s onErrorResume in the normal (async) path, but raiseBlocking()
        // can also be invoked directly (e.g. in tests), so make the exhaustion visible.
        log.warn("Failed to raise security incident [{}] after {} retries due to contention",
                type, MAX_RAISE_RETRIES);
    }

    private void doRaise(IncidentType type, IncidentSeverity severity, String description,
                         String userId, String ipAddress, String userAgent) {
        Instant since = clock.instant().minus(CORRELATION_WINDOW_MINUTES, ChronoUnit.MINUTES);

        var existing = userId != null
                ? incidentRepository.findFirstByTypeAndUserIdAndResolvedFalseAndCreatedDateAfter(type, userId, since)
                : incidentRepository.findFirstByTypeAndIpAddressAndResolvedFalseAndCreatedDateAfter(type, ipAddress, since);

        SecurityIncident incident = existing.map(i -> {
            i.setOccurrenceCount(i.getOccurrenceCount() + 1);
            //i.setUpdatedAt(clock.instant());
            // Escalate severity if repeated occurrences suggest an active attack
            if (i.getOccurrenceCount() >= 5 && i.getSeverity() != IncidentSeverity.CRITICAL) {
                i.setSeverity(IncidentSeverity.CRITICAL);
            }
            return i;
        }).orElseGet(() -> SecurityIncident.builder()
                .type(type)
                .severity(severity)
                .description(description)
                .userId(userId)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .occurrenceCount(1)
                .resolved(false)
                .build());

        // Throws ObjectOptimisticLockingFailureException on a lost-update race
        // (see @Version on SecurityIncident) — caught by raiseBlocking()'s retry loop.
        SecurityIncident saved = incidentRepository.save(incident);

        log.warn("🚨 Security incident [{} / {}] occurrence={} ip={} user={}",
                saved.getType(), saved.getSeverity(), saved.getOccurrenceCount(), ipAddress, userId);

        if (saved.getSeverity() == IncidentSeverity.CRITICAL || saved.getSeverity() == IncidentSeverity.HIGH) {
            notificationService.onSecurityIncidentRaised(saved.getType().name(), saved.getSeverity().name(),
                    saved.getDescription(), saved.getOccurrenceCount());
        }
    }

    public Mono<Page<SecurityIncident>> getOpenIncidents(Pageable pageable) {
        return Mono.fromCallable(() -> incidentRepository.findByResolvedFalseOrderByCreatedDateDesc(pageable))
                .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<Page<SecurityIncident>> getBySeverity(IncidentSeverity severity, Pageable pageable) {
        return Mono.fromCallable(() ->
                        incidentRepository.findBySeverityAndResolvedFalseOrderByCreatedDateDesc(severity, pageable))
                .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<SecurityIncident> resolve(UUID incidentId, String resolverId, String notes) {
        return Mono.fromCallable(() -> {
                    SecurityIncident incident = incidentRepository.findById(incidentId)
                            .orElseThrow(() -> new IllegalArgumentException("Incident not found: " + incidentId));
                    incident.setResolved(true);
                    incident.setResolvedBy(resolverId);
                    incident.setResolvedAt(clock.instant());
                    incident.setResolutionNotes(notes);
                    return incidentRepository.save(incident);
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<java.util.Map<String, Long>> getIncidentCounts() {
        return Mono.fromCallable(() -> java.util.Map.of(
                        "critical", incidentRepository.countBySeverityAndResolvedFalse(IncidentSeverity.CRITICAL),
                        "high", incidentRepository.countBySeverityAndResolvedFalse(IncidentSeverity.HIGH),
                        "medium", incidentRepository.countBySeverityAndResolvedFalse(IncidentSeverity.MEDIUM),
                        "low", incidentRepository.countBySeverityAndResolvedFalse(IncidentSeverity.LOW),
                        "totalOpen", incidentRepository.countByResolvedFalse()
                ))
                .subscribeOn(Schedulers.boundedElastic());
    }
}