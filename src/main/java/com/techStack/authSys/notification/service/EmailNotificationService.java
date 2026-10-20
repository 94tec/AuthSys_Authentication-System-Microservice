package com.techStack.authSys.notification.service;

import com.techStack.authSys.notification.models.NotificationChannel;
import com.techStack.authSys.notification.models.NotificationContext;
import com.techStack.authSys.notification.models.NotificationLog;
import com.techStack.authSys.notification.models.NotificationType;
import com.techStack.authSys.notification.repository.NotificationLogRepository;
import com.techStack.authSys.notification.template.NotificationTemplateEngine;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * EmailNotificationService — booking / payment / account emails.
 * Renders the template, delegates delivery to BrevoClient, persists the result.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EmailNotificationService {

    private final BrevoClient                brevoClient;
    private final NotificationLogRepository  logRepository;
    private final NotificationTemplateEngine templateEngine;

    public Mono<Void> send(NotificationType type, NotificationContext ctx,
                           NotificationLog logEntry) {

        if (ctx.getCustomerEmail() == null || ctx.getCustomerEmail().isBlank()) {
            return Mono.fromRunnable(() -> {
                logEntry.markSkipped("No email address on record");
                logRepository.save(logEntry);
                log.warn("Email skipped — no address: customerId={}", ctx.getCustomerId());
            }).subscribeOn(Schedulers.boundedElastic()).then();
        }

        String subject  = templateEngine.renderSubject(type, ctx);
        String htmlBody = templateEngine.renderBody(type, NotificationChannel.EMAIL, ctx);

        // Persist subject + body for audit
        logEntry.setSubject(subject);
        logEntry.setBody(htmlBody);

        return brevoClient.send(ctx.getCustomerEmail(), ctx.getCustomerName(), subject, htmlBody)
                .flatMap(messageId -> Mono.fromRunnable(() -> {
                    logEntry.markSent(messageId);
                    logRepository.save(logEntry);
                    log.info("Email sent: type={} to={} messageId={}",
                            type, ctx.getCustomerEmail(), messageId);
                }).subscribeOn(Schedulers.boundedElastic()))
                .onErrorResume(e -> Mono.fromRunnable(() -> {
                    logEntry.markFailed(e.getMessage());
                    logRepository.save(logEntry);
                    log.error("Email failed: type={} to={} error={}",
                            type, ctx.getCustomerEmail(), e.getMessage());
                }).subscribeOn(Schedulers.boundedElastic()))
                .then();
    }
}