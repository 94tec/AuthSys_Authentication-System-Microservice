package com.techStack.authSys.customer.listener;

import com.techStack.authSys.auth.event.UserRegisteredEvent;
import com.techStack.authSys.customer.service.CustomerService;
import com.techStack.authSys.identity.models.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;

/**
 * Eagerly creates a CustomerProfile the moment a USER-role account finishes
 * registration, instead of waiting for the first GET /api/customers/me call.
 * Business rule (confirmed): USER role == customer. Registered users all
 * carry the same role/permission set and are customers by definition — so
 * the role check below isn't a narrow special case, it's the actual rule:
 * only USER-role registrations get a customer_profiles row. Staff accounts
 * (ADMIN/MANAGER/OPERATOR), if they ever flow through the same
 * UserRegisteredEvent,
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CustomerProfileCreationListener {

    private static final String CUSTOMER_ROLE = "USER";

    private final CustomerService customerService;

    @EventListener
    public void onUserRegistered(UserRegisteredEvent event) {
        User user = event.getUser();

        boolean isCustomer = user.getRoleNames() != null
                && user.getRoleNames().contains(CUSTOMER_ROLE);

        if (!isCustomer) {
            log.debug("Skipping customer profile creation for non-USER registration: roles={}",
                    user.getRoleNames());
            return;
        }

        customerService.getOrCreateProfile(
                        user.getId(),
                        user.getFirstName(),
                        user.getLastName(),
                        user.getEmail()
                )
                .retryWhen(Retry.backoff(3, Duration.ofMillis(200))
                        .filter(this::isRetryable))
                .doOnSuccess(profile -> log.info(
                        "✅ Customer profile created eagerly at registration for: {}", user.getEmail()))
                .doOnError(e -> log.error(
                        "⚠️ Eager customer profile creation failed for {} — will fall back to lazy " +
                                "creation on first /api/customers/me call.",
                        user.getEmail(), e))
                .onErrorResume(e -> Mono.empty())
                .subscribe();
    }

    /**
     * Retry transient failures only (DB connection blips, etc.) — never
     * retry validation/logic errors, which will just fail identically
     * every time and waste three attempts before giving up anyway.
     */
    private boolean isRetryable(Throwable t) {
        return !(t instanceof IllegalArgumentException)
                && !(t instanceof IllegalStateException);
    }
}