package com.techStack.authSys.security.context;

import com.techStack.authSys.exception.service.CustomException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Reactive helper that extracts the current user's identity from the
 * Spring Security context without blocking.
 *
 * Fix from original:
 *   getCurrentUserId() mapped the principal to CustomUserDetails and then
 *   called .getUsername() — but getUsername() returns the user's email
 *   (it is the UserDetails contract implementation, backed by user.getEmail()).
 *   A method named getCurrentUserId() must return the internal user ID, not email.
 *   Fixed to call .getUserId() instead.
 *
 *   getCurrentUserEmail() is added as a named alternative for callers that
 *   genuinely want the email — so the intent is explicit at the call site.
 */
@Component
@RequiredArgsConstructor
public class CurrentUserProvider {

    /**
     * Returns the authenticated user's internal ID (Firebase UID / database PK).
     *
     * Fix: original returned getUsername() which is the email address.
     * Changed to getUserId() which returns user.getId().
     *
     * @return Mono<String> the user's ID, or UNAUTHORIZED error if not authenticated
     */
    public Mono<String> getCurrentUserId() {
        return getDetails()
                .map(CustomUserDetails::getUserId);
    }

    /**
     * Returns the authenticated user's email address.
     *
     * Added to provide a clearly named alternative to getCurrentUserId() for
     * callers that need the email — previously both use-cases shared the broken
     * getCurrentUserId() which returned email disguised as an ID.
     *
     * @return Mono<String> the user's email, or UNAUTHORIZED error if not authenticated
     */
    public Mono<String> getCurrentUserEmail() {
        return getDetails()
                .map(CustomUserDetails::getUsername); // getUsername() == email per UserDetails contract
    }

    /**
     * Returns the full CustomUserDetails for the authenticated user.
     *
     * @return Mono<CustomUserDetails> or UNAUTHORIZED error if not authenticated
     */
    public Mono<CustomUserDetails> getCurrentUserDetails() {
        return getDetails();
    }

    // -------------------------------------------------------------------------
    // Private
    // -------------------------------------------------------------------------

    private Mono<CustomUserDetails> getDetails() {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(auth -> auth != null && auth.isAuthenticated())
                .map(Authentication::getPrincipal)
                .cast(CustomUserDetails.class)
                .switchIfEmpty(Mono.error(
                        new CustomException(HttpStatus.UNAUTHORIZED, "User not authenticated")));
    }
}