package com.techStack.authSys.security;

import com.techStack.authSys.exception.CustomException;
import org.springframework.stereotype.Component;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.Authentication;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;
import lombok.RequiredArgsConstructor;


@Component
@RequiredArgsConstructor
public class CurrentUserProvider {

    public Mono<String> getCurrentUserId() {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(auth -> auth != null && auth.isAuthenticated())
                .map(Authentication::getPrincipal)
                .cast(CustomUserDetails.class)
                .map(CustomUserDetails::getUsername)
                .switchIfEmpty(Mono.error(new CustomException(HttpStatus.UNAUTHORIZED, "User not authenticated")));
    }

    public Mono<CustomUserDetails> getCurrentUserDetails() {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(auth -> auth != null && auth.isAuthenticated())
                .map(Authentication::getPrincipal)
                .cast(CustomUserDetails.class)
                .switchIfEmpty(Mono.error(new CustomException(HttpStatus.UNAUTHORIZED, "User not authenticated")));
    }
}
