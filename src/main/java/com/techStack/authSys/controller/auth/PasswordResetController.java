package com.techStack.authSys.controller.auth;

import com.techStack.authSys.dto.request.PasswordResetRequest;
import com.techStack.authSys.dto.internal.TokenValidationRequest;
import com.techStack.authSys.exception.account.UserNotFoundException;
import com.techStack.authSys.exception.email.EmailSendingException;
import com.techStack.authSys.service.user.PasswordResetService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/v1/password-reset")
@RequiredArgsConstructor
public class PasswordResetController {

    private final PasswordResetService passwordResetService;
    private static final Logger logger = LoggerFactory.getLogger(PasswordResetService.class);

    @PostMapping("/initiate")
    public Mono<ResponseEntity<String>> initiatePasswordReset(
            @RequestBody PasswordResetRequest request) {
        return passwordResetService.initiatePasswordReset(request.getEmail())
                .map(token -> ResponseEntity.ok("Password reset email sent"))
                .onErrorResume(IllegalArgumentException.class, e ->
                        Mono.just(ResponseEntity.badRequest().body(e.getMessage())))
                .onErrorResume(UserNotFoundException.class, e ->
                        Mono.just(ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage())))
                .onErrorResume(EmailSendingException.class, e ->
                        Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                                .body("Failed to send reset email. Please try again later.")))
                .onErrorResume(e ->
                        Mono.just(ResponseEntity.internalServerError()
                                .body("An unexpected error occurred")));
    }

    @PostMapping("/validate-token")
    public Mono<ResponseEntity<Boolean>> validateResetToken(
            @RequestBody TokenValidationRequest request) {
        return passwordResetService.validateResetToken(request.getToken())
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.badRequest().body(false))
                .onErrorResume(e ->
                        Mono.just(ResponseEntity.internalServerError().body(false)));
    }

}
