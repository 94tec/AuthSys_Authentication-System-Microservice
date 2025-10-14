package com.techStack.authSys.controller;

import com.techStack.authSys.dto.ApiResponse;
import com.techStack.authSys.dto.PasswordResetRequest;
import com.techStack.authSys.dto.PasswordResetCompletion;
import com.techStack.authSys.dto.TokenValidationRequest;
import com.techStack.authSys.exception.*;
import com.techStack.authSys.service.PasswordResetService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/v1/password-reset")
@RequiredArgsConstructor
public class PasswordResetController {

    private final PasswordResetService passwordResetService;

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

    @PostMapping("/complete")
    public Mono<ResponseEntity<ApiResponse>> completePasswordReset(
            @RequestBody PasswordResetCompletion request) {
        return passwordResetService.completePasswordReset(request.getToken(), request.getNewPassword())
                .map(user -> ResponseEntity.ok(new ApiResponse(true, user, null)))
                .onErrorResume(InvalidTokenException.class, e ->
                        Mono.just(ResponseEntity.badRequest()
                                .body(new ApiResponse(false, null, e.getMessage()))))
                .onErrorResume(IllegalArgumentException.class, e ->
                        Mono.just(ResponseEntity.badRequest()
                                .body(new ApiResponse(false, null, e.getMessage()))))
                .onErrorResume(UserNotFoundException.class, e ->
                        Mono.just(ResponseEntity.status(HttpStatus.NOT_FOUND)
                                .body(new ApiResponse(false, null, e.getMessage()))))
                .onErrorResume(e ->
                        Mono.just(ResponseEntity.internalServerError()
                                .body(new ApiResponse(false, null, "Failed to complete password reset"))));
    }
}
