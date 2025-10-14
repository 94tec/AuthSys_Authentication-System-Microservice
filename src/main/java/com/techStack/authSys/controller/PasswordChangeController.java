package com.techStack.authSys.controller;
import com.techStack.authSys.dto.ApiResponse;
import com.techStack.authSys.dto.ForcePasswordChangeRequest;
import com.techStack.authSys.dto.PasswordChangeRequest;
import com.techStack.authSys.exception.CustomException;
import com.techStack.authSys.security.CurrentUserProvider;
import com.techStack.authSys.service.UserService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import lombok.Data;
import lombok.RequiredArgsConstructor;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class PasswordChangeController {
    private final UserService userService;
    private final CurrentUserProvider currentUserProvider;

    @PostMapping("/change-password")
    public Mono<ResponseEntity<ApiResponse>> changePassword(
            @Valid @RequestBody PasswordChangeRequest request,
            ServerWebExchange exchange) {

        return currentUserProvider.getCurrentUserId()
                .flatMap(userId -> userService.changePassword(
                        userId,
                        request.getCurrentPassword(),
                        request.getNewPassword()
                ))
                .then(Mono.fromRunnable(() ->
                        exchange.getSession().subscribe(WebSession::invalidate)
                ))
                .thenReturn(ResponseEntity.ok(new ApiResponse(true, "Password changed successfully", null)))
                .onErrorResume(CustomException.class, e ->
                        Mono.just(ResponseEntity.status(e.getStatusCode())
                                .body(new ApiResponse(false, e.getMessage(), null))));
    }

    @PostMapping("/force-change-password")
    public Mono<ResponseEntity<ApiResponse>> forceChangePassword(
            @Valid @RequestBody ForcePasswordChangeRequest request) {

        return userService.forcePasswordChange(request.getUserId(), request.getNewPassword())
                .thenReturn(ResponseEntity.ok(new ApiResponse(true, "Password changed successfully", null)))
                .onErrorResume(CustomException.class, e ->
                        Mono.just(ResponseEntity.status(e.getStatusCode())
                                .body(new ApiResponse(false, null, e.getMessage()))));
    }
}



