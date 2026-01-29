package com.techStack.authSys.controller.user;
import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.dto.request.ForcePasswordChangeRequest;
import com.techStack.authSys.dto.request.PasswordChangeRequest;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.security.context.CurrentUserProvider;
import com.techStack.authSys.service.user.UserService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
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
                        Mono.just(ResponseEntity.status(e.getStatus())
                                .body(new ApiResponse(false, e.getMessage(), null))));
    }

    @PostMapping("/force-change-password")
    public Mono<ResponseEntity<ApiResponse>> forceChangePassword(
            @Valid @RequestBody ForcePasswordChangeRequest request) {

        return userService.forcePasswordChange(request.getUserId(), request.getNewPassword())
                .thenReturn(ResponseEntity.ok(new ApiResponse(true, "Password changed successfully", null)))
                .onErrorResume(CustomException.class, e ->
                        Mono.just(ResponseEntity.status(e.getStatus())
                                .body(new ApiResponse(false, null, e.getMessage()))));
    }
}



