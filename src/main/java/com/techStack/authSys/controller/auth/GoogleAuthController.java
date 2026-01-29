package com.techStack.authSys.controller.auth;


import com.techStack.authSys.service.auth.GoogleAuthService;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.exception.service.CustomException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class GoogleAuthController {

    private final GoogleAuthService googleAuthService;

    @PostMapping("/google-signin")
    public ResponseEntity<User> googleSignIn(@RequestParam String idToken) {
        try {
            User user = googleAuthService.authenticateWithGoogle(idToken);
            return ResponseEntity.ok(user);
        } catch (CustomException e) {
            HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR; // Default status
            if (e.getMessage().contains("Unauthorized")) {
                status = HttpStatus.UNAUTHORIZED;
            } else if (e.getMessage().contains("Bad Request")) {
                status = HttpStatus.BAD_REQUEST;
            }
            return ResponseEntity.status(status).body(null);
        }
    }
}
