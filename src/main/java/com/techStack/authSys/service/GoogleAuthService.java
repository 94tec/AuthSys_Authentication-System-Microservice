package com.techStack.authSys.service;


import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import com.techStack.authSys.exception.CustomException;
import com.techStack.authSys.models.User;
import com.techStack.authSys.repository.AuthRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class GoogleAuthService {

    private static final Logger logger = LoggerFactory.getLogger(GoogleAuthService.class);
    private final AuthRepository authRepository;

    @Transactional
    public User authenticateWithGoogle(String idToken) throws CustomException {
        try {
            FirebaseToken firebaseToken = FirebaseAuth.getInstance().verifyIdToken(idToken);

            String email = firebaseToken.getEmail();
            String name = firebaseToken.getName();
            String uid = firebaseToken.getUid();

            logger.info("Google authentication successful for user: {}", email);

            User user = authRepository.findByEmail(email)
                    .switchIfEmpty(Mono.defer(() -> {
                        User newUser = new User();
                        newUser.setEmail(email);
                        newUser.setUsername(uid);
                        newUser.setFirstName(name);
                        newUser.setEnabled(true);
                        return authRepository.save(newUser);
                    }))
                    .block(); // Blocking call to get the User synchronously

            return user;

        } catch (FirebaseAuthException e) {
            logger.error("Google authentication failed: {}", e.getMessage());
            throw new CustomException(HttpStatus.UNAUTHORIZED, "Invalid Google ID token.");
        }
    }

}
