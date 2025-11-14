package com.techStack.authSys.service;

import com.techStack.authSys.models.Roles;
import com.techStack.authSys.models.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Collections;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private static final Logger logger = LoggerFactory.getLogger(CustomOAuth2UserService.class);

    @Autowired
    private final  FirebaseServiceAuth firebaseServiceAuth;

    public CustomOAuth2UserService(FirebaseServiceAuth firebaseServiceAuth) {
        this.firebaseServiceAuth = firebaseServiceAuth;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        try {
            OAuth2User oAuth2User = super.loadUser(userRequest);
            logger.debug("OAuth2 user loaded successfully: {}", oAuth2User);

            String email = extractEmail(oAuth2User);
            String name = extractName(oAuth2User);

            // Use Mono for reactive Firebase database calls
            User user = findOrCreateUser(email, name).block();

            return createOAuth2User(oAuth2User, user);
        } catch (OAuth2AuthenticationException e) {
            logger.error("OAuth2 authentication failed: {}", e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error during OAuth2 user processing: {}", e.getMessage(), e);
            throw new OAuth2AuthenticationException("An unexpected error occurred");
        }
    }

    private String extractEmail(OAuth2User oAuth2User) throws OAuth2AuthenticationException {
        String email = oAuth2User.getAttribute("email");
        if (email == null || email.isEmpty()) {
            logger.warn("Email attribute is missing in OAuth2 user details");
            throw new OAuth2AuthenticationException("Email attribute is missing");
        }
        logger.debug("Extracted email from OAuth2 user: {}", email);
        return email;
    }

    private String extractName(OAuth2User oAuth2User) {
        String name = oAuth2User.getAttribute("name");
        if (name == null || name.isEmpty()) {
            logger.warn("Name attribute is missing in OAuth2 user details");
            name = "Unknown";
        }
        logger.debug("Extracted name from OAuth2 user: {}", name);
        return name;
    }

    private Mono<User> findOrCreateUser(String email, String name) {
        return firebaseServiceAuth.findByEmail(email)
                .switchIfEmpty(Mono.defer(() -> {
                    User newUser = new User();
                    newUser.setEmail(email);
                    newUser.setUsername(name);
                    // Ensure the role names are stored as List<String>
                    newUser.setRoleNames(Collections.singletonList(Roles.USER.name())); // Convert to List<String>
                    return firebaseServiceAuth.save(newUser);
                }));
    }

    private OAuth2User createOAuth2User(OAuth2User oAuth2User, User user) {
        return new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(user.getRoles().toString())),
                oAuth2User.getAttributes(),
                "email"
        );
    }
}
