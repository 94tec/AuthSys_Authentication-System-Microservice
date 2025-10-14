package com.techStack.authSys.service;

import com.techStack.authSys.repository.AuthRepository;
import com.techStack.authSys.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;


@Service
@RequiredArgsConstructor
public class CustomReactiveUserDetailsService implements ReactiveUserDetailsService {
    private final UserService userService;
    private final AuthRepository authRepository;

    public Mono<UserDetails> updatePassword(CustomUserDetails userDetails, String newPassword) {
        return userService.forcePasswordChange(userDetails.getUsername(), newPassword)
                .then(Mono.defer(() -> authRepository.findByUsername(userDetails.getUsername())))
                .map(user -> new CustomUserDetails(
                        user,
                        user.getRoles().stream()
                                .map(Enum::name)
                                .toList(),
                        user.getPermissions()
                ));
    }


    @Override
    public Mono<UserDetails> findByUsername(String username) {
        return null;
    }
}

