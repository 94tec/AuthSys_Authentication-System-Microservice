package com.techStack.authSys.service.user;


import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Set;

/**
 * Dictionary Password Service
 *
 * Checks if a password is too common or dictionary-based.
 */
@Slf4j
@Service
public class DictionaryPasswordService {

    private static final Set<String> COMMON_PASSWORDS = Set.of(
            "password", "123456", "qwerty", "letmein", "admin"
    );

    /**
     * Check if password is a common dictionary word.
     */
    public Mono<Boolean> isCommonWord(String password) {
        if (password == null) {
            return Mono.just(false);
        }
        boolean common = COMMON_PASSWORDS.contains(password.toLowerCase());
        log.debug("Password {} common word check: {}", password, common);
        return Mono.just(common);
    }
}

