package com.techStack.authSys.repository;

import com.techStack.authSys.models.User;
import reactor.core.publisher.Flux;

import java.time.Instant;

public interface CustomAuthRepository {
    Flux<User> findUsersAfterCursor(String cursorUsername, int pageSize);
}



