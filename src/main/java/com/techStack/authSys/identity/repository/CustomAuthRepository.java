package com.techStack.authSys.identity.repository;

import com.techStack.authSys.identity.models.User;
import reactor.core.publisher.Flux;

public interface CustomAuthRepository {
    Flux<User> findUsersAfterCursor(String cursorUsername, int pageSize);
}



