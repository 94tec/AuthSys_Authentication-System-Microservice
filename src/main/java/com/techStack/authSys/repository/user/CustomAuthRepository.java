package com.techStack.authSys.repository.user;

import com.techStack.authSys.models.user.User;
import reactor.core.publisher.Flux;

public interface CustomAuthRepository {
    Flux<User> findUsersAfterCursor(String cursorUsername, int pageSize);
}



