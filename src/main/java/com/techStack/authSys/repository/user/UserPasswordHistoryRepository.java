package com.techStack.authSys.repository.user;

import com.techStack.authSys.models.user.UserPasswordHistory;
import com.google.cloud.spring.data.firestore.FirestoreReactiveRepository;
import reactor.core.publisher.Mono;

public interface UserPasswordHistoryRepository extends FirestoreReactiveRepository<UserPasswordHistory> {

    Mono<UserPasswordHistory> findFirstByUserIdOrderByCreatedAtDesc(String userId);
}
