package com.techStack.authSys.identity.repository;

import com.google.cloud.spring.data.firestore.FirestoreReactiveRepository;
import com.techStack.authSys.auth.model.UserPasswordHistory;
import reactor.core.publisher.Mono;

public interface UserPasswordHistoryRepository extends FirestoreReactiveRepository<UserPasswordHistory> {

    Mono<UserPasswordHistory> findFirstByUserIdOrderByCreatedAtDesc(String userId);
}
