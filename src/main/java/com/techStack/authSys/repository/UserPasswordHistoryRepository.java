package com.techStack.authSys.repository;

import com.techStack.authSys.models.UserPasswordHistory;
import com.google.cloud.spring.data.firestore.FirestoreReactiveRepository;
import reactor.core.publisher.Mono;

public interface UserPasswordHistoryRepository extends FirestoreReactiveRepository<UserPasswordHistory> {

    Mono<UserPasswordHistory> findFirstByUserIdOrderByCreatedAtDesc(String userId);
}
