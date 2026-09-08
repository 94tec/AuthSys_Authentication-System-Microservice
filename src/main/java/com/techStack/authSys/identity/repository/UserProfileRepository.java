package com.techStack.authSys.identity.repository;

import com.google.cloud.spring.data.firestore.FirestoreReactiveRepository;
import com.techStack.authSys.identity.models.UserProfile;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface UserProfileRepository extends FirestoreReactiveRepository<UserProfile> {
    Mono<UserProfile> findByUserId(String userId);
    Mono<Void> deleteByUserId(String userId);
}