package com.techStack.authSys.repository;

import com.google.cloud.spring.data.firestore.FirestoreReactiveRepository;
import com.techStack.authSys.models.UserProfile;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public interface UserProfileRepository extends FirestoreReactiveRepository<UserProfile> {

    // ✅ Find UserProfile by User ID
    Mono<UserProfile> findByUserId(UUID userId);

    // ✅ Delete UserProfile by User ID
    Mono<Void> deleteByUserId(UUID userId);
}

