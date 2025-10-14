package com.techStack.authSys.repository;

import com.google.cloud.spring.data.firestore.FirestoreReactiveRepository;
import com.techStack.authSys.models.AuditLog;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Repository
public interface AuditLogRepository extends FirestoreReactiveRepository<AuditLog> {

    // ✅ Find logs by user ID (Firestore uses String IDs)
    Flux<AuditLog> findByUserId(String userId);

    // ✅ Find logs by user ID and action type
    Flux<AuditLog> findByUserIdAndActionType(String userId, String actionType);

    // ✅ Find a specific log entry by ID
    Mono<AuditLog> findById(String id);
}

