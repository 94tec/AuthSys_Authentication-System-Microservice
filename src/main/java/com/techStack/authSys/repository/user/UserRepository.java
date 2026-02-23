package com.techStack.authSys.repository.user;

import com.techStack.authSys.models.user.UserEntity;
import com.techStack.authSys.models.user.UserStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * JPA Repository for UserEntity (PostgreSQL).
 *
 * This repository covers only the relational anchor record.
 * Full user state (roles, permissions, security metadata) lives in
 * Firestore (UserDocument).
 *
 * Model split fix:
 *   Previously JpaRepository<User, UUID> — User was dual-annotated with
 *   @Entity and @Document, causing Spring Data Firestore to reject complex
 *   field types (Map<String,Object>, SecurityMetadata inner classes, Set<>)
 *   at startup. Now typed to UserEntity which is @Entity only.
 *
 * JPQL field name:
 *   updateLastLogin uses u.lastLoginAt — the Java field name on UserEntity,
 *   not the column name (last_login_at). JPQL always uses Java field names.
 */
@Repository
public interface UserRepository extends JpaRepository<UserEntity, UUID> {

    Optional<UserEntity> findByFirebaseUid(String firebaseUid);
    Optional<UserEntity> findByEmail(String email);
    Optional<UserEntity> findByUsername(String username);

    boolean existsByEmail(String email);
    boolean existsByFirebaseUid(String firebaseUid);

    @Modifying
    @Query("UPDATE UserEntity u SET u.lastLoginAt = :loginTime " +
            "WHERE u.firebaseUid = :firebaseUid")
    void updateLastLogin(
            @Param("firebaseUid") String firebaseUid,
            @Param("loginTime") Instant loginTime
    );

    @Modifying
    @Query("UPDATE UserEntity u SET u.status = :status, u.updatedAt = :updatedAt " +
            "WHERE u.firebaseUid = :firebaseUid")
    void updateStatus(
            @Param("firebaseUid") String firebaseUid,
            @Param("status") UserStatus status,
            @Param("updatedAt") Instant updatedAt
    );

    @Modifying
    @Query("UPDATE UserEntity u SET u.enabled = :enabled, u.updatedAt = :updatedAt " +
            "WHERE u.firebaseUid = :firebaseUid")
    void updateEnabled(
            @Param("firebaseUid") String firebaseUid,
            @Param("enabled") boolean enabled,
            @Param("updatedAt") Instant updatedAt
    );

    List<UserEntity> findByStatus(UserStatus status);
    List<UserEntity> findByStatusOrderByCreatedAtAsc(UserStatus status);
    long countByStatus(UserStatus status);
}