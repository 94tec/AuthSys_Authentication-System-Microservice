// auth/repository/UserRepository.java
package com.techStack.authSys.repository.user;


import com.techStack.authSys.models.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByFirebaseUid(String firebaseUid);

    Optional<User> findByEmail(String email);

    Optional<User> findByUsername(String username);

    boolean existsByEmail(String email);

    boolean existsByFirebaseUid(String firebaseUid);

    @Modifying
    @Query("UPDATE User u SET u.lastLoginAt = :loginTime WHERE u.firebaseUid = :firebaseUid")
    void updateLastLogin(String firebaseUid, Instant loginTime);
}