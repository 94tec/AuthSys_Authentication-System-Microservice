package com.techStack.authSys.repository;

import com.google.cloud.spring.data.firestore.FirestoreReactiveRepository;
import com.techStack.authSys.models.User;
import org.jetbrains.annotations.NotNull;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Repository
public interface AuthRepository extends FirestoreReactiveRepository<User> {

    Mono<User> findByUsername(String username);
    Mono<User> findByEmail(String email);

    @Override
    @NonNull
    Mono<User> findById(@NonNull String id);

    @NotNull Mono<Long> count();
    //Flux<User> findAllByActiveTrue();

    default Mono<Boolean> existsByEmail(String email) {
        return findByEmail(email).hasElement();
    }

    default Mono<Boolean> existsByUsername(String username) {
        return findByUsername(username).hasElement();
    }

    //void updateLastPasswordChangeDate(@NonNull String userId, @NonNull String lastPasswordChangeDate);
}