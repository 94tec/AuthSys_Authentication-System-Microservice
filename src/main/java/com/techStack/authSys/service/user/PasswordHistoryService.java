package com.techStack.authSys.service.user;

import com.google.cloud.firestore.*;
import com.techStack.authSys.service.security.EncryptionService;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PasswordHistoryService {

    private final Firestore firestore;
    private final EncryptionService encryptionService;

    public Mono<Boolean> isPasswordReused(String userId, String newPassword) {
        return Mono.fromCallable(() ->
                        firestore.collection("password_history")
                                .document(userId)
                                .collection("history")
                                .orderBy("createdAt", Query.Direction.DESCENDING)
                                .limit(5)
                                .get()
                )
                .flatMap(apiFuture -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(apiFuture)))
                .flatMapMany(querySnapshot -> Flux.fromIterable(querySnapshot.getDocuments()))
                .publishOn(Schedulers.boundedElastic())
                .map(doc -> {
                    String encryptedPassword = doc.getString("password");
                    return encryptionService.decrypt(encryptedPassword);
                })
                .any(decrypted -> decrypted.equals(newPassword));
    }
    public Mono<Void> saveToHistory(String userId, String plainPassword) {
        return Mono.fromCallable(() -> {
                    String encrypted = encryptionService.encrypt(plainPassword);

                    Map<String, Object> entry = new HashMap<>();
                    entry.put("password", encrypted);
                    entry.put("createdAt", new Date());

                    return firestore.collection("password_history")
                            .document(userId)
                            .collection("history")
                            .document(UUID.randomUUID().toString())
                            .set(entry);
                })
                .flatMap(apiFuture -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(apiFuture)))
                .then();
    }

}

