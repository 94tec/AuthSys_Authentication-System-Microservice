package com.techStack.authSys.util.firebase;

import com.google.api.core.ApiFuture;
import com.google.api.core.ApiFutureCallback;
import com.google.api.core.ApiFutures;
import reactor.core.publisher.Mono;

import java.util.concurrent.CompletableFuture;

public class FirestoreUtils {
    public static <T> Mono<T> apiFutureToMono(ApiFuture<T> apiFuture) {
        CompletableFuture<T> completableFuture = new CompletableFuture<>();
        ApiFutures.addCallback(apiFuture, new ApiFutureCallback<>() {
            @Override
            public void onSuccess(T result) {
                completableFuture.complete(result);
            }

            @Override
            public void onFailure(Throwable t) {
                completableFuture.completeExceptionally(t);
            }
        }, Runnable::run); // Direct executor
        return Mono.fromFuture(completableFuture);
    }
}
