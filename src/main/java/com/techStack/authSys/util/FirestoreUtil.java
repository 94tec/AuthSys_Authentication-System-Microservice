package com.techStack.authSys.util;

import com.google.api.core.ApiFuture;
import org.springframework.stereotype.Component;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

@Component
public class FirestoreUtil {

    /**
     * Converts a Google Cloud ApiFuture to a CompletableFuture.
     *
     * @param apiFuture the ApiFuture to convert
     * @param <T>       the type of the future's result
     * @return a CompletableFuture representing the result of the ApiFuture
     */
    public static <T> CompletableFuture<T> toCompletableFuture(ApiFuture<T> apiFuture) {
        CompletableFuture<T> completableFuture = new CompletableFuture<>();

        apiFuture.addListener(() -> {
            try {
                // Completes the CompletableFuture when the ApiFuture is done
                T result = apiFuture.get();  // Might throw ExecutionException or InterruptedException
                completableFuture.complete(result);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); // Restore the interrupted status
                completableFuture.completeExceptionally(e);
            } catch (ExecutionException e) {
                completableFuture.completeExceptionally(e.getCause());
            }
        }, Runnable::run);

        return completableFuture;
    }
}
