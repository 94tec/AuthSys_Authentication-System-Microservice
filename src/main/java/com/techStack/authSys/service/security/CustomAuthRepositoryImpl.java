package com.techStack.authSys.service.security;

import com.google.api.core.ApiFuture;
import com.google.cloud.firestore.*;
import com.google.cloud.spring.data.firestore.FirestoreTemplate;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.repository.user.CustomAuthRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;

import java.util.List;
import java.util.concurrent.ExecutionException;

@Repository
@RequiredArgsConstructor
public class CustomAuthRepositoryImpl implements CustomAuthRepository {

    private final Firestore firestore;
    private final FirestoreTemplate firestoreTemplate;

    @Override
    public Flux<User> findUsersAfterCursor(String cursorUsername, int pageSize) {
        return Flux.defer(() -> {
            try {
                CollectionReference usersCollection = firestore.collection("users");

                Query query;
                if (cursorUsername == null) {
                    query = usersCollection.orderBy("username").limit(pageSize);
                } else {
                    query = usersCollection.orderBy("username").startAfter(cursorUsername).limit(pageSize);
                }

                ApiFuture<QuerySnapshot> querySnapshot = query.get();
                List<User> users = querySnapshot.get().toObjects(User.class);

                return Flux.fromIterable(users);

            } catch (InterruptedException | ExecutionException e) {
                return Flux.error(e);
            }
        });
    }
}




