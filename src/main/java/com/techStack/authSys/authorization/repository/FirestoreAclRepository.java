package com.techStack.authSys.authorization.repository;


import com.google.cloud.spring.data.firestore.FirestoreReactiveRepository;

import com.techStack.authSys.authorization.models.FirestoreAclEntry;
import reactor.core.publisher.Mono;

public interface FirestoreAclRepository extends FirestoreReactiveRepository<FirestoreAclEntry> {

    Mono<FirestoreAclEntry> findByObjectIdAndPrincipal(String objectId, String principal);
}
