package com.techStack.authSys.service.authorization;

import com.techStack.authSys.models.authorization.FirestoreAclEntry;
import com.techStack.authSys.repository.authorization.FirestoreAclRepository;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class FirestoreAclService {

    private final FirestoreAclRepository aclRepository;

    public FirestoreAclService(FirestoreAclRepository aclRepository) {
        this.aclRepository = aclRepository;
    }

    /**
     * Check if a user has a specific permission on a given object.
     */
    public Mono<Boolean> hasPermission(String userId, String objectId, String permission) {
        return aclRepository.findByObjectIdAndPrincipal(objectId, userId)
                .map(acl -> acl.getPermissions().contains(permission))
                .defaultIfEmpty(false);
    }

    /**
     * Grant a permission to a user.
     */
    public Mono<FirestoreAclEntry> grantPermission(String userId, String objectId, String permission) {
        return aclRepository.findByObjectIdAndPrincipal(objectId, userId)
                .switchIfEmpty(Mono.just(new FirestoreAclEntry(objectId, userId)))
                .flatMap(acl -> {
                    acl.getPermissions().add(permission);
                    return aclRepository.save(acl);
                });
    }

    /**
     * Revoke a permission from a user.
     */
    public Mono<Void> revokePermission(String userId, String objectId, String permission) {
        return aclRepository.findByObjectIdAndPrincipal(objectId, userId)
                .flatMap(acl -> {
                    acl.getPermissions().remove(permission);
                    if (acl.getPermissions().isEmpty()) {
                        return aclRepository.delete(acl);
                    }
                    return aclRepository.save(acl).then();
                });
    }
}

