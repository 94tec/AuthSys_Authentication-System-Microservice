package com.techStack.authSys.service.auth;

import com.techStack.authSys.auth.repository.FirestoreUserPermissionsRepository;
import com.techStack.authSys.auth.repository.UserDocumentRepository;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserAssembler;
import com.techStack.authSys.models.user.UserDocument;
import com.techStack.authSys.security.context.CustomUserDetails;
import com.techStack.authSys.service.authorization.PermissionResolutionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Reactive UserDetailsService for Spring Security WebFlux.
 *
 * loadUserByUsername() receives the Firebase UID
 * (passed by FirebaseAuthenticationManager).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements ReactiveUserDetailsService {

    private final UserDocumentRepository userDocumentRepository;
    private final UserAssembler userAssembler;
    private final FirestoreUserPermissionsRepository permissionsRepo;
    private final PermissionResolutionService permissionResolver;

    /**
     * @param username Firebase UID
     */
    @Override
    public Mono<UserDetails> findByUsername(String username) {
        return Mono.fromCallable(() ->
                userDocumentRepository.findById(username))
            .subscribeOn(Schedulers.boundedElastic())
            .flatMap(optDoc -> {
                if (optDoc.isEmpty()) {
                    return Mono.error(new UsernameNotFoundException(
                        "User not found: " + username));
                }

                UserDocument doc = optDoc.get();
                User user = userAssembler.assembleFromDocumentOnly(doc);

                Set<SimpleGrantedAuthority> authorities =
                    buildAuthorities(username, doc.getRoleNames());

                user.setAuthorities(authorities);

                List<String> permissions = authorities.stream()
                    .map(SimpleGrantedAuthority::getAuthority)
                    .filter(a -> !a.startsWith("ROLE_"))
                    .toList();

                UserDetails details = new CustomUserDetails(
                    user,
                    doc.getRoleNames(),
                    permissions
                );

                return Mono.just(details);
            });
    }

    private Set<SimpleGrantedAuthority> buildAuthorities(
            String firebaseUid, List<String> roleNames) {

        Set<SimpleGrantedAuthority> authorities = new HashSet<>();

        if (roleNames != null) {
            roleNames.forEach(role ->
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
        }

        permissionsRepo.findByFirebaseUid(firebaseUid).ifPresent(userPerms ->
            permissionResolver.resolve(userPerms)
                .forEach(perm ->
                    authorities.add(new SimpleGrantedAuthority(perm))));

        return authorities;
    }
}