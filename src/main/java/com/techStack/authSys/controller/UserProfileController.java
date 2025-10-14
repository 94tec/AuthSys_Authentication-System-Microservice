package com.techStack.authSys.controller;

import com.techStack.authSys.dto.UserProfileDTO;
import com.techStack.authSys.service.UserProfileService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

@RestController
@RequestMapping("/api/user-profiles")
public class UserProfileController {

    private final UserProfileService userProfileService;

    public UserProfileController(UserProfileService userProfileService) {
        this.userProfileService = userProfileService;
    }

    // ✅ Create User Profile
    @PostMapping("/{userId}")
    @PreAuthorize("hasAuthority('profile:create') or #userId == authentication.principal.id")
    public Mono<ResponseEntity<UserProfileDTO>> createUserProfile(@PathVariable UUID userId, @RequestBody UserProfileDTO profileDTO) {
        return userProfileService.createUserProfile(userId, profileDTO)
                .map(ResponseEntity::ok); // ✅ Wrap Mono result in ResponseEntity
    }

    // ✅ Get User Profile by User ID
    @GetMapping("/{userId}")
    @PreAuthorize("hasAuthority('profile:read') or #userId == authentication.principal.id")
    public Mono<ResponseEntity<UserProfileDTO>> getUserProfile(@PathVariable UUID userId) {
        return userProfileService.getUserProfile(userId)
                .map(ResponseEntity::ok) // ✅ Convert Mono<UserProfileDTO> to Mono<ResponseEntity<UserProfileDTO>>
                .defaultIfEmpty(ResponseEntity.notFound().build()); // ✅ Handle case where profile is not found
    }

    @PutMapping("/{userId}")
    @PreAuthorize("hasAuthority('profile:update') or #userId == authentication.principal.id")
    public Mono<ResponseEntity<UserProfileDTO>> updateUserProfile(@PathVariable UUID userId, @RequestBody UserProfileDTO profileDTO) {
        return userProfileService.updateUserProfile(userId, profileDTO)
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.notFound().build()); // ✅ Handle not found case properly
    }


    // ✅ Delete User Profile
    @DeleteMapping("/{userId}")
    @PreAuthorize("hasAuthority('profile:delete') or #userId == authentication.principal.id")
    public ResponseEntity<Void> deleteUserProfile(@PathVariable UUID userId) {
        userProfileService.deleteUserProfile(userId);
        return ResponseEntity.noContent().build();
    }
}

