package com.techStack.authSys.service.user;

import com.techStack.authSys.dto.response.UserProfileDTO;
import com.techStack.authSys.exception.resource.ResourceNotFoundException;
import com.techStack.authSys.models.user.UserProfile;
import com.techStack.authSys.repository.user.UserProfileRepository;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Service
@Transactional
public class UserProfileService {

    private final UserProfileRepository userProfileRepository;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final ModelMapper modelMapper;

    public UserProfileService(UserProfileRepository userProfileRepository, FirebaseServiceAuth firebaseServiceAuth, ModelMapper modelMapper) {
        this.userProfileRepository = userProfileRepository;
        this.firebaseServiceAuth = firebaseServiceAuth;
        this.modelMapper = modelMapper;
    }

    @PreAuthorize("hasAuthority('profile:create') or #userId.toString() == authentication.name")
    public Mono<UserProfileDTO> createUserProfile(UUID userId, UserProfileDTO profileDTO) {
        String userIdStr = userId.toString(); // Convert UUID to String

        return firebaseServiceAuth.getUserById(userIdStr)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException(HttpStatus.NOT_FOUND, "User not found with ID: " + userId)))
                .flatMap(user -> {
                    UserProfile userProfile = modelMapper.map(profileDTO, UserProfile.class);
                    userProfile.setUserId(userIdStr); // Ensure userId is set
                    return userProfileRepository.save(userProfile);
                })
                .map(savedProfile -> modelMapper.map(savedProfile, UserProfileDTO.class));
    }


    // ✅ Get User Profile by ID
    @PreAuthorize("hasAuthority('profile:read') or #userId == authentication.principal.id")
    public Mono<UserProfileDTO> getUserProfile(UUID userId) {
        return userProfileRepository.findByUserId(userId)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException(HttpStatus.NOT_FOUND, "UserProfile not found for User ID: " + userId)))
                .map(profile -> modelMapper.map(profile, UserProfileDTO.class));
    }

    // ✅ Update User Profile
    @PreAuthorize("hasAuthority('profile:update') or #userId == authentication.principal.id")
    public Mono<UserProfileDTO> updateUserProfile(UUID userId, UserProfileDTO profileDTO) {
        return userProfileRepository.findByUserId(userId)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException(HttpStatus.NOT_FOUND, "UserProfile not found for User ID: " + userId)))
                .flatMap(profile -> {
                    profile.setFirstName(profileDTO.getFirstName());
                    profile.setLastName(profileDTO.getLastName());
                    profile.setProfilePictureUrl(profileDTO.getProfilePictureUrl());
                    profile.setBio(profileDTO.getBio());
                    profile.setPublic(profileDTO.isPublic());
                    return userProfileRepository.save(profile);
                })
                .map(updatedProfile -> modelMapper.map(updatedProfile, UserProfileDTO.class));
    }

    // ✅ Delete User Profile
    @PreAuthorize("hasAuthority('profile:delete') or #userId == authentication.principal.id")
    public Mono<Void> deleteUserProfile(UUID userId) {
        return userProfileRepository.findByUserId(userId)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException(HttpStatus.NOT_FOUND, "UserProfile not found for User ID: " + userId)))
                .flatMap(profile -> userProfileRepository.delete(profile));
    }

}
