package com.techStack.authSys.controller.user;

import com.techStack.authSys.dto.response.UserProfileDTO;
import com.techStack.authSys.service.user.UserProfileService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * User Profile Controller
 *
 * Handles user profile CRUD operations with granular permission control.
 * Users can manage their own profiles, or admins can manage any profile.
 * Uses Clock for deterministic timestamp tracking.
 *
 * @version 1.0
 * @since 2026-02-14
 */
@Slf4j
@RestController
@RequestMapping("/api/user-profiles")
@RequiredArgsConstructor
@Tag(
        name = "User Profile",
        description = "APIs for managing user profile information including bio, contact details, " +
                "preferences, and additional metadata. Supports both self-management and " +
                "administrative operations with fine-grained permission control."
)
@SecurityRequirement(name = "Bearer Authentication")
public class UserProfileController {

    /* =========================
       Dependencies
       ========================= */

    private final UserProfileService userProfileService;
    private final Clock clock;

    /* =========================
       Profile Operations
       ========================= */

    /**
     * Create user profile
     */
    @PostMapping(value = "/{userId}",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAuthority('profile:create') or #userId == authentication.principal.id")
    @Operation(
            summary = "Create user profile",
            description = """
            Creates a new profile for a user. Users can create their own profile,
            or users with `profile:create` permission can create profiles for others.
            
            **Authorization:**
            - User can create their own profile
            - OR user has `profile:create` permission
            
            **Profile Fields:**
            - Bio (personal description)
            - Phone number
            - Address information
            - Social media links
            - Preferences and settings
            - Profile picture URL
            - Department/organization
            - Additional custom metadata
            
            **Validation:**
            - Phone number must be valid format
            - Email must be valid (if provided)
            - URLs must be valid format
            - Bio max length: 500 characters
            
            **Note:** A user can only have one profile. If profile already exists,
            use the update endpoint instead.
            """,
            tags = {"User Profile"}
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Profile created successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    name = "Success response",
                                    value = """
                        {
                          "success": true,
                          "message": "Profile created successfully",
                          "data": {
                            "userId": "550e8400-e29b-41d4-a716-446655440000",
                            "bio": "Software engineer passionate about building scalable systems",
                            "phoneNumber": "+1234567890",
                            "address": {
                              "street": "123 Main St",
                              "city": "San Francisco",
                              "state": "CA",
                              "zipCode": "94102",
                              "country": "USA"
                            },
                            "socialLinks": {
                              "linkedin": "https://linkedin.com/in/johndoe",
                              "github": "https://github.com/johndoe",
                              "twitter": "https://twitter.com/johndoe"
                            },
                            "profilePictureUrl": "https://example.com/profiles/johndoe.jpg",
                            "department": "Engineering",
                            "preferences": {
                              "emailNotifications": true,
                              "smsNotifications": false,
                              "theme": "dark"
                            },
                            "createdAt": "2026-02-14T10:00:00Z",
                            "updatedAt": "2026-02-14T10:00:00Z"
                          },
                          "timestamp": "2026-02-14T10:00:00Z"
                        }
                        """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Bad Request - Invalid profile data or profile already exists",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "Profile already exists",
                                            value = """
                            {
                              "success": false,
                              "message": "Profile already exists for this user",
                              "errorCode": "PROFILE_EXISTS"
                            }
                            """
                                    ),
                                    @ExampleObject(
                                            name = "Validation error",
                                            value = """
                            {
                              "success": false,
                              "message": "Invalid profile data",
                              "validationErrors": {
                                "phoneNumber": "Invalid phone number format",
                                "bio": "Bio exceeds maximum length of 500 characters"
                              }
                            }
                            """
                                    )
                            }
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Forbidden - User lacks permission to create this profile",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": false,
                          "message": "You do not have permission to create this profile",
                          "errorCode": "FORBIDDEN"
                        }
                        """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404",
                    description = "User not found",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": false,
                          "message": "User not found",
                          "errorCode": "USER_NOT_FOUND"
                        }
                        """
                            )
                    )
            )
    })
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "User profile data",
            required = true,
            content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = UserProfileDTO.class),
                    examples = @ExampleObject(
                            name = "Create profile request",
                            value = """
                    {
                      "bio": "Software engineer passionate about building scalable systems",
                      "phoneNumber": "+1234567890",
                      "address": {
                        "street": "123 Main St",
                        "city": "San Francisco",
                        "state": "CA",
                        "zipCode": "94102",
                        "country": "USA"
                      },
                      "socialLinks": {
                        "linkedin": "https://linkedin.com/in/johndoe",
                        "github": "https://github.com/johndoe"
                      },
                      "profilePictureUrl": "https://example.com/profiles/johndoe.jpg",
                      "department": "Engineering",
                      "preferences": {
                        "emailNotifications": true,
                        "smsNotifications": false,
                        "theme": "dark"
                      }
                    }
                    """
                    )
            )
    )
    public Mono<ResponseEntity<Map<String, Object>>> createUserProfile(
            @Parameter(
                    description = "User ID (UUID format)",
                    required = true,
                    example = "550e8400-e29b-41d4-a716-446655440000"
            )
            @PathVariable UUID userId,
            @RequestBody UserProfileDTO profileDTO) {

        Instant createTime = clock.instant();

        log.info("Create profile request at {} for user: {}", createTime, userId);

        return userProfileService.createUserProfile(userId, profileDTO)
                .map(profile -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ Profile created at {} for user: {}", completionTime, userId);

                    return ResponseEntity.ok(Map.of(
                            "success", true,
                            "message", "Profile created successfully",
                            "data", profile,
                            "timestamp", completionTime.toString()
                    ));
                });
    }

    /**
     * Get user profile by user ID
     */
    @GetMapping(value = "/{userId}", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAuthority('profile:read') or #userId == authentication.principal.id")
    @Operation(
            summary = "Get user profile",
            description = """
            Retrieves a user's profile by their user ID. Users can view their own profile,
            or users with `profile:read` permission can view any profile.
            
            **Authorization:**
            - User can view their own profile
            - OR user has `profile:read` permission
            
            **Returns:**
            Complete profile information including:
            - Personal information (bio, contact details)
            - Address information
            - Social media links
            - Profile picture
            - Preferences and settings
            - Timestamps (created/updated)
            
            **Use Cases:**
            - Display user profile on profile page
            - Show user information in admin panel
            - Populate profile edit forms
            - Display contact information
            """,
            tags = {"User Profile"}
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Profile retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    name = "Success response",
                                    value = """
                        {
                          "success": true,
                          "data": {
                            "userId": "550e8400-e29b-41d4-a716-446655440000",
                            "bio": "Software engineer passionate about building scalable systems",
                            "phoneNumber": "+1234567890",
                            "address": {
                              "street": "123 Main St",
                              "city": "San Francisco",
                              "state": "CA",
                              "zipCode": "94102",
                              "country": "USA"
                            },
                            "socialLinks": {
                              "linkedin": "https://linkedin.com/in/johndoe",
                              "github": "https://github.com/johndoe"
                            },
                            "profilePictureUrl": "https://example.com/profiles/johndoe.jpg",
                            "department": "Engineering",
                            "preferences": {
                              "emailNotifications": true,
                              "smsNotifications": false,
                              "theme": "dark"
                            },
                            "createdAt": "2026-02-14T10:00:00Z",
                            "updatedAt": "2026-02-14T10:30:00Z"
                          },
                          "timestamp": "2026-02-14T11:00:00Z"
                        }
                        """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Forbidden - User lacks permission to view this profile",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": false,
                          "message": "You do not have permission to view this profile",
                          "errorCode": "FORBIDDEN"
                        }
                        """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404",
                    description = "Profile not found",
                    content = @Content(mediaType = "application/json")
            )
    })
    public Mono<ResponseEntity<Map<String, Object>>> getUserProfile(
            @Parameter(
                    description = "User ID (UUID format)",
                    required = true,
                    example = "550e8400-e29b-41d4-a716-446655440000"
            )
            @PathVariable UUID userId) {

        Instant requestTime = clock.instant();

        log.debug("Get profile request at {} for user: {}", requestTime, userId);

        return userProfileService.getUserProfile(userId)
                .map(profile -> ResponseEntity.ok(Map.of(
                        "success", true,
                        "data", profile,
                        "timestamp", requestTime.toString()
                )))
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }

    /**
     * Update user profile
     */
    @PutMapping(value = "/{userId}",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAuthority('profile:update') or #userId == authentication.principal.id")
    @Operation(
            summary = "Update user profile",
            description = """
            Updates an existing user profile. Users can update their own profile,
            or users with `profile:update` permission can update any profile.
            
            **Authorization:**
            - User can update their own profile
            - OR user has `profile:update` permission
            
            **Update Behavior:**
            - Partial updates supported (only send fields to update)
            - Null values will not overwrite existing data
            - Empty strings will clear the field
            - Arrays/objects are replaced entirely (not merged)
            
            **Updateable Fields:**
            - Bio and personal information
            - Contact details (phone, address)
            - Social media links
            - Profile picture URL
            - Department/organization
            - Preferences and settings
            
            **Validation:**
            - Same validation rules as create
            - Cannot update userId or timestamps
            
            **Audit:**
            - All updates are logged
            - Updated timestamp is automatically set
            """,
            tags = {"User Profile"}
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Profile updated successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    name = "Success response",
                                    value = """
                        {
                          "success": true,
                          "message": "Profile updated successfully",
                          "data": {
                            "userId": "550e8400-e29b-41d4-a716-446655440000",
                            "bio": "Updated bio - Senior Software Engineer",
                            "phoneNumber": "+1234567890",
                            "address": {
                              "street": "456 New St",
                              "city": "San Francisco",
                              "state": "CA",
                              "zipCode": "94102",
                              "country": "USA"
                            },
                            "profilePictureUrl": "https://example.com/profiles/johndoe-new.jpg",
                            "department": "Engineering",
                            "preferences": {
                              "emailNotifications": true,
                              "smsNotifications": true,
                              "theme": "light"
                            },
                            "createdAt": "2026-02-14T10:00:00Z",
                            "updatedAt": "2026-02-14T11:30:00Z"
                          },
                          "timestamp": "2026-02-14T11:30:00Z"
                        }
                        """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Bad Request - Invalid profile data",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": false,
                          "message": "Invalid profile data",
                          "validationErrors": {
                            "phoneNumber": "Invalid phone number format"
                          }
                        }
                        """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Forbidden - User lacks permission to update this profile",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": false,
                          "message": "You do not have permission to update this profile",
                          "errorCode": "FORBIDDEN"
                        }
                        """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404",
                    description = "Profile not found",
                    content = @Content(mediaType = "application/json")
            )
    })
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Updated profile data (partial updates supported)",
            required = true,
            content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = UserProfileDTO.class),
                    examples = @ExampleObject(
                            name = "Update profile request",
                            value = """
                    {
                      "bio": "Updated bio - Senior Software Engineer",
                      "address": {
                        "street": "456 New St"
                      },
                      "preferences": {
                        "smsNotifications": true,
                        "theme": "light"
                      }
                    }
                    """
                    )
            )
    )
    public Mono<ResponseEntity<Map<String, Object>>> updateUserProfile(
            @Parameter(
                    description = "User ID (UUID format)",
                    required = true,
                    example = "550e8400-e29b-41d4-a716-446655440000"
            )
            @PathVariable UUID userId,
            @RequestBody UserProfileDTO profileDTO) {

        Instant updateTime = clock.instant();

        log.info("Update profile request at {} for user: {}", updateTime, userId);

        return userProfileService.updateUserProfile(userId, profileDTO)
                .map(profile -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ Profile updated at {} for user: {}", completionTime, userId);

                    return ResponseEntity.ok(Map.of(
                            "success", true,
                            "message", "Profile updated successfully",
                            "data", profile,
                            "timestamp", completionTime.toString()
                    ));
                })
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }

    /**
     * Delete user profile
     */
    @DeleteMapping(value = "/{userId}", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAuthority('profile:delete') or #userId == authentication.principal.id")
    @Operation(
            summary = "Delete user profile",
            description = """
            Deletes a user's profile permanently. Users can delete their own profile,
            or users with `profile:delete` permission can delete any profile.
            
            **Authorization:**
            - User can delete their own profile
            - OR user has `profile:delete` permission
            
            **Warning:** This action is permanent and cannot be undone!
            
            **Behavior:**
            - Profile data is permanently deleted
            - User account remains active (only profile is deleted)
            - User can create a new profile afterward
            - All associated profile data is removed
            
            **Audit:**
            - Deletion is logged for compliance
            - Includes who deleted and when
            - User account audit trail maintained
            
            **Use Cases:**
            - User requests data deletion (GDPR compliance)
            - Admin removes inappropriate profile content
            - User wants to start fresh with new profile
            - Account cleanup during user offboarding
            
            **Note:** Consider using a "deactivate" feature instead of
            permanent deletion for better user experience and data recovery.
            """,
            tags = {"User Profile"}
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Profile deleted successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    name = "Success response",
                                    value = """
                        {
                          "success": true,
                          "message": "Profile deleted successfully",
                          "timestamp": "2026-02-14T12:00:00Z"
                        }
                        """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Forbidden - User lacks permission to delete this profile",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": false,
                          "message": "You do not have permission to delete this profile",
                          "errorCode": "FORBIDDEN"
                        }
                        """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404",
                    description = "Profile not found",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": false,
                          "message": "Profile not found",
                          "errorCode": "PROFILE_NOT_FOUND"
                        }
                        """
                            )
                    )
            )
    })
    public Mono<ResponseEntity<Map<String, Object>>> deleteUserProfile(
            @Parameter(
                    description = "User ID (UUID format)",
                    required = true,
                    example = "550e8400-e29b-41d4-a716-446655440000"
            )
            @PathVariable UUID userId) {

        Instant deleteTime = clock.instant();

        log.warn("Delete profile request at {} for user: {}", deleteTime, userId);

        return userProfileService.deleteUserProfile(userId)
                .then(Mono.fromCallable(() -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ Profile deleted at {} for user: {}", completionTime, userId);

                    return ResponseEntity.ok(Map.of(
                            "success", true,
                            "message", "Profile deleted successfully",
                            "timestamp", completionTime.toString()
                    ));
                }));
    }
}