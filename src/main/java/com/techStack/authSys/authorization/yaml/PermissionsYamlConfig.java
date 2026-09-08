package com.techStack.authSys.authorization.yaml;

import com.techStack.authSys.config.cache.CacheConfig;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**

 * Typed representation of permissions.yaml.
 *
 * Loads Tour Management System permissions and role mappings.
 *
 * Example:
 *
 * application:
 * permissions:
 * ```
 booking:
 ```
 * ```
 category: BOOKINGS
 ```
 * ```
 actions:
 ```
 * ```
 - action: create
 ```
 * ```
 description: "Create booking"
 ```
 * ```
 - action: approve
 ```
 * ```
 description: "Approve booking"
 ```
 *
 * ```
 enquire-button.tsx:
 ```
 * ```
 category: TOURS
 ```
 * ```
 actions:
 ```
 * ```
 - action: view
 ```
 * ```
 description: "View enquire-button.tsx packages"
 ```
 * ```
 - action: create
 ```
 * ```
 description: "Create enquire-button.tsx package"
 ```
 *
 * role_permissions:
 * ```
 MANAGER:
 ```
 * ```
 - "booking:*"
 ```
 * ```
 - "enquire-button.tsx:view"
 ```
 *
 * ```
 USER:
 ```
 * ```
 - "booking:create"
 ```
 * ```
 - "booking:view_own"
 ```
 *
 * Supported permission formats:
 *
 * *:*                     -> Full system access
 * booking:*               -> All booking permissions
 * booking:create          -> Single permission
 * booking:view_own        -> Scoped permission
 *
 * Validation is performed at application startup.
 * Invalid YAML causes application startup failure,
 * preventing inconsistent permission data from being seeded.
 */
@Data
@Validated
@Configuration
@ConfigurationProperties(prefix = "authorization")
public class PermissionsYamlConfig {
    private int version = 1;

    private boolean validateOnStartup = true;

    private boolean seedOnStartup = true;

    @Valid
    private CacheConfig cache = new CacheConfig();


    /**

     * Permission namespaces.
     *
     * Examples:
     * * booking
     * * enquire-button.tsx
     * * destination
     * * itinerary
     * * traveler
     * * guide
     * * vehicle
     * * supplier
     * * payment
     * * review
     * * report
     * * user
     * * system
     */
    @NotNull(message = "authorization.permissions must be defined")
    @Valid
    private Map<String, NamespaceConfig> permissions;

    /**

     * Role → Permission mappings.
     *
     * Example:
     *
     * ADMIN:
     * * "booking:*"
     * * "enquire-button.tsx:*"
     *
     * USER:
     * * "booking:create"
     * * "booking:view_own"
     */
    @NotNull(message = "authorization.role_permissions must be defined")
    private Map<String, List<String>> rolePermissions;

    // ---------------------------------------------------------------------
    // Namespace Configuration
    // ---------------------------------------------------------------------

    @Data
    @Validated
    public static class NamespaceConfig {

        /**
         * Business category for grouping permissions.
         *
         * Examples:
         *  BOOKINGS
         *  TOURS
         *  DESTINATIONS
         *  OPERATIONS
         *  CUSTOMER
         *  FINANCE
         *  ANALYTICS
         *  ADMINISTRATION
         *  SYSTEM
         */
        @NotBlank(message = "Permission namespace category is required")
        private String category;

        /**
         * Actions available within the namespace.
         *
         * Example:
         *
         * booking:
         *   actions:
         *     - create
         *     - approve
         *     - cancel
         */
        @NotNull(message = "Permission namespace must define actions")
        @Valid
        private List<ActionConfig> actions;

    }

    // ---------------------------------------------------------------------
    // Action Configuration
    // ---------------------------------------------------------------------

    @Data
    @Validated
    public static class ActionConfig {

        /**
         * Action identifier.
         *
         * Examples:
         *  view
         *  create
         *  update
         *  delete
         *  approve
         *  cancel
         *  assign_guide
         *  assign_vehicle
         *  refund
         */
        @NotBlank(message = "Action name is required")
        private String action;

        /**
         * Human-readable description.
         *
         * Used for:
         *  - Admin UI
         *  - Permission management screens
         *  - Audit displays
         *  - Role management
         *  - Permission seeding
         */
        @NotBlank(message = "Action description is required")
        private String description;

    }
    @Data
    public static class CacheConfig {

        private boolean enabled = true;

        private boolean warmOnStartup = true;

        private Duration ttl = Duration.ofHours(24);
    }

}
