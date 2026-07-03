package com.techStack.authSys.config.yaml;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

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
 tour:
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
 description: "View tour packages"
 ```
 * ```
 - action: create
 ```
 * ```
 description: "Create tour package"
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
 - "tour:view"
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
@ConfigurationProperties(prefix = "application")
public class PermissionsYamlConfig {

    /**

     * Permission namespaces.
     *
     * Examples:
     * * booking
     * * tour
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
    @NotNull(message = "application.permissions must be defined")
    @Valid
    private Map<String, NamespaceConfig> permissions;

    /**

     * Role → Permission mappings.
     *
     * Example:
     *
     * ADMIN:
     * * "booking:*"
     * * "tour:*"
     *
     * USER:
     * * "booking:create"
     * * "booking:view_own"
     */
    @NotNull(message = "application.role_permissions must be defined")
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
}
