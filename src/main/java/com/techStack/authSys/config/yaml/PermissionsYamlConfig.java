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
 * Bound via Spring Boot's @ConfigurationProperties under the "app" prefix.
 * This avoids clashing with Spring's own root-level properties (server.*, spring.*, etc.)
 *
 * Your permissions.yaml (or application.yaml) must use:
 *
 *   app:
 *     permissions:
 *       portfolio:
 *         category: PORTFOLIO
 *         actions:
 *           - action: view
 *             description: "View portfolio items"
 *     role-permissions:
 *       ADMIN:
 *         - "portfolio:view"
 *         - "portfolio:create"
 *       USER:
 *         - "portfolio:view"
 *
 * @Validated ensures that @NotNull / @Valid constraints are evaluated at startup.
 * A bad YAML will throw a BindException on context load rather than an NPE at runtime.
 */
@Data
@Validated
@Configuration
@ConfigurationProperties(prefix = "application")
public class PermissionsYamlConfig {

    /**
     * Namespace map: namespace key (e.g. "portfolio") → namespace config.
     * Must be present — without permissions the seeder has nothing to write.
     */
    @NotNull(message = "app.permissions must be defined in YAML")
    @Valid
    private Map<String, NamespaceConfig> permissions;

    /**
     * Role → permission list map.
     * Must be present — without this no role has any permissions.
     * Supports wildcards: "*:*", "portfolio:*", or exact strings like "portfolio:view".
     */
    @NotNull(message = "app.role-permissions must be defined in YAML")
    private Map<String, List<String>> rolePermissions;

    // -------------------------------------------------------------------------
    // Inner: NamespaceConfig
    // -------------------------------------------------------------------------

    @Data
    @Validated
    public static class NamespaceConfig {

        /**
         * Logical grouping category for this namespace.
         * e.g. "PORTFOLIO", "USER_MANAGEMENT", "SYSTEM"
         */
        @NotBlank(message = "Each permission namespace must declare a category")
        private String category;

        /**
         * List of actions within this namespace.
         * At least one action must be defined per namespace.
         */
        @NotNull(message = "Each permission namespace must declare at least one action")
        @Valid
        private List<ActionConfig> actions;
    }

    // -------------------------------------------------------------------------
    // Inner: ActionConfig
    // -------------------------------------------------------------------------

    @Data
    @Validated
    public static class ActionConfig {

        /**
         * Action name — the second segment of the permission full name.
         * e.g. "view" in "portfolio:view"
         */
        @NotBlank(message = "Each action must have a non-blank action name")
        private String action;

        /**
         * Human-readable description of what this permission allows.
         * Stored in Firestore and used in admin UIs.
         */
        @NotBlank(message = "Each action must have a description")
        private String description;
    }
}