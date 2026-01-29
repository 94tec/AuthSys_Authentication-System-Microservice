package com.techStack.authSys.models.authorization;

import lombok.Getter;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Getter
public enum Permissions {
    // CRUD
    READ("Read Access", 1),
    WRITE("Write Access", 2),
    DELETE("Delete Access", 3),

    // Stock
    STOCK_CREATE("Create parts, locations, suppliers", 4),
    STOCK_READ("Read all stock information", 5),
    STOCK_UPDATE("Update all stock information", 6),
    STOCK_DELETE("Delete parts, locations, suppliers", 7),
    STOCK_ADJUST("Create stock adjustments", 8),
    STOCK_REPORT("View stock reports and analytics", 9),

    // Sales
    SALES_CREATE("Create sales transactions", 10),
    SALES_READ("Read sales data", 11),
    SALES_UPDATE("Update sales data", 12),
    SALES_DELETE("Delete sales records", 13),
    SALES_REPORT("View sales reports", 14),
    SALES_CONFIG("Manage sales point configurations", 15),

    // User Management
    USER_CREATE("Create user accounts", 16),
    USER_READ("Read user information", 17),
    USER_UPDATE("Update user accounts", 18),
    USER_DELETE("Delete user accounts", 19),
    USER_ROLE_MANAGE("Manage user roles", 20),

    // System
    SYSTEM_SETTINGS("Access system settings", 21),
    SYSTEM_BACKUP("Manage backups and logs", 22),
    SYSTEM_AUDIT("View system audit logs", 23),

    // Special
    SUPER_ADMIN("System-wide Administrative Access", 1000),
    ADMIN("Full Administrative Access", 100),
    MANAGER("Managerial Access with location restrictions", 50);

    private final String description;
    public final int level;

    Permissions(String description, int level) {
        this.description = description;
        this.level = level;
    }
    /**
     * Get the permission name (same as name() but explicit)
     */
    public String getName() {
        return this.name();
    }

    public boolean hasAtLeastPrivilegesOf(Permissions other) {
        return this.level >= other.level;
    }

    public boolean implies(Permissions requiredPermission) {
        return this == ADMIN ||
                (this == MANAGER && requiredPermission.level <= MANAGER.level) ||
                this.level >= requiredPermission.level;
    }

    // Utility to load from strings safely
    public static Optional<Permissions> fromNameSafe(String name) {
        try {
            // Extract pure enum name if input is in "NAME (Description)" format
            String pureName = name.split("\\s+")[0];  // Takes "STOCK_READ" from "STOCK_READ (Desc)"
            return Optional.of(Permissions.valueOf(pureName.toUpperCase()));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    public static List<Permissions> fromNamesSafe(List<String> names) {
        return names.stream()
                .map(name -> fromNameSafe(name).orElseThrow(() -> new IllegalArgumentException("Invalid permission name: " + name)))
                .collect(Collectors.toList());
    }

    // Permission groups
    public static Permissions[] getSuperAdminPermissions() {
        return values(); // all available permissions
    }
    public static Permissions[] getStockPermissions() {
        return new Permissions[]{
                STOCK_CREATE, STOCK_READ, STOCK_UPDATE, STOCK_DELETE,
                STOCK_ADJUST, STOCK_REPORT
        };
    }

    public static Permissions[] getSalesPermissions() {
        return new Permissions[]{
                SALES_CREATE, SALES_READ, SALES_UPDATE,
                SALES_DELETE, SALES_REPORT, SALES_CONFIG
        };
    }

    public static Permissions[] getUserManagementPermissions() {
        return new Permissions[]{
                USER_CREATE, USER_READ, USER_UPDATE,
                USER_DELETE, USER_ROLE_MANAGE
        };
    }

    public static Permissions[] getSystemPermissions() {
        return new Permissions[]{
                SYSTEM_SETTINGS, SYSTEM_BACKUP, SYSTEM_AUDIT
        };
    }

    // Predefined roles
    public static Permissions[] getAdminPermissions() {
        return values();
    }

    public static Permissions[] getManagerPermissions() {
        return new Permissions[]{
                STOCK_READ, STOCK_UPDATE, STOCK_ADJUST, STOCK_REPORT,
                SALES_CREATE, SALES_READ, SALES_UPDATE, SALES_REPORT, SALES_CONFIG,
                USER_CREATE, USER_READ, USER_UPDATE
        };
    }

    public static Permissions[] getUserPermissions() {
        return new Permissions[]{
                STOCK_READ,
                SALES_CREATE, SALES_READ, SALES_REPORT
        };
    }

    @Override
    public String toString() {
        return name() + " (" + description + ")";
    }
}
