package com.techStack.authSys.models.user;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.Iterator;
import java.util.Optional;
import java.util.Spliterator;
import java.util.function.Consumer;

@Getter
public enum Roles implements Iterable<Roles> {  // Specify Roles as the type of iteration

    SUPER_ADMIN("Super Administrator", 4),
    ADMIN("Administrator", 3),
    MANAGER("Manager", 2),
    USER("Standard User", 1);

    private final String description;
    private final int level;

    Roles(String description, int level) {
        this.description = description;
        this.level = level;
    }

    /**
     * Checks if this role has equal or greater privileges than another role.
     */
    public boolean hasAtLeastPrivilegesOf(Roles other) {
        return this.level >= other.level;
    }

    /**
     * Checks if this role has strictly higher privileges than another role.
     */
    public boolean hasHigherPrivilegesThan(Roles other) {
        return this.level > other.level;
    }

    /**
     * Determines if the current role can request an upgrade to the target role.
     * You can add business logic here to block certain paths (e.g., USER -> ADMIN).
     */
    public boolean canRequestUpgradeTo(Roles target) {
        return this.level < target.level;
    }

    /**
     * Attempts to resolve a role from a case-insensitive name.
     */
    public static Optional<Roles> fromName(String name) {
        try {
            return Optional.of(Roles.valueOf(name.toUpperCase()));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /**
     * Gets a role by numeric level.
     */
    public static Optional<Roles> getByLevel(int level) {
        return Arrays.stream(values())
                .filter(role -> role.level == level)
                .findFirst();
    }

    @Override
    public String toString() {
        return name() + " (" + description + ")";
    }

    @NotNull
    @Override
    public Iterator<Roles> iterator() {  // Corrected the iterator to return Roles
        return Arrays.asList(Roles.values()).iterator();  // Create an iterator over the enum values
    }

    @Override
    public void forEach(Consumer<? super Roles> action) {
        Iterable.super.forEach(action);
    }

    @Override
    public Spliterator<Roles> spliterator() {
        return Iterable.super.spliterator();
    }
}
