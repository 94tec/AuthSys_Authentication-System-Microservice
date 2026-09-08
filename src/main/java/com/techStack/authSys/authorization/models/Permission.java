package com.techStack.authSys.authorization.models;


import lombok.Builder;
import lombok.Value;

/**

 * Represents a single permission.
 *
 * Example:
 *
 * namespace = booking
 * action    = create
 *
 * fullName  = booking:create
 */
@Value
@Builder
public class Permission {

    String namespace;

    String action;

    String description;

    PermissionGroup group;

    public String getFullName() {
        return namespace + ":" + action;
    }
}

