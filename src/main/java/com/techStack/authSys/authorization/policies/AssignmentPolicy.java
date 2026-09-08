package com.techStack.authSys.authorization.policies;


import com.techStack.authSys.authorization.models.Roles;

/**

 * Determines whether an actor
 * may assign a target role.
 */
public interface AssignmentPolicy {

    boolean canAssign(
            Roles actor,
            Roles targetRole
    );
}

