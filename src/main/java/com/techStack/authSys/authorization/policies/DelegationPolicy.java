package com.techStack.authSys.authorization.policies;

import com.techStack.authSys.authorization.models.Roles;

/**

 * Determines whether a role
 * may delegate authority
 * to another role.
 */
public interface DelegationPolicy {

    boolean canDelegate(
            Roles delegator,
            Roles targetRole
    );
}

