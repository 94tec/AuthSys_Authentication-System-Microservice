package com.techStack.authSys.authorization.policy_implementation;

import com.techStack.authSys.authorization.models.Roles;
import com.techStack.authSys.authorization.policies.DelegationPolicy;
import org.springframework.stereotype.Component;

/**

 * Default authority delegation policy.
 *
 * Delegation is temporary authority
 * granted to another role without
 * permanently changing assignments.
 *
 * Examples:
 *
 * ADMIN   -> MANAGER
 * MANAGER -> OPERATOR
 *
 * Not allowed:
 *
 * USER -> MANAGER
 * ADMIN -> ADMIN
 * ADMIN -> SUPER_ADMIN
 */
@Component
public class DefaultDelegationPolicy implements DelegationPolicy {

    @Override
    public boolean canDelegate(
            Roles delegator,
            Roles targetRole
    ) {
        if (delegator == null || targetRole == null) {
            return false;
        }

        if (delegator == targetRole) {
            return false;
        }

        if (targetRole == Roles.SUPER_ADMIN) {
            return false;
        }

        return delegator.hasHigherPrivilegesThan(targetRole);
    }
}

