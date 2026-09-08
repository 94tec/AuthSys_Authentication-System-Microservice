package com.techStack.authSys.authorization.policy_implementation;

import com.techStack.authSys.authorization.models.Roles;
import com.techStack.authSys.authorization.policies.AssignmentPolicy;
import org.springframework.stereotype.Component;

/**

 * Default role assignment policy.
 *
 * Determines whether one role
 * can assign another role.
 *
 * Examples:
 *
 * SUPER_ADMIN -> ADMIN
 * ADMIN       -> MANAGER
 * MANAGER     -> OPERATOR
 */
@Component
public class DefaultAssignmentPolicy implements AssignmentPolicy {

    @Override
    public boolean canAssign(
            Roles actor,
            Roles targetRole
    ) {

        if (actor == null || targetRole == null) {
            return false;
        }

        if (!targetRole.isAssignable()) {
            return false;
        }

        if (actor == targetRole) {
            return false;
        }

        return actor.hasHigherPrivilegesThan(targetRole);

    }
}

