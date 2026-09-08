package com.techStack.authSys.authorization.policy_implementation;

import com.techStack.authSys.authorization.models.Roles;
import com.techStack.authSys.authorization.policies.RoleUpgradePolicy;
import org.springframework.stereotype.Component;

@Component
public class DefaultRoleUpgradePolicy
        implements RoleUpgradePolicy {

    @Override
    public boolean canUpgrade(
            Roles current,
            Roles target
    ) {

        if (current == null || target == null) {
            return false;
        }

        if (current == target) {
            return false;
        }

        if (!target.hasHigherPrivilegesThan(current)) {
            return false;
        }

        return switch (current) {
            case GUEST ->
                    target == Roles.USER;

            case USER ->
                    target == Roles.OPERATOR
                            || target == Roles.MANAGER;

            case OPERATOR ->
                    target == Roles.MANAGER;

            case MANAGER ->
                    target == Roles.ADMIN;

            case ADMIN ->
                    target == Roles.SUPER_ADMIN;

            case SUPER_ADMIN ->
                    false;
        };
    }
}