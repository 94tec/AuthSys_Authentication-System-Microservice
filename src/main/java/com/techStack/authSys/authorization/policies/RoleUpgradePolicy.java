package com.techStack.authSys.authorization.policies;

import com.techStack.authSys.authorization.models.Roles;

public interface RoleUpgradePolicy {

    boolean canUpgrade(
            Roles current,
            Roles target
    );
}