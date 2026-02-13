package com.techStack.authSys.security.context;

import com.techStack.authSys.models.user.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@AllArgsConstructor
@Getter
public class CustomUserDetails implements UserDetails {

    private final User user;
    private final List<String> roles;
    private final List<String> permissions;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getAuthorities();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !user.isAccountLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }

    /**
     * Check if user needs to change password
     */
    public boolean isForcePasswordChange() {
        return user.isForcePasswordChange();
    }

    /**
     * Check if user has verified their phone
     */
    public boolean isPhoneVerified() {
        return user.isPhoneVerified();
    }

    /**
     * Check if first-time setup is complete
     */
    public boolean isFirstTimeSetupComplete() {
        return !user.isForcePasswordChange() && user.isPhoneVerified();
    }

    /**
     * Get user ID
     */
    public String getUserId() {
        return user.getId();
    }
}