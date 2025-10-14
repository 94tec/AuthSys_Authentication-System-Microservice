package com.techStack.authSys.security;

import com.techStack.authSys.models.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Map;

@AllArgsConstructor
@Getter
public class CustomUserDetails implements UserDetails {

    private final User user;
    private final List<String> roles;
    private final List<String> permissions;
    //private final boolean forcePasswordChange;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getAuthorities(); // or convert roles to GrantedAuthority
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail(); // or user.getUsername(), depending on your User model
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // or user.isAccountNonExpired()
    }

    @Override
    public boolean isAccountNonLocked() {
        return !user.isAccountLocked(); // if you track this
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled(); // depending on your logic
    }

    public boolean isForcePasswordChange() {
        return user.isForcePasswordChange();
    }

}

