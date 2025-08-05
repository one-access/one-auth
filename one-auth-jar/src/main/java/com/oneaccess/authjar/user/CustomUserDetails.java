package com.oneaccess.authjar.user;

import com.oneaccess.authjar.utils.AppUserUtil;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Getter
@Setter
public class CustomUserDetails implements OAuth2User, UserDetails {

    private String userUniqueId; // refers to UserEntity -> email
    private String password;

    private OneAuthUser oneAuthUser;
    // refers to UserEntity -> Authorities, Usually defines roles (ROLE_USER, ROLE_ADMIN)
    private Collection<? extends GrantedAuthority> authorities;
    // permissions or combination of Scope:Permissions e.g. users:full, users:read, profile:full, profile:edit
    // private Map<String, String> permissions;
    // OAuth2 Provider attributes or custom Attributes
    private Map<String, Object> attributes;
    // =================================================

    public CustomUserDetails(String userUniqueId,
                             String password,
                             OneAuthUser oneAuthUser,
                             Collection<? extends GrantedAuthority> authorities,
                             Map<String, Object> attributes) {
        this.userUniqueId = userUniqueId;
        this.password = password;
        this.oneAuthUser = oneAuthUser;
        this.authorities = authorities;
        this.attributes = attributes;
    }

    public static CustomUserDetails buildFromUserEntity(String userId, String password, OneAuthUser oneAuthUser) {

        Collection<? extends GrantedAuthority> grantedAuthorities = AppUserUtil
                .convertRolesSetToGrantedAuthorityList(oneAuthUser.getRoles());
        return new CustomUserDetails(
                userId,
                password,
                oneAuthUser,
                grantedAuthorities,
                new HashMap<>()
        );
    }


    public static CustomUserDetails buildWithAuthAttributesAndAuthorities(String userId, String password, OneAuthUser oneAuthUser,
                                                                                                         Collection<? extends GrantedAuthority> authorities,
                                                                                                         Map<String, Object> attributes) {

        CustomUserDetails customUserDetails = CustomUserDetails.buildFromUserEntity(userId, password, oneAuthUser);
        customUserDetails.setAuthorities(authorities);
        customUserDetails.setAttributes(attributes);
        return customUserDetails;
    }


    // UserDetails fields
    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.userUniqueId;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        boolean isVerified = this.oneAuthUser.isUserVerified();
        // Always return true if email verification is disabled, otherwise check verification status
        boolean enabled = isVerified || !isEmailVerificationRequired();
        log.debug("User {} isEnabled: {} (verified: {}, verification required: {})", 
                this.userUniqueId, enabled, isVerified, isEmailVerificationRequired());
        return enabled;
    }
    
    private boolean isEmailVerificationRequired() {
        // For now, assume email verification is not required when disabled in config
        // This can be enhanced to check application properties if needed
        return false;
    }

    // Oauth2User fields
    @Override
    public <A> A getAttribute(String name) {
        return OAuth2User.super.getAttribute(name);
    }

    @Override
    public Map<String, Object> getAttributes() {
        return this.attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getName() {
        return String.valueOf(this.getUserUniqueId());
    }
}
