package com.oneaccess.authjar.user;

import com.oneaccess.authjar.user.enums.ProviderEnums;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OneAuthUser {

    private Long id;

    private String fullName;

    private String displayName;

    private String userUniqueId;  // corresponds to the email

    private String email;
    
    private String password;

    private boolean isUserVerified;  // corresponds to if emailVerified

    private String imageUrl;

    private Set<String> roles;

    private String registeredProviderName;

    private boolean isPasswordBased;

    public String getDisplayName() {
        return fullName;
    }

    public boolean isPasswordBased() {
        return ProviderEnums.AuthProviderId.app_custom_authentication.name()
                .equals(registeredProviderName);
    }
}
