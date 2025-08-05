package com.oneaccess.auth.entities;

import com.oneaccess.auth.entities.common.AbstractGenericPKAuditableEntity;
import com.oneaccess.authjar.user.enums.ProviderEnums;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.oneaccess.authjar.user.OneAuthUser;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users", uniqueConstraints = {
        @UniqueConstraint(columnNames = "email")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserEntity extends AbstractGenericPKAuditableEntity<Long> {

    @Column(name = "full_name", nullable = false)
    private String fullName;

    // TODO @Email Validation
    @Column(name = "email", nullable = false)
    private String email;

    @Column(name = "email_verified")
    private boolean emailVerified;

    @JsonProperty(value = "password", access = JsonProperty.Access.WRITE_ONLY)
    @Column(name = "password")
    private String password;

    @Column(name = "image_url")
    private String imageUrl;

    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(
            name = "users_roles",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id")
    )
    @Column(name = "role")
    protected Set<String> roles = new HashSet<>();

    @Column(name = "phone_number")
    private String phoneNumber;

    @Column(name = "registered_provider_name")
    @Enumerated(EnumType.STRING)
    private ProviderEnums.AuthProviderId registeredProviderName;

    @Column(name = "registered_provider_id")
    private String registeredProviderId;

    // Will be using same verificationCode and verificationCodeExpiresAt for both (email-verification and password reset)
    @Column(name = "verification_code")
    private String verificationCode;

    @Column(name = "verification_code_expires_at")
    private Instant verificationCodeExpiresAt;

    public static OneAuthUser buildOneAuthUser(UserEntity userEntity) {
        return OneAuthUser.builder()
                .id(userEntity.getId())
                .userUniqueId(userEntity.getEmail())
                .fullName(userEntity.getFullName())
                .email(userEntity.getEmail())
                .password(userEntity.getPassword())
                .isUserVerified(userEntity.isEmailVerified())
                .imageUrl(userEntity.getImageUrl())
                .roles(userEntity.getRoles())
                .registeredProviderName(userEntity.getRegisteredProviderName() != null ? 
                    userEntity.getRegisteredProviderName().toString() : ProviderEnums.AuthProviderId.app_custom_authentication.toString())
                .build();
    }

}
