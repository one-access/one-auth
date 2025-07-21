package com.oneaccess.auth.services.webapp.user.dto;

import com.oneaccess.auth.security.oauth.common.SecurityEnums;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class VerifyEmailRequestDTO {

    private String email;

    private String verificationCode;

    @JsonProperty("registeredProviderName")
    private SecurityEnums.AuthProviderId authProviderId;
}
