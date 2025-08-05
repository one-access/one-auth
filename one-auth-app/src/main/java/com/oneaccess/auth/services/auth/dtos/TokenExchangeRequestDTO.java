package com.oneaccess.auth.services.auth.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import jakarta.validation.constraints.NotBlank;

/**
 * Request DTO for exchanging authorization code for JWT tokens.
 * Used in the PKCE OAuth2 flow for cross-domain authentication.
 */
@Data
public class TokenExchangeRequestDTO {
    
    @NotBlank(message = "Authorization code is required")
    private String code;
    
    @NotBlank(message = "Code verifier is required for PKCE validation")
    @JsonProperty("code_verifier")
    private String codeVerifier;
    
    @NotBlank(message = "Redirect URI is required for validation")
    @JsonProperty("redirect_uri")
    private String redirectUri;
    
    private String state;
}