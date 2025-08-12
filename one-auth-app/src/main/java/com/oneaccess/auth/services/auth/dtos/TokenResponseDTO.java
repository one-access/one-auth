package com.oneaccess.auth.services.auth.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.oneaccess.authjar.user.OneAuthUser;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * Unified response DTO for token endpoints (/login and /exchange).
 * Maps from either AuthResponseDTO or TokenExchangeResponseDTO to a consistent response format.
 */
@Data
@Builder
public class TokenResponseDTO {
    
    @JsonProperty("token_type")
    private String tokenType;
    
    @JsonProperty("expires_in")
    private long expiresIn;
    
    @JsonProperty("token")
    private String token;
    
    @JsonProperty("refresh_token")
    private String refreshToken;
    
    @JsonProperty("auth_user")
    private OneAuthUser authUser;
    
    @JsonProperty("original_request_uri")
    private String originalRequestUri;

    @JsonProperty("token_expiry_date")
    private LocalDateTime tokenExpiryDate;
    
    /**
     * Create TokenResponseDTO from TokenExchangeResponseDTO
     */
    public static TokenResponseDTO from(TokenExchangeResponseDTO exchangeResponse) {
        return TokenResponseDTO.builder()
                .tokenType(exchangeResponse.getTokenType() != null ? exchangeResponse.getTokenType() : "Bearer")
                .expiresIn(exchangeResponse.getExpiresIn() > 0 ? exchangeResponse.getExpiresIn() : 3600)
                .token(exchangeResponse.getAccessToken())
                .refreshToken(exchangeResponse.getRefreshToken())
                .authUser(exchangeResponse.getAuthUser())
                .originalRequestUri(exchangeResponse.getOriginalRequestUri())
                .tokenExpiryDate(exchangeResponse.getTokenExpiryDate())
                .build();
    }
}