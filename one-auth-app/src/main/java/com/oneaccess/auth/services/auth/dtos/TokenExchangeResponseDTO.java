package com.oneaccess.auth.services.auth.dtos;

import com.oneaccess.authjar.user.OneAuthUser;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * Response DTO for token exchange endpoint.
 * Contains JWT access token and refresh token along with metadata.
 */
@Data
@Builder
public class TokenExchangeResponseDTO {
    
    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private long expiresIn;
    private OneAuthUser authUser;
    private String originalRequestUri;
    private LocalDateTime tokenExpiryDate;
}