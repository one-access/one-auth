package com.oneaccess.auth.services.auth.dtos;

import lombok.Builder;
import lombok.Data;

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
    private int expiresIn;
    private Object user; // User information extracted from token
}