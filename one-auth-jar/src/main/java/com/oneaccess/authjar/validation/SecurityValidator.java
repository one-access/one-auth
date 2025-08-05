package com.oneaccess.authjar.validation;

import com.oneaccess.authjar.user.CustomUserDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.security.PrivateKey;
import java.time.Duration;

/**
 * Minimal security validation utility.
 * Most validation should use Bean Validation (@Valid, @NotNull, etc.)
 */
@Slf4j
public class SecurityValidator {

    // Minimal security constraints for JWT-specific operations
    private static final long MIN_TOKEN_VALIDITY_MS = Duration.ofMinutes(1).toMillis();
    private static final long MAX_TOKEN_VALIDITY_MS = Duration.ofDays(30).toMillis();

    /**
     * Minimal validation for JWT token creation - only what Bean Validation can't handle.
     * Use @Valid, @NotNull, @NotBlank etc. for standard validation.
     */
    public static void validateTokenCreationParameters(CustomUserDetails customUserDetails, 
                                                     PrivateKey privateKey, 
                                                     long validityInMilliseconds, 
                                                     String kid) {
        // Basic null checks
        if (customUserDetails == null) {
            throw new IllegalArgumentException("User details cannot be null");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }
        if (!StringUtils.hasText(kid)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        
        // JWT-specific validation that Bean Validation can't handle
        validateTokenValidity(validityInMilliseconds);
        validateRSAKey(privateKey);
    }

    /**
     * Validate JWT token format - basic structure check.
     */
    public static void validateJwtTokenFormat(String token) {
        if (!StringUtils.hasText(token)) {
            throw new IllegalArgumentException("JWT token cannot be null or empty");
        }

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT token format (must have 3 parts separated by dots)");
        }
    }

    /**
     * Validate token validity period.
     */
    private static void validateTokenValidity(long validityInMilliseconds) {
        if (validityInMilliseconds < MIN_TOKEN_VALIDITY_MS) {
            throw new IllegalArgumentException("Token validity too short (minimum: 1 minute)");
        }
        if (validityInMilliseconds > MAX_TOKEN_VALIDITY_MS) {
            throw new IllegalArgumentException("Token validity too long (maximum: 30 days)");
        }
    }

    /**
     * Validate RSA key algorithm.
     */
    private static void validateRSAKey(PrivateKey privateKey) {
        if (!"RSA".equals(privateKey.getAlgorithm())) {
            throw new IllegalArgumentException("Only RSA private keys are supported");
        }
    }
}