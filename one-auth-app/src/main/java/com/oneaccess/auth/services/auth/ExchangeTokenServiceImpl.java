package com.oneaccess.auth.services.auth;

import com.oneaccess.auth.security.UserJWTKeyProvider;
import com.oneaccess.auth.security.oauth.OAuth2AuthenticationSuccessHandler;
import com.oneaccess.auth.services.auth.dtos.TokenExchangeRequestDTO;
import com.oneaccess.auth.services.auth.dtos.TokenExchangeResponseDTO;
import com.oneaccess.auth.utils.exceptions.CustomAppException;
import com.oneaccess.authjar.user.CustomUserDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Base64;

@Slf4j
@Service
public class ExchangeTokenServiceImpl implements ExchangeTokenService {

    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final UserJWTKeyProvider userJWTKeyProvider;

    public ExchangeTokenServiceImpl(OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler,
                                   UserJWTKeyProvider userJWTKeyProvider) {
        this.oAuth2AuthenticationSuccessHandler = oAuth2AuthenticationSuccessHandler;
        this.userJWTKeyProvider = userJWTKeyProvider;
    }

    @Override
    public TokenExchangeResponseDTO exchangeCodeForToken(TokenExchangeRequestDTO request) {
        log.info("Token exchange request for code: {}", 
                request.getCode() != null ? request.getCode().substring(0, Math.min(request.getCode().length(), 10)) + "..." : "null");
        log.debug("Token exchange request - redirectUri: {}, hasCodeVerifier: {}", 
                 request.getRedirectUri(), request.getCodeVerifier() != null);
        // Step 1: Peek at authorization code without consuming it
        OAuth2AuthenticationSuccessHandler.AuthCodeData authCodeData = 
            oAuth2AuthenticationSuccessHandler.peekAuthorizationCode(request.getCode());
        
        if (authCodeData == null) {
            log.warn("Invalid or expired authorization code during peek: {}", request.getCode());
            throw new CustomAppException("Invalid or expired authorization code");
        }
            
        log.debug("Authorization code peek successful - frontendProvidedPkce: {}, hasCodeChallenge: {}", 
                 authCodeData.frontendProvidedPkce, authCodeData.codeChallenge != null);
        
        // Step 2: Validate PKCE code verifier BEFORE consuming the code
        if (authCodeData.frontendProvidedPkce) {
            // For frontend-provided PKCE, validate the frontend's verifier against stored challenge
            if (authCodeData.codeChallenge == null) {
                log.warn("Frontend PKCE expected but no code challenge found for code: {}", request.getCode());
                throw new CustomAppException("PKCE code challenge not found");
            }
            
            if (!validatePKCE(request.getCodeVerifier(), authCodeData.codeChallenge)) {
                log.warn("Frontend PKCE validation failed for code: {} - challenge mismatch", request.getCode());
                throw new CustomAppException("PKCE validation failed");
            }
            log.debug("Frontend PKCE validation successful");
        } else {
            // For server-generated PKCE, validate stored verifier against stored challenge  
            if (authCodeData.codeVerifier == null || authCodeData.codeChallenge == null) {
                log.warn("Server PKCE expected but missing verifier or challenge for code: {}", request.getCode());
                throw new CustomAppException("PKCE parameters missing");
            }
            
            if (!validatePKCE(authCodeData.codeVerifier, authCodeData.codeChallenge)) {
                log.warn("Server PKCE validation failed for code: {} - challenge mismatch", request.getCode());
                throw new CustomAppException("PKCE validation failed");
            }
            log.debug("Server PKCE validation successful");
        }
            
        // Step 3: Validate redirect URI (optional additional security)
        log.debug("Redirect URI validation - provided: {}", request.getRedirectUri());
        
        // Step 4: Only now consume the authorization code after all validations pass
        authCodeData = oAuth2AuthenticationSuccessHandler.exchangeAuthorizationCode(request.getCode());
        String originalRequestUri = authCodeData.frontendOriginalRequestUri;

        if (authCodeData == null) {
            log.error("Authorization code was consumed between peek and exchange - possible race condition for code: {}", request.getCode());
            throw new CustomAppException("Authorization code already consumed");
        }
            
        // Generate JWT tokens
        CustomUserDetails userDetails = (CustomUserDetails) authCodeData.authentication.getPrincipal();
        String accessToken = userJWTKeyProvider.createUserToken(userDetails);
        
        // For now, we'll use the same token as refresh token
        String refreshToken = userJWTKeyProvider.createUserToken(userDetails);
        Duration jwtExpirationDuration = userJWTKeyProvider.getJwtExpirationDuration();

        // Build response
        TokenExchangeResponseDTO response = TokenExchangeResponseDTO.builder()
                .tokenType("Bearer")
                .expiresIn(jwtExpirationDuration.toSeconds())
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .authUser(userDetails.getOneAuthUser())
                .originalRequestUri(originalRequestUri)
                .tokenExpiryDate(LocalDateTime.now().plus(jwtExpirationDuration))
                .build();

        log.info("Token exchange successful for user: {}", userDetails.getUserUniqueId());
        return response;
    }

    /**
     * Validates PKCE code verifier against the stored code challenge.
     */
    private boolean validatePKCE(String codeVerifier, String storedCodeChallenge) {
        if (codeVerifier == null || storedCodeChallenge == null) {
            return false;
        }
        
        try {
            // Generate code challenge from verifier
            byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(bytes, 0, bytes.length);
            byte[] digest = messageDigest.digest();
            String computedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            
            return storedCodeChallenge.equals(computedChallenge);
            
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to validate PKCE", e);
            return false;
        }
    }

}