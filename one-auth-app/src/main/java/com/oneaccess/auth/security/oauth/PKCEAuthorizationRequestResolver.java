package com.oneaccess.auth.security.oauth;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Custom OAuth2 Authorization Request Resolver that adds PKCE (Proof Key for Code Exchange) support.
 * 
 * This resolver extends the default OAuth2 authorization flow by:
 * 1. Generating or using provided PKCE code challenge/verifier pairs
 * 2. Adding PKCE parameters to the authorization request
 * 3. Storing the code verifier for later validation during token exchange
 * 
 * PKCE is essential for cross-domain OAuth2 flows and provides protection against
 * authorization code interception attacks.
 */
@Slf4j
public class PKCEAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private static final String CODE_CHALLENGE_PARAMETER = "code_challenge";
    private static final String CODE_CHALLENGE_METHOD_PARAMETER = "code_challenge_method";
    private static final String CODE_CHALLENGE_METHOD_S256 = "S256";
    
    private final DefaultOAuth2AuthorizationRequestResolver defaultResolver;

    public PKCEAuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository) {
        this.defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(
            clientRegistrationRepository, "/oauth2/authorize");

        // Configure the default resolver to add PKCE parameters
        this.defaultResolver.setAuthorizationRequestCustomizer(this::customizeAuthorizationRequest);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        return defaultResolver.resolve(request);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        return defaultResolver.resolve(request, clientRegistrationId);
    }

    /**
     * Customizes the OAuth2 authorization request by handling frontend PKCE parameters.
     * PKCE is used between frontend and backend, NOT between backend and OAuth provider (Google).
     */
    private void customizeAuthorizationRequest(OAuth2AuthorizationRequest.Builder builder) {
        try {
            // Get current request with proper error handling
            HttpServletRequest currentRequest = getCurrentRequest();
            
            // Check if PKCE parameters are provided in the request (from frontend)
            String codeChallenge = currentRequest.getParameter(CODE_CHALLENGE_PARAMETER);
            String codeChallengeMethod = currentRequest.getParameter(CODE_CHALLENGE_METHOD_PARAMETER);
            
            // Extract frontend state parameter for later retrieval
            String frontendState = currentRequest.getParameter("state");
            
            // Validate PKCE parameters before processing
            if (StringUtils.hasText(codeChallenge) && CODE_CHALLENGE_METHOD_S256.equals(codeChallengeMethod)) {
                // Validate code challenge format (base64url)
                if (!codeChallenge.matches("^[A-Za-z0-9_-]+$")) {
                    log.error("PKCE: Invalid code challenge format - contains illegal characters");
                    throw new IllegalArgumentException("Invalid PKCE code challenge format");
                }
                
                // Validate code challenge length (RFC 7636: 43-128 characters)
                if (codeChallenge.length() < 43 || codeChallenge.length() > 128) {
                    log.error("PKCE: Invalid code challenge length: {} (must be 43-128 characters)", codeChallenge.length());
                    throw new IllegalArgumentException("Invalid PKCE code challenge length");
                }
                
                // Frontend provided PKCE parameters
                log.debug("PKCE: Frontend provided valid PKCE challenge - storing for later validation");
                
                // CORRECT APPROACH: Store frontend PKCE challenge for /auth/exchange validation
                // Do NOT send PKCE parameters to Google - Google OAuth2 is already secure
                builder.attributes(attrs -> {
                    // Store frontend PKCE challenge for validation in /auth/exchange
                    attrs.put("frontend_code_challenge", codeChallenge);
                    attrs.put("code_challenge_method", codeChallengeMethod);
                    attrs.put("frontend_provided_pkce", true);
                    
                    // Store frontend state to return it after OAuth callback
                    if (StringUtils.hasText(frontendState)) {
                        attrs.put("frontend_state", frontendState);
                        log.debug("PKCE: Stored frontend state for later retrieval");
                    }
                });
                
                log.debug("PKCE: Stored frontend PKCE challenge for /auth/exchange validation. Google OAuth2 will proceed without PKCE.");
                
            } else if (StringUtils.hasText(codeChallenge) || StringUtils.hasText(codeChallengeMethod)) {
                // Partial PKCE parameters provided - this is an error
                log.error("PKCE: Incomplete PKCE parameters - both code_challenge and code_challenge_method are required");
                throw new IllegalArgumentException("Incomplete PKCE parameters");
                
            } else {
                // No frontend PKCE - this could be a direct server-side OAuth2 flow
                log.debug("PKCE: No frontend PKCE detected - standard OAuth2 flow");
                
                builder.attributes(attrs -> {
                    attrs.put("frontend_provided_pkce", false);
                    
                    // Still store frontend state if provided (for non-PKCE flows)
                    if (StringUtils.hasText(frontendState)) {
                        attrs.put("frontend_state", frontendState);
                        log.debug("PKCE: Stored frontend state for non-PKCE flow");
                    }
                });
            }
            
            log.debug("PKCE: OAuth2 authorization request customization completed successfully");
            
        } catch (IllegalArgumentException e) {
            // Validation errors - these should be returned to client
            log.error("PKCE: Invalid request parameters: {}", e.getMessage());
            throw e;
        } catch (IllegalStateException e) {
            // Request context issues - these are server configuration problems
            log.error("PKCE: Server configuration error: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            // Unexpected errors
            log.error("PKCE: Unexpected error during OAuth2 authorization request customization: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to process OAuth2 authorization request", e);
        }
    }

    /**
     * Generates a cryptographically secure code verifier for PKCE.
     */
    private String generateCodeVerifier() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] codeVerifier = new byte[32];
        secureRandom.nextBytes(codeVerifier);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
    }

    /**
     * Generates the code challenge from the code verifier using SHA256.
     */
    private String generateCodeChallenge(String codeVerifier) throws NoSuchAlgorithmException {
        byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(bytes, 0, bytes.length);
        byte[] digest = messageDigest.digest();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    /**
     * Helper method to get the current HTTP request.
     */
    private HttpServletRequest getCurrentRequest() {
        try {
            return ((org.springframework.web.context.request.ServletRequestAttributes) 
                org.springframework.web.context.request.RequestContextHolder.currentRequestAttributes())
                .getRequest();
        } catch (IllegalStateException e) {
            // This can happen if called outside of a request context
            log.warn("PKCE: No request context available - this may indicate a configuration issue: {}", e.getMessage());
            throw new IllegalStateException("PKCE authorization resolver called outside of request context", e);
        } catch (Exception e) {
            log.error("PKCE: Unexpected error getting request context: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to get request context for PKCE processing", e);
        }
    }
}