package com.oneaccess.auth.security.oauth;

import com.oneaccess.auth.config.AppProperties;
import com.oneaccess.auth.security.UserJWTKeyProvider;
import com.oneaccess.auth.services.cache.CacheService;
import com.oneaccess.auth.utils.AppWebUtils;
import com.oneaccess.auth.utils.exceptions.BadRequestException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.io.Serializable;
import java.net.URI;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;

import static com.oneaccess.auth.security.oauth.common.OAuth2Util.ORIGINAL_REQUEST_URI_PARAM_COOKIE_NAME;
import static com.oneaccess.auth.security.oauth.common.OAuth2Util.REDIRECT_URI_PARAM_COOKIE_NAME;

/**
 * Cross-Domain OAuth2 Authentication Success Handler with Authorization Code Flow
 * 
 * 1. Flow comes here "onAuthenticationSuccess()", After successful OAuth2 Authentication (see: CustomOAuth2UserService )
 * - Instead of creating JWT directly, we generate a temporary authorization code
 * - We respond back to redirect_uri with the authorization code (e.g. http://myui.com/auth/callback?code=temp_code&state=xyz)
 * - Frontend will exchange this code for JWT tokens via the /auth/exchange endpoint
 * - We validate the redirect_uri for security measures
 * 
 * 2. We use a temporary in-memory storage for authorization codes (5-minute expiration)
 * - This is secure because codes are single-use and short-lived
 * - Real implementation should use Redis or distributed cache
 * 
 * 3. PKCE validation happens during token exchange, not here
 */
@Slf4j
@Service
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Autowired
    private UserJWTKeyProvider userJWTKeyProvider;

    @Autowired
    private HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    @Autowired
    private AppProperties appProperties;
    
    @Autowired
    private CacheService cacheService;

    // Spring Cache replaces in-memory ConcurrentHashMap
    // Configured in CacheConfig.java with 5-minute TTL
    // Supports both in-memory and Redis backends
    private final SecureRandom secureRandom = new SecureRandom();

    // Data class to store authentication and PKCE info - now Serializable for Redis
    public static class AuthCodeData implements Serializable {
        private static final long serialVersionUID = 1L;
        
        public final Authentication authentication;
        public final String codeVerifier;
        public final String codeChallenge;
        public final boolean frontendProvidedPkce;
        public final String frontendOriginalRequestUri;
        private final long creationTime;

        public AuthCodeData(Authentication authentication, String codeVerifier, String codeChallenge, String frontendOriginalRequestUri) {
            this.authentication = authentication;
            this.codeVerifier = codeVerifier;
            this.codeChallenge = codeChallenge;
            this.frontendOriginalRequestUri = frontendOriginalRequestUri;
            // Determine if this is frontend-provided PKCE (a challenge exists but no verifier)
            this.frontendProvidedPkce = codeChallenge != null && codeVerifier == null;
            this.creationTime = System.currentTimeMillis();
        }

        // TTL is now handled by Spring Cache configuration (5 minutes)
        // This method is kept for backward compatibility
        boolean isExpired() {
            return System.currentTimeMillis() - creationTime > Duration.ofMinutes(5).toMillis();
        }
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) {
        Optional<String> redirectUriOpt = AppWebUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);
        String originalRequestUriOpt = AppWebUtils.getCookie(request, ORIGINAL_REQUEST_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue).orElse("/");

        String targetUrl = redirectUriOpt.orElseThrow(() ->
                new BadRequestException("Sorry! No Redirect URI provided! Can't proceed with the authentication."));

        if (!isRedirectOriginAuthorized(targetUrl)) {
            throw new BadRequestException("Sorry! We've got an Unauthorized Redirect URI! Can't proceed with the authentication, redirectUri: " + targetUrl);
        }

        // Generate secure authorization code
        String authorizationCode = generateSecureAuthorizationCode();
        
        // Get frontend PKCE parameters from the authorization request attributes (stored by PKCEAuthorizationRequestResolver)
        String codeChallenge = null;
        boolean frontendProvidedPkce = false;
        
        // Try to get PKCE parameters from cookies (stored by HttpCookieOAuth2AuthorizationRequestRepository)
        Optional<String> storedChallenge = Optional.ofNullable(httpCookieOAuth2AuthorizationRequestRepository.getCodeChallenge(request));
        
        if (storedChallenge.isPresent()) {
            codeChallenge = storedChallenge.get();
            
            // The presence of a challenge indicates frontend-provided PKCE
            frontendProvidedPkce = true;
            
            log.debug("Retrieved frontend PKCE challenge from cookies for /auth/exchange validation");
        } else {
            log.debug("No frontend PKCE challenge found - standard OAuth2 flow");
        }
        
        // Store authentication with authorization code using Spring Cache
        // For frontend PKCE: no verifier (frontend has it), only challenge for validation
        // For standard OAuth2: no PKCE parameters needed
        AuthCodeData authCodeData = new AuthCodeData(authentication, null, codeChallenge, originalRequestUriOpt);
        storeAuthorizationCode(authorizationCode, authCodeData, Duration.ofMinutes(2));
        
        // Note: TTL and cleanup are now handled by Spring Cache configuration

        // Get frontend state from cookies (instead of OAuth provider state)
        String frontendState = httpCookieOAuth2AuthorizationRequestRepository.getFrontendState(request);
        String oauthProviderState = request.getParameter("state");
        
        log.debug("State parameters - Frontend: {}, OAuth Provider: {}", 
                 frontendState != null ? "present" : "absent",
                 oauthProviderState != null ? "present" : "absent");
        
        // Build redirect URL with authorization code and frontend state
        UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("code", authorizationCode);
        
        // Use frontend state for validation (this is what the frontend expects)
        if (frontendState != null) {
            uriBuilder.queryParam("state", frontendState);
            log.debug("Forwarding frontend state to maintain validation: {}", frontendState);
        } else if (oauthProviderState != null) {
            // Fallback: use OAuth provider state if no frontend state available
            uriBuilder.queryParam("state", oauthProviderState);
            log.warn("No frontend state found, using OAuth provider state as fallback: {}", oauthProviderState);
        } else {
            // Last resort: generate state if none provided (should not happen in normal flow)
            String fallbackState = generateState();
            uriBuilder.queryParam("state", fallbackState);
            log.warn("No state found, generated fallback state: {}", fallbackState);
        }

//        // Correctly add the optional originalRequestUri parameter
//        originalRequestUriOpt.ifPresent(originalRequestUri ->
//                uriBuilder.queryParam(ORIGINAL_REQUEST_URI_PARAM_COOKIE_NAME, originalRequestUri));

        return uriBuilder.build().toUriString();
    }

    /**
     * Generates a cryptographically secure authorization code.
     */
    private String generateSecureAuthorizationCode() {
        byte[] codeBytes = new byte[32];
        secureRandom.nextBytes(codeBytes);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(codeBytes);
    }

    /**
     * Generates a state parameter for CSRF protection.
     */
    private String generateState() {
        byte[] stateBytes = new byte[16];
        secureRandom.nextBytes(stateBytes);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(stateBytes);
    }

    /**
     * Retrieves (without consuming) authentication data for the given authorization code.
     * Used for validation before consuming the code.
     * Uses CacheService for distributed storage support with custom TTL.
     */
    public AuthCodeData peekAuthorizationCode(String code) {
        if (code == null) {
            return null;
        }
        
        AuthCodeData authCodeData = cacheService.get(
            "oauth2_auth_codes", 
            code, 
            AuthCodeData.class
        );
        
        if (authCodeData == null) {
            log.debug("Authorization code not found in cache: {}", code);
            return null;
        }
        
        // Additional expiration check (belt and suspenders approach)
        if (authCodeData.isExpired()) {
            log.debug("Authorization code expired, evicting: {}", code);
            cacheService.evict("oauth2_auth_codes", code);
            return null;
        }
        
        return authCodeData;
    }

    /**
     * Retrieves and removes (single-use) authentication data for the given authorization code.
     * Should only be called after successful validation via peekAuthorizationCode.
     * Uses CacheService eviction for secure single-use consumption.
     */
    public AuthCodeData exchangeAuthorizationCode(String code) {
        if (code == null) {
            return null;
        }
        
        // Retrieve the data before evicting it
        AuthCodeData authCodeData = cacheService.get(
            "oauth2_auth_codes", 
            code, 
            AuthCodeData.class
        );
        
        if (authCodeData == null) {
            log.debug("Authorization code not found during exchange: {}", code);
            return null;
        }
        
        if (authCodeData.isExpired()) {
            log.debug("Authorization code expired during exchange: {}", code);
            cacheService.evict("oauth2_auth_codes", code);
            return null;
        }
        
        // Evict the code to ensure single-use (atomic operation)
        cacheService.evict("oauth2_auth_codes", code);
        log.debug("Authorization code consumed and evicted from cache: {}", code);
        
        return authCodeData;
    }
    
    /**
     * Stores authorization code data with custom TTL.
     * Useful for special cases requiring different expiration times.
     */
    public void storeAuthorizationCode(String code, AuthCodeData authCodeData, Duration durationTtl) {
        cacheService.put(
            "oauth2_auth_codes", 
            code, 
            authCodeData,
                durationTtl
        );
        
        log.debug("Authorization code stored in cache with custom TTL {}: {}", durationTtl, code);
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request,
                                                 HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequest(request, response);
    }

    private boolean isRedirectOriginAuthorized(String uri) {
        URI clientRedirectUri = URI.create(uri);

        return Arrays.stream(appProperties.getOAuth2().getAuthorizedRedirectOrigins())
                .anyMatch(authorizedRedirectOrigin -> {
                    URI authorizedURI = URI.create(authorizedRedirectOrigin);
                    if (authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                            && authorizedURI.getPort() == clientRedirectUri.getPort()) {
                        return true;
                    }
                    return false;
                });
    }
}
