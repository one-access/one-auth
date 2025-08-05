package com.oneaccess.authjar;

import com.oneaccess.authjar.config.OneAuthProperties;
import com.oneaccess.authjar.service.OneAuthJwtService;
import com.oneaccess.authjar.user.CustomUserDetails;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;

/**
 * Clean, industry-standard JWT authentication filter.
 * 
 * Supports:
 * - User JWT: Authorization: Bearer <user-token>
 * - Service JWT: X-Service-Token: <service-token>  
 * - Merged authorities for @PreAuthorize annotations
 * 
 * Authority patterns:
 * - User: ROLE_{role}, USER_TOKEN, USER_ID_{userId}
 * - Service: SERVICE_TOKEN, SERVICE_APP_{appId}, SERVICE_APP_{appId}_{scope}, SERVICE_TOKEN_{scope}
 */
@Slf4j
public class OneAuthFilter extends OncePerRequestFilter {

    // Constants
    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String HEADER_SERVICE_TOKEN = "X-Service-Token";
    
    private static final String AUTHORITY_USER_TOKEN = "USER_TOKEN";
    private static final String AUTHORITY_ROLE_PREFIX = "ROLE_";
    private static final String AUTHORITY_USER_ID_PREFIX = "USER_ID_";
    
    private static final String AUTHORITY_SERVICE_TOKEN = "SERVICE_TOKEN";
    private static final String AUTHORITY_SERVICE_APP_PREFIX = "SERVICE_APP_";
    private static final String AUTHORITY_ROLE_SERVICE = "ROLE_SERVICE";
    
    private static final String DEFAULT_USER_PRINCIPAL = "user";
    private static final String DEFAULT_SERVICE_PRINCIPAL = "service";
    
    // Dependencies
    private final OneAuthProperties properties;
    private final OneAuthJwtService jwtService;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public OneAuthFilter(OneAuthProperties properties, OneAuthJwtService jwtService) {
        this.properties = properties;
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) 
            throws ServletException, IOException {
        
        String requestPath = request.getRequestURI();
        
        // Skip authentication for an exclusion pattern, and serviceAuth is disabled
        boolean isAppExclusionPattern = isAppExclusionPattern(requestPath);
        boolean serviceAuthEnabled = isServiceAuthEnabled();
        if (isAppExclusionPattern && !serviceAuthEnabled) {
            log.debug("Skipping authentication for path: {} as isAppExclusionPattern: {}, serviceAuthEnabled: {}", requestPath, isAppExclusionPattern, serviceAuthEnabled);
            SecurityContextHolder.createEmptyContext();
            filterChain.doFilter(request, response);
            return;
        }
        
        try {
            // Extract tokens from request headers
            String userToken = extractUserToken(request);
            String serviceToken = extractServiceToken(request);
            
            // Require at least one token for protected APIs
            if (!StringUtils.hasText(userToken) && !StringUtils.hasText(serviceToken)) {
                log.debug("No authentication tokens found for protected API: {}", requestPath);
                sendUnauthorized(response, "Authentication required");
                return;
            }
            
            // Create authentication with merged authorities from both tokens if present
            Authentication authentication = retrieveMergedAuthentication(userToken, serviceToken, request, response);
            
            if (authentication == null) {
                log.debug("Token validation failed for API: {}", requestPath);
                sendUnauthorized(response, "Invalid token");
                return;
            }
            
            // Set authentication in SecurityContext
            SecurityContextHolder.getContext().setAuthentication(authentication);
            
            log.debug("Authentication successful for: {} (principal: {}, authorities: {})", 
                      requestPath, authentication.getName(), authentication.getAuthorities().size());
            
            // Continue with the filter chain
            filterChain.doFilter(request, response);
            
        } catch (Exception e) {
            log.warn("Authentication failed for path: {}", requestPath);
            log.debug("Authentication error details: {}", e.getMessage()); // Debug level only
            sendUnauthorized(response, "Authentication failed");
        } finally {
            try {
                SecurityContextHolder.clearContext();
                request.removeAttribute(HEADER_SERVICE_TOKEN);
            } catch (Exception clearException) {
                log.error("Failed to clear security context: {}", clearException.getMessage());
            }
        }
    }
    
    /**
     * Extract user JWT from Authorization: Bearer header.
     *
     * @param request The HTTP request
     * @return The extracted token or null if not found
     */
    private String extractUserToken(HttpServletRequest request) {
        String authHeader = request.getHeader(HEADER_AUTHORIZATION);
        if (StringUtils.hasText(authHeader) && authHeader.startsWith(BEARER_PREFIX)) {
            return authHeader.substring(BEARER_PREFIX.length());
        }
        return null;
    }
    
    /**
     * Extract service JWT from X-Service-Token header.
     *
     * @param request The HTTP request
     * @return The extracted token or null if not found
     */
    private String extractServiceToken(HttpServletRequest request) {
        return request.getHeader(HEADER_SERVICE_TOKEN);
    }
    
    /**
     * Create Authentication with merged user + service authorities.
     *
     * @param userToken The user JWT token
     * @param serviceToken The service JWT token
     * @param request The HTTP request
     * @return Authentication object or null if validation fails
     */
    private Authentication retrieveMergedAuthentication(String userToken, String serviceToken, HttpServletRequest request, HttpServletResponse response) throws IOException {
        Collection<GrantedAuthority> mergedAuthorities = new HashSet<>();
        String principal = DEFAULT_USER_PRINCIPAL;
        
        // Process user token if present
        CustomUserDetails customUserDetailsToken = null;
        if (StringUtils.hasText(userToken)) {
            customUserDetailsToken = jwtService.getCustomUserDetailsFromUserToken(userToken);
            if (customUserDetailsToken == null) {
                log.debug("Invalid user token");
                sendUnauthorized(response, "Invalid User Token");
                return null; // User token provided but invalid
            } else {
                mergedAuthorities.addAll(customUserDetailsToken.getAuthorities());
                principal = customUserDetailsToken.getName();
                log.debug("User token validated for: {}", principal);
            }
        }
        
        // Process service token if present
        boolean isServiceAuthValid = false;
        List<String> scopes;
        
        if (StringUtils.hasText(serviceToken)) {
            // Validate service token and get app ID and scopes if applicable
            Object[] validationResult = jwtService.validateServiceToken(serviceToken, request.getRequestURI());
            boolean serviceValid = (boolean) validationResult[0];
            boolean signatureValid = (boolean) validationResult[1];
            String appId = (String) validationResult[2];
            isServiceAuthValid = serviceValid && signatureValid;

            if (serviceValid) {
                scopes = (List<String>) validationResult[3];
                
                mergedAuthorities.addAll(extractServiceAuthorities(appId, scopes));
                
                // If no user token, use service app ID as principal
                if (customUserDetailsToken == null) {
                    principal = StringUtils.hasText(appId) ? appId : DEFAULT_SERVICE_PRINCIPAL;
                }
                log.debug("Service token validated for app: {} with scopes: {}", appId, scopes);
            } else if (!serviceValid && signatureValid) {
                log.info("Service authentication failed for appId: {}", appId);
                sendForbidden(response, "Service authentication failed, " +appId+ " is not allowed to make this request.");
                return null;
            } else {
                log.debug("Invalid service token");
                sendUnauthorized(response, "Service Not allowed to make this request.");
                return null; // Service token provided but invalid
            }
        }

        // Must have at least one valid token - userAuth or serviceAuth
        if (customUserDetailsToken == null && !isServiceAuthValid) {
            return null;
        }

        if(customUserDetailsToken != null) {
            customUserDetailsToken.setAuthorities(mergedAuthorities);
            return new UsernamePasswordAuthenticationToken(customUserDetailsToken, null, mergedAuthorities);
        }

        // If Only ServiceToken is present and is valid: Create Simple UserDetails with merged authorities.
        UserDetails userDetails = User.builder()
                .username(principal)
                .password("") // No password for JWT auth
                .authorities(mergedAuthorities)
                .build();
        return new UsernamePasswordAuthenticationToken(userDetails, null, mergedAuthorities);
    }
    
    /**
     * Extract authorities from user JWT claims.
     *
     * @param claims The JWT claims
     * @return Set of granted authorities
     */
    private Set<GrantedAuthority> extractUserAuthorities(Claims claims) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        
        // Add user token indicator
        authorities.add(new SimpleGrantedAuthority(AUTHORITY_USER_TOKEN));
        
        // Add user roles as ROLE_ authorities
        @SuppressWarnings("unchecked")
        List<String> roles = claims.get("roles", List.class);
        if (roles != null) {
            for (String role : roles) {
                authorities.add(new SimpleGrantedAuthority(AUTHORITY_ROLE_PREFIX + role.toUpperCase()));
            }
        }
        
        // Add user ID authority
        String userId = claims.getSubject();
        if (StringUtils.hasText(userId)) {
            authorities.add(new SimpleGrantedAuthority(AUTHORITY_USER_ID_PREFIX + userId.toUpperCase()));
        }
        
        return authorities;
    }
    
    /**
     * Extract authorities from service app ID and scopes.
     *
     * @param appId The service app ID
     * @param scopes The list of scopes granted to the app
     * @return Set of granted authorities
     */
    private Set<GrantedAuthority> extractServiceAuthorities(String appId, List<String> scopes) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        
        // Add service token indicator
        authorities.add(new SimpleGrantedAuthority(AUTHORITY_SERVICE_TOKEN));
        
        if (StringUtils.hasText(appId)) {
            // Add app ID authority
            authorities.add(new SimpleGrantedAuthority(AUTHORITY_SERVICE_APP_PREFIX + appId.toUpperCase()));
            
            // Add scope-specific authorities if available
            if (scopes != null && !scopes.isEmpty()) {
                for (String scope : scopes) {
                    if (StringUtils.hasText(scope)) {
                        // Add app-specific scope authority: SERVICE_APP_{appId}_{scope}
                        authorities.add(new SimpleGrantedAuthority(
                            AUTHORITY_SERVICE_APP_PREFIX + appId.toUpperCase() + "_" + scope.toUpperCase()));
                        
                        // Add general scope authority for wildcard permissions: SERVICE_TOKEN_{scope}
                        authorities.add(new SimpleGrantedAuthority(
                            AUTHORITY_SERVICE_TOKEN + "_" + scope.toUpperCase()));
                    }
                }
            }
        }
        
        // Add service role
        authorities.add(new SimpleGrantedAuthority(AUTHORITY_ROLE_SERVICE));
        
        return authorities;
    }
    
    /**
     * Get principal name from user claims.
     *
     * @param claims The JWT claims
     * @return The principal name
     */
    private String getUserPrincipal(Claims claims) {
        String email = claims.get("email", String.class);
        if (StringUtils.hasText(email)) {
            return email;
        }
        
        String userId = claims.getSubject();
        if (StringUtils.hasText(userId)) {
            return userId;
        }
        
        return DEFAULT_USER_PRINCIPAL;
    }
    
    /**
     * Check if the requested path matches any exclusion API patterns.
     *
     * @param requestPath The request path
     * @return true if the path is in a exclusion API, false otherwise
     */
    private boolean isAppExclusionPattern(String requestPath) {
        List<String> appExclusionPatterns = properties.getApplication().getAppExclusionPatterns();
        if (appExclusionPatterns == null || appExclusionPatterns.isEmpty()) {
            return false;
        }
        
        for (String pattern : appExclusionPatterns) {
            if (pathMatcher.match(pattern, requestPath)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check if service-to-service auth is enabled
     * @return true if enabled, false otherwise
     */
    private boolean isServiceAuthEnabled(){
        return properties.getApplication().getServiceAuth().isServiceAuthEnabled();
    }
    
    /**
     * Send unauthorized response. 401
     *
     * @param response The HTTP response
     * @param message The error message
     * @throws IOException If an I/O error occurs
     */
    private void sendUnauthorized(HttpServletResponse response, String message) throws IOException {
//        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//        response.setContentType("text/plain");
//        response.getWriter().write(message);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
    }

    /**
     * Send forbidden response. 403
     *
     * @param response The HTTP response
     * @param message The error message
     * @throws IOException If an I/O error occurs
     */
    private void sendForbidden(HttpServletResponse response, String message) throws IOException {
//        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
//        response.setContentType("text/plain");
//        response.getWriter().write(message);
        response.sendError(HttpServletResponse.SC_FORBIDDEN, message);
    }
}