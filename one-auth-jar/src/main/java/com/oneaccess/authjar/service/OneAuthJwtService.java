package com.oneaccess.authjar.service;

import com.oneaccess.authjar.config.OneAuthProperties;
import com.oneaccess.authjar.user.CustomUserDetails;
import com.oneaccess.authjar.user.OneAuthUser;
import com.oneaccess.authjar.utils.AppUserUtil;
import com.oneaccess.authjar.utils.AuthCommonUtil;
import com.oneaccess.authjar.utils.SecurityUtil;
import com.oneaccess.authjar.validation.SecurityValidator;
import io.jsonwebtoken.*;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

/**
 * Main JWT service that handles all JWT operations.
 * Provides a clean interface for both user and service JWT operations.
 */
@Service
public class OneAuthJwtService {
    // Constants
    private static final Logger logger = LoggerFactory.getLogger(OneAuthJwtService.class);
    
    private static final String HEADER_AUTHORIZATION = HttpHeaders.AUTHORIZATION;
    private static final String BEARER_TOKEN_START = "Bearer ";
    
    private static final String CLAIM_EMAIL = "email";
    private static final String CLAIM_USER = "user";
    private static final String CLAIM_AUTHORITIES = "authorities";
    private static final String CLAIM_ATTRIBUTES = "attributes";
    private static final String CLAIM_TOKEN_TYPE = "token_type";
    
    private static final String TOKEN_TYPE_USER = "user";
    private static final String TOKEN_TYPE_SERVICE = "service";
    
    private static final String JWT_HEADER_KID = "kid";
    
    private static final String WILDCARD_APP_ID = "*";
    
    // Cache expiry offset (50 minutes for 1-hour tokens)
    private static final long TOKEN_CACHE_EXPIRY_OFFSET_MS = 50 * 60 * 1000;
    
    // Dependencies
    private final OneAuthProperties properties;
    private final JwksManager jwksManager;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    
    // Cache for service tokens
    private String cachedServiceToken;
    private long serviceTokenExpiryTime;
    
    /**
     * Constructor with required dependencies.
     *
     * @param properties The OneAuth properties
     * @param jwksManager The JWKs manager
     */
    public OneAuthJwtService(OneAuthProperties properties, JwksManager jwksManager) {
        this.properties = properties;
        this.jwksManager = jwksManager;
    }
    
    /**
     * Create a JWT token with a specific kid for key rotation.
     *
     * @param customUserDetails User details
     * @param privateKey Private key for signing
     * @param validityInMilliseconds Token validity in milliseconds
     * @param kid Key ID (required)
     * @return JWT token
     * @throws IllegalArgumentException if any parameter is invalid
     */
    public String createUserJWTToken(CustomUserDetails customUserDetails, PrivateKey privateKey,
                                     long validityInMilliseconds, String kid) {
        // SECURITY FIX: Comprehensive input validation
        try {
            SecurityValidator.validateTokenCreationParameters(customUserDetails, privateKey, validityInMilliseconds, kid);
        } catch (IllegalArgumentException e) {
            logger.error("Invalid parameters for JWT token creation: {}", e.getMessage());
            throw e;
        }
        Set<String> authoritiesSet = AppUserUtil.convertGrantedAuthorityListToRolesSet(customUserDetails.getAuthorities());

        String authoritiesJsonValue = AuthCommonUtil.toJson(authoritiesSet);
        String attributesJsonValue = AuthCommonUtil.toJson(customUserDetails.getAttributes());
        String oneAuthUserJsonValue = AuthCommonUtil.toJson(customUserDetails.getOneAuthUser());

        // Creating claims data
        Claims claims = Jwts.claims().setSubject(customUserDetails.getUserUniqueId());
        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put(CLAIM_EMAIL, customUserDetails.getUserUniqueId());
        claimsMap.put(CLAIM_USER, oneAuthUserJsonValue);
        claimsMap.put(CLAIM_AUTHORITIES, authoritiesJsonValue);
        claimsMap.put(CLAIM_ATTRIBUTES, attributesJsonValue);
        claimsMap.put(CLAIM_TOKEN_TYPE, TOKEN_TYPE_USER);
        claims.putAll(claimsMap);

        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        JwtBuilder jwtBuilder = Jwts.builder()
                .setSubject(customUserDetails.getUserUniqueId())
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.RS256, privateKey);
                
        // Add kid to header if provided
        if (kid != null && !kid.isEmpty()) {
            jwtBuilder.setHeaderParam(JWT_HEADER_KID, kid);
        }
        
        return jwtBuilder.compact();
    }
    
    /**
     * Extract the token from the Authorization header.
     *
     * @param req The HTTP request
     * @return The token or null if not found
     */
    public String getTokenFromRequestHeader(HttpServletRequest req) {
        String bearerToken = req.getHeader(HEADER_AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_TOKEN_START)) {
            return bearerToken.substring(7);
        }
        return null;
    }

    /**
     * Extract the kid from a JWT token without verifying the signature.
     *
     * @param token JWT token
     * @return kid or null if not present
     */
    private String extractKidFromToken(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return null;
            }
            
            // Decode the header
            String headerJson = new String(Base64.getDecoder().decode(parts[0]));
            Map<String, Object> header = AuthCommonUtil.fromJson(headerJson, Map.class);
            
            return (String) header.get(JWT_HEADER_KID);
        } catch (Exception e) {
            logger.warn("Failed to extract kid from token: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * Extract the issuer from a JWT token without verifying the signature.
     *
     * @param token JWT token
     * @return issuer or null if not present
     */
    private String extractIssuerFromToken(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return null;
            }
            
            // Decode the payload
            String payloadJson = new String(Base64.getDecoder().decode(parts[1]));
            Map<String, Object> payload = AuthCommonUtil.fromJson(payloadJson, Map.class);
            
            return (String) payload.get("iss");
        } catch (Exception e) {
            logger.warn("Failed to extract issuer from token: {}", e.getMessage());
            return null;
        }
    }
    
    public CustomUserDetails getCustomUserDetailsFromUserToken(String token) {
        SecurityValidator.validateJwtTokenFormat(token);
        // Extract kid from token
        String kid = extractKidFromToken(token);
        
        // Get the appropriate public key based on kid
        PublicKey keyToUse = jwksManager.getUserPublicKey(kid);
            
        Claims body = Jwts.parserBuilder()
                .setSigningKey(keyToUse)
                .build()
                .parseClaimsJws(token)
                .getBody();

        // Parsing Claims Data
        String email = (String) body.get(CLAIM_EMAIL);
        OneAuthUser oneAuthUser = AuthCommonUtil.fromJson(body.get(CLAIM_USER).toString(), OneAuthUser.class);
        Set<String> authoritiesSet = AuthCommonUtil.fromJson(body.get(CLAIM_AUTHORITIES).toString(), 
                                                           (Class<Set<String>>) ((Class) Set.class));
        Collection<? extends GrantedAuthority> grantedAuthorities = 
                AppUserUtil.convertRolesSetToGrantedAuthorityList(authoritiesSet);
        Map<String, Object> attributes = AuthCommonUtil.fromJson(body.get(CLAIM_ATTRIBUTES).toString(), 
                                                               (Class<Map<String, Object>>) (Class) Map.class);

        // Setting Principle Object
        CustomUserDetails customUserDetails = CustomUserDetails.buildWithAuthAttributesAndAuthorities(
                email, null, oneAuthUser, grantedAuthorities, attributes);
        customUserDetails.setAttributes(attributes);
        return customUserDetails;
    }
    
    /**
     * Validate a user token.
     *
     * @param token The JWT token
     * @return true if valid, false otherwise
     * @throws IllegalArgumentException if token format is invalid
     */
    public boolean validateUserToken(String token) {
        // SECURITY FIX: Validate token format first
        SecurityValidator.validateJwtTokenFormat(token);
        
        try {
            // First, parse the token without verification to extract the kid
            String kid = extractKidFromToken(token);
            
            // Get the appropriate public key based on kid
            PublicKey keyToUse = jwksManager.getUserPublicKey(kid);
                
            // Now parse with verification
            Jws<Claims> claims = Jwts.parserBuilder()
                .setSigningKey(keyToUse)
                .build()
                .parseClaimsJws(token);
                
            if (claims.getBody().getExpiration().before(new Date())) {
                throw new ExpiredJwtException(null, claims.getBody(), "JWT token has expired");
            }
            return true;
        } catch (ExpiredJwtException e) {
            throw e;
        } catch (JwtException | IllegalArgumentException e) {
            logger.info("Invalid JWT token: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Create a service JWT token using the configured service identity.
     *
     * @return JWT token string or null if service identity is not configured
     * @throws IllegalArgumentException if service configuration is invalid
     */
    public String createServiceToken() {
        OneAuthProperties.Application.KeyPair keyPair = properties.getApplication().getKeyPair();
        String appId = properties.getApplication().getAppId();
        String appName = properties.getApplication().getAppName();

        // Basic configuration check
        if (appId == null || appId.isEmpty() ||
            keyPair.getCurrentKid().isEmpty() || keyPair.getPrivateKeyB64().isEmpty()) {
            logger.error("Service identity not properly configured");
            return null;
        }
        
        try {
            String kid = keyPair.getCurrentKid();
            
            // Load private key using SecurityUtil
            PrivateKey privateKey = SecurityUtil.loadPrivateKey(keyPair.getPrivateKeyB64());
            
            // Create JWT Claims
            JwtClaims claims = new JwtClaims();
            claims.setSubject(appName);
            claims.setIssuer(appId);
            claims.setIssuedAt(NumericDate.fromSeconds(System.currentTimeMillis() / 1000L));
            claims.setExpirationTimeMinutesInTheFuture(
                properties.getApplication().getServiceAuth().getServiceJwtTokenValidity().toMinutes());
            claims.setClaim(CLAIM_TOKEN_TYPE, TOKEN_TYPE_SERVICE);
            
            // Create JWS
            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(claims.toJson());
            jws.setKey(privateKey);
            jws.setKeyIdHeaderValue(kid);
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
            
            // Sign and return the token
            return jws.getCompactSerialization();
        } catch (Exception e) {
            logger.error("Failed to create service token: {}", e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Gets a service JWT token for service-to-service authentication.
     * Creates a new token if one doesn't exist or if the cached token is expired.
     *
     * @return The JWT token, or null if the service identity is not configured
     */
    public String getOrCreateServiceToken() {
        // Check if we have a cached token that's still valid
        if (cachedServiceToken != null && System.currentTimeMillis() < serviceTokenExpiryTime) {
            return cachedServiceToken;
        }
        
        // Create a new token
        try {
            OneAuthProperties.Application.KeyPair keyPair = properties.getApplication().getKeyPair();
            String appId = properties.getApplication().getAppId();
            
            if (appId == null || appId.isEmpty() ||
                keyPair.getCurrentKid().isEmpty() || keyPair.getPrivateKeyB64().isEmpty()) {
                logger.warn("App identity is not configured. Cannot create service token.");
                return null;
            }
            
            String token = createServiceToken();
            if (token != null) {
                cachedServiceToken = token;
                // Set expiry time to 50 minutes (tokens are valid for 1 hour)
                serviceTokenExpiryTime = System.currentTimeMillis() + TOKEN_CACHE_EXPIRY_OFFSET_MS;
            }
            return token;
        } catch (Exception e) {
            logger.error("Failed to create service token: {}", e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Invalidates the cached service token, forcing a new token to be created on the next request.
     */
    public void invalidateServiceToken() {
        cachedServiceToken = null;
    }
    
    /**
     * Extract app ID from a JWT token.
     *
     * @param token The JWT token
     * @return The app ID or null if extraction fails
     */
    public String extractAppIdFromToken(String token) {
        if (jwksManager.getKeyResolver() == null) {
            logger.warn("No JWKs available for token validation");
            return null;
        }
        
        try {
            // Create a non-validating JWT consumer that only checks the signature
            JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setSkipDefaultAudienceValidation()
                .setVerificationKeyResolver(jwksManager.getKeyResolver())
                .setJwsAlgorithmConstraints(
                    new AlgorithmConstraints(ConstraintType.PERMIT,
                                           AlgorithmIdentifiers.RSA_USING_SHA256))
                .build();
            
            // Process the token
            JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
            
            // Return the issuer as the app ID
            return jwtClaims.getIssuer();
        } catch (Exception e) {
            logger.error("Error extracting app ID from token: {}", e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Check if an API path matches any exclusion patterns (public/unprotected APIs).
     * 
     * @param apiPath The API path to check
     * @return true if the API should be excluded from authentication, false otherwise
     */
    private boolean isApiServiceExclusion(String apiPath) {
        List<String> serviceExclusionPatterns =
                properties.getApplication().getServiceAuth().getServiceExclusionPatterns();
        
        if (serviceExclusionPatterns == null || serviceExclusionPatterns.isEmpty()) {
            return false;
        }
        
        for (String exclusionPattern : serviceExclusionPatterns) {
            if (pathMatcher.match(exclusionPattern, apiPath)) {
                logger.debug("API {} matches exclusion pattern: {}", apiPath, exclusionPattern);
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if an app ID is allowed to access an API path.
     * SECURE BY DEFAULT: When service auth is enabled, all APIs are protected unless explicitly excluded.
     * Returns a list of allowed scopes if applicable.
     *
     * @param appId The app ID
     * @param apiPath The API path
     * @return Object array with [isAllowed (boolean), allowedScopes (List<String> or null)]
     */
    private Object[] isServiceAllowed(String appId, String apiPath) {
        // Step 1: Check exclusion patterns first - these APIs are public/unprotected
        if (isApiServiceExclusion(apiPath)) {
            logger.debug("API {} is excluded from authentication (public API)", apiPath);
            return new Object[] { true, null };
        }
        
        // Step 2: Check inclusion patterns - these APIs require specific app permissions
        List<OneAuthProperties.Application.ApiPattern> apiPatterns = properties.getApplication().getServiceAuth().getApiPatterns();
        if (apiPatterns != null && !apiPatterns.isEmpty()) {
            for (OneAuthProperties.Application.ApiPattern pattern : apiPatterns) {
                if (pathMatcher.match(pattern.getPattern(), apiPath)) {
                    // Check app permissions for this pattern
                    if (pattern.getAppPermissions() != null && !pattern.getAppPermissions().isEmpty()) {
                        // First check for specific app permissions
                        List<String> allowedScopes = pattern.getAppPermissions().get(appId);
                        if (allowedScopes != null && !allowedScopes.isEmpty()) {
                            logger.debug("App {} is allowed to access {} with scopes: {}",
                                    appId, apiPath, allowedScopes);
                            return new Object[] { true, allowedScopes };
                        }
                        
                        // If no specific app permissions, check for wildcard entry
                        List<String> wildcardScopes = pattern.getAppPermissions().get(WILDCARD_APP_ID);
                        if (wildcardScopes != null && !wildcardScopes.isEmpty()) {
                            logger.debug("App {} is allowed to access {} via wildcard with scopes: {}",
                                    appId, apiPath, wildcardScopes);
                            return new Object[] { true, wildcardScopes };
                        }
                    }
                    
                    logger.debug("App {} is not allowed to access {} (matched pattern: {} but no permissions)",
                            appId, apiPath, pattern.getPattern());
                    return new Object[] { false, null };
                }
            }
        }
        
        // Step 3: SECURE BY DEFAULT - If no exclusion and no inclusion pattern matches, DENY ACCESS
        logger.debug("API {} is protected by default - no exclusion or inclusion pattern matched (secure by default)", apiPath);
        return new Object[] { false, null };
    }
    
    /**
     * Validate a user token and return claims.
     *
     * @param token The JWT token
     * @return Claims if valid, null otherwise
     */
    public Claims validateUserTokenAndGetClaims(String token) {
        try {
            // First, parse the token without verification to extract the kid
            String kid = extractKidFromToken(token);
            
            // Get the appropriate public key based on kid
            PublicKey keyToUse = jwksManager.getUserPublicKey(kid);
                
            // Now parse with verification
            Jws<Claims> claims = Jwts.parserBuilder()
                .setSigningKey(keyToUse)
                .build()
                .parseClaimsJws(token);
                
            if (claims.getBody().getExpiration().before(new Date())) {
                throw new ExpiredJwtException(null, claims.getBody(), "JWT token has expired");
            }
            return claims.getBody();
        } catch (ExpiredJwtException e) {
            logger.warn("JWT token has expired: {}", e.getMessage());
            return null;
        } catch (JwtException | IllegalArgumentException e) {
            logger.warn("Invalid JWT token: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * Validate service token for API access.
     * Enhanced version that returns app ID and allowed scopes.
     * Now uses issuer+kid lookup instead of full key resolver.
     *
     * @param token The JWT token
     * @param requestPath The API path being accessed
     * @return Object array with [isValid (boolean), signatureVerified (boolean) appId (String), allowedScopes (List<String> or null)]
     * @throws IllegalArgumentException if token format or API path is invalid
     */
    public Object[] validateServiceToken(String token, String requestPath) {
        // Basic input validation
        if (!StringUtils.hasText(token) || !StringUtils.hasText(requestPath)) {
            logger.warn("Invalid service token validation parameters");
            return new Object[] { false, false, null, null };
        }
        // If service auth is not enabled, allow access without validation
        if (!jwksManager.isServiceAuthEnabled()) {
            return new Object[] { true, null, null };
        }
        
        try {
            // First extract kid and issuer from token without verification
            String kid = extractKidFromToken(token);
            if (!StringUtils.hasText(kid)) {
                logger.warn("Service token missing kid header");
                return new Object[] { false, false, null, null };
            }
            
            // Extract issuer (appId) from token payload without verification
            String appId = extractIssuerFromToken(token);
            if (!StringUtils.hasText(appId)) {
                logger.warn("Service token missing issuer");
                return new Object[] { false, false, null, null };
            }
            
            // Get public key using issuer+kid lookup
            PublicKey publicKey = jwksManager.getServicePublicKeyByIssuerAndKid(appId, kid);
            if (publicKey == null) {
                logger.warn("No public key found for appId: {}, kid: {}", appId, kid);
                return new Object[] { false, false, null, null };
            }
            
            // Create JWT consumer with specific public key
            JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(30)
                .setVerificationKey(publicKey)
                .build();
            
            // Process and validate the token
            JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
            
            // Extract claims
            String tokenIssuer = jwtClaims.getIssuer();
            String tokenType = jwtClaims.getClaimValue(CLAIM_TOKEN_TYPE, String.class);
            
            // Verify token type is "service"
            if (!TOKEN_TYPE_SERVICE.equals(tokenType)) {
                logger.warn("Token is not a service token");
                return new Object[] { false, true, null, null };
            }
            
            // Verify issuer matches what we extracted
            if (!appId.equals(tokenIssuer)) {
                logger.warn("Token issuer mismatch: expected {}, got {}", appId, tokenIssuer);
                return new Object[] { false, true, null, null };
            }
            
            // Check if app ID is allowed for API pattern and get allowed scopes
            Object[] serviceAllowedResult = isServiceAllowed(appId, requestPath);
            boolean isAllowed = (boolean) serviceAllowedResult[0];
            List<String> allowedScopes = (List<String>) serviceAllowedResult[1];
            
            return new Object[] { isAllowed, true, appId, allowedScopes };
        } catch (InvalidJwtException e) {
            if (e.hasErrorCode(ErrorCodes.EXPIRED)) {
                logger.warn("Service token has expired");
            } else {
                logger.warn("Invalid service token: {}", e.getMessage());
            }
            return new Object[] { false, false, null, null };
        } catch (Exception e) {
            logger.error("Error validating service access: {}", e.getMessage(), e);
            return new Object[] { false, false, null, null };
        }
    }
}