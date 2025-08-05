package com.oneaccess.authjar.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oneaccess.authjar.config.OneAuthProperties;
import com.oneaccess.authjar.utils.SecurityUtil;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manager for JSON Web Key Sets (JWKS).
 * Handles optimal caching and refresh of JWKS for user and service token validation.
 * Supports both online (auth-server API) and offline (local JWKS file) modes.
 * Each service appId loads keys on demand from the unified JWKS structure.
 */
@Component
@Slf4j
public class JwksManager {
    
    private final OneAuthProperties properties;
    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate;
    private final ResourceLoader resourceLoader;
    
    // Cache for user JWT keys from auth-server
    private final Map<String, PublicJsonWebKey> userJwtCache = new ConcurrentHashMap<>();
    // Cache for service keys per appId (each appId has its own JWKS)
    private final Map<String, Map<String, PublicJsonWebKey>> serviceKeysByAppId = new ConcurrentHashMap<>();
    
    private VerificationKeyResolver keyResolver;
    private LocalDateTime lastUserJwtRefresh;
    private LocalDateTime lastServiceKeysRefresh;
    private final Duration cacheTimeout = Duration.ofHours(1);
    private volatile boolean userJwtKeysInitialized = false;
    // Track which appIds have been initialized
    private final Set<String> initializedAppIds = ConcurrentHashMap.newKeySet();
    
    public JwksManager(OneAuthProperties properties, @Qualifier("oneAuth_objectMapper") ObjectMapper objectMapper,
                       @Qualifier("oneAuth_restTemplate") RestTemplate restTemplate, ResourceLoader resourceLoader) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.restTemplate = restTemplate;
        this.resourceLoader = resourceLoader;
    }
    
    /**
     * Initialize user JWT keys on demand.
     * This method is thread-safe and ensures single initialization.
     */
    private synchronized void initializeUserKeysIfNeeded() {
        if (!userJwtKeysInitialized) {
            refreshUserJwks();
            userJwtKeysInitialized = true;
        }
    }
    
    /**
     * Initialize service keys for a specific appId on demand.
     * This method is thread-safe and ensures single initialization per appId.
     */
    private synchronized void initializeServiceKeysIfNeeded(String appId) {
        if (!initializedAppIds.contains(appId)) {
            refreshServiceJwksForAppId(appId);
            initializedAppIds.add(appId);
        }
    }
    
    /**
     * Refresh user JWT keys from auth-server.
     * This method is synchronized to prevent concurrent refresh issues.
     */
    public synchronized void refreshUserJwks() {
        try {
            List<JsonWebKey> userKeys = new ArrayList<>();
            
            if (properties.getAuthServer().isOfflineMode()) {
                loadOfflineUserJwks(userKeys);
                log.info("Loading user JWKS in offline mode");
            } else {
                loadOnlineUserJwks(userKeys);
                log.info("Loading user JWKS from auth-server API");
            }
            
            // Update user JWT cache atomically
            userJwtCache.clear();
            for (JsonWebKey key : userKeys) {
                if (key instanceof PublicJsonWebKey) {
                    PublicJsonWebKey pubKey = (PublicJsonWebKey) key;
                    String kid = pubKey.getKeyId();
                    if (StringUtils.hasText(kid)) {
                        userJwtCache.put(kid, pubKey);
                        log.debug("Cached user JWT key with kid: {}", kid);
                    }
                }
            }
            
            this.lastUserJwtRefresh = LocalDateTime.now();
            log.info("User JWT cache refreshed successfully with {} keys", userKeys.size());
            
        } catch (Exception e) {
            log.error("Failed to refresh user JWT cache", e);
            throw new RuntimeException("User JWT refresh failed", e);
        }
    }
    
    /**
     * Refresh service keys for a specific appId.
     * This method is synchronized to prevent concurrent refresh issues.
     */
    public synchronized void refreshServiceJwksForAppId(String appId) {
        try {
            List<JsonWebKey> serviceKeys = new ArrayList<>();
            
            if (properties.getAuthServer().isOfflineMode()) {
                loadOfflineServiceJwksForAppId(appId, serviceKeys);
                log.info("Loading service keys for appId {} in offline mode", appId);
            } else {
                loadOnlineServiceJwksForAppId(appId, serviceKeys);
                log.info("Loading service keys for appId {} from auth-server API", appId);
            }
            
            // Update service keys cache for this appId atomically
            Map<String, PublicJsonWebKey> appIdCache = new ConcurrentHashMap<>();
            for (JsonWebKey key : serviceKeys) {
                if (key instanceof PublicJsonWebKey) {
                    PublicJsonWebKey pubKey = (PublicJsonWebKey) key;
                    String kid = pubKey.getKeyId();
                    if (StringUtils.hasText(kid)) {
                        appIdCache.put(kid, pubKey);
                        log.debug("Cached service key with kid: {} for appId: {}", kid, appId);
                    }
                }
            }
            serviceKeysByAppId.put(appId, appIdCache);
            
            // Update key resolver for service token validation
            if (!serviceKeys.isEmpty()) {
                this.keyResolver = new JwksVerificationKeyResolver(serviceKeys);
            }
            
            this.lastServiceKeysRefresh = LocalDateTime.now();
            log.info("Service keys cache refreshed successfully for appId {} with {} keys", appId, serviceKeys.size());
            
        } catch (Exception e) {
            log.error("Failed to refresh service keys cache for appId: {}", appId, e);
            throw new RuntimeException("Service keys refresh failed for appId: " + appId, e);
        }
    }
    
    /**
     * Load user JWT keys from auth-server API endpoint using appId filtering.
     */
    private void loadOnlineUserJwks(List<JsonWebKey> userKeys) throws Exception {
        String authServerUrl = properties.getAuthServer().getBaseUrl();
        String jwksApi = properties.getAuthServer().getJwksApi();
        
        if (!StringUtils.hasText(authServerUrl)) {
            throw new IllegalStateException("Auth server base URL is not configured for online mode");
        }
        
        String jwksUrl = authServerUrl + jwksApi + "?appId=auth-server";
        log.debug("Fetching user JWKS from: {}", jwksUrl);
        
        // HTTP call to fetch user JWKS (filtered by appId=auth-server)
        String jwksJson = restTemplate.getForObject(jwksUrl, String.class);
        if (!StringUtils.hasText(jwksJson)) {
            throw new RuntimeException("Empty user JWKS response from auth server");
        }
        
        JsonNode jwksNode = objectMapper.readTree(jwksJson);
        if (jwksNode.has("keys") && jwksNode.get("keys").isArray()) {
            for (JsonNode keyNode : jwksNode.get("keys")) {
                try {
                    JsonWebKey jwk = JsonWebKey.Factory.newJwk(keyNode.toString());
                    userKeys.add(jwk);
                } catch (Exception e) {
                    log.warn("Failed to parse user JWK: {}", e.getMessage());
                }
            }
        } else {
            throw new RuntimeException("Invalid user JWKS format: missing 'keys' array");
        }
        
        log.info("Loaded {} user keys from auth-server JWKS API", userKeys.size());
    }
    
    /**
     * Load service keys from auth-server API endpoint for a specific appId.
     */
    private void loadOnlineServiceJwksForAppId(String appId, List<JsonWebKey> serviceKeys) throws Exception {
        String authServerUrl = properties.getAuthServer().getBaseUrl();
        String jwksApi = properties.getAuthServer().getJwksApi();
        
        if (!StringUtils.hasText(authServerUrl)) {
            throw new IllegalStateException("Auth server base URL is not configured for online mode");
        }
        
        String jwksUrl = authServerUrl + jwksApi + "?appId=" + appId;
        log.debug("Fetching service JWKS for appId {} from: {}", appId, jwksUrl);
        
        // HTTP call to fetch service JWKS for specific appId
        String jwksJson = restTemplate.getForObject(jwksUrl, String.class);
        if (!StringUtils.hasText(jwksJson)) {
            throw new RuntimeException("Empty service JWKS response for appId: " + appId);
        }
        
        JsonNode jwksNode = objectMapper.readTree(jwksJson);
        if (jwksNode.has("keys") && jwksNode.get("keys").isArray()) {
            for (JsonNode keyNode : jwksNode.get("keys")) {
                try {
                    JsonWebKey jwk = JsonWebKey.Factory.newJwk(keyNode.toString());
                    serviceKeys.add(jwk);
                } catch (Exception e) {
                    log.warn("Failed to parse service JWK for appId {}: {}", appId, e.getMessage());
                }
            }
        } else {
            throw new RuntimeException("Invalid service JWKS format for appId " + appId + ": missing 'keys' array");
        }
        
        log.info("Loaded {} service keys for appId {} from auth-server JWKS API", serviceKeys.size(), appId);
    }
    
    /**
     * Load user JWT keys from local file for offline mode.
     * Loads from unified jwks.json and filters for auth-server keys.
     */
    private void loadOfflineUserJwks(List<JsonWebKey> userKeys) throws Exception {
        // Load from unified jwks.json file and filter for auth-server keys
        try {
            Resource jwksResource = resourceLoader.getResource("classpath:/.well-known/jwks.json");
            if (jwksResource.exists()) {
                String jwksJson = StreamUtils.copyToString(jwksResource.getInputStream(), StandardCharsets.UTF_8);
                JsonNode jwksNode = objectMapper.readTree(jwksJson);
                
                // Look for auth-server section in the appId-organized structure
                if (jwksNode.has("auth-server")) {
                    JsonNode authServerNode = jwksNode.get("auth-server");
                    if (authServerNode.has("keys") && authServerNode.get("keys").isArray()) {
                        for (JsonNode keyNode : authServerNode.get("keys")) {
                            try {
                                JsonWebKey jwk = JsonWebKey.Factory.newJwk(keyNode.toString());
                                userKeys.add(jwk);
                            } catch (Exception e) {
                                log.warn("Failed to parse user JWK from offline file: {}", e.getMessage());
                            }
                        }
                        log.info("Loaded {} user keys from offline jwks.json (auth-server section)", userKeys.size());
                    }
                } else {
                    log.warn("auth-server section not found in jwks.json for user keys");
                }
            } else {
                log.warn("JWKS file not found: classpath:/.well-known/jwks.json");
            }
        } catch (Exception e) {
            log.warn("Failed to load offline user JWKS file: {}", e.getMessage());
        }
        
        if (userKeys.isEmpty()) {
            log.warn("No user JWKS keys loaded in offline mode");
        }
    }
    
    /**
     * Load service keys from local file for offline mode for a specific appId.
     * Loads from unified jwks.json and extracts keys for the specific appId section.
     */
    private void loadOfflineServiceJwksForAppId(String appId, List<JsonWebKey> serviceKeys) throws Exception {
        // Load from unified jwks.json file and extract keys for specific appId
        try {
            Resource jwksResource = resourceLoader.getResource("classpath:/.well-known/jwks.json");
            if (jwksResource.exists()) {
                String jwksJson = StreamUtils.copyToString(jwksResource.getInputStream(), StandardCharsets.UTF_8);
                JsonNode jwksNode = objectMapper.readTree(jwksJson);
                
                // Look for specific appId section
                if (jwksNode.has(appId)) {
                    JsonNode appSection = jwksNode.get(appId);
                    
                    if (appSection.has("keys") && appSection.get("keys").isArray()) {
                        for (JsonNode keyNode : appSection.get("keys")) {
                            try {
                                JsonWebKey jwk = JsonWebKey.Factory.newJwk(keyNode.toString());
                                serviceKeys.add(jwk);
                            } catch (Exception e) {
                                log.warn("Failed to parse service JWK from offline file for appId {}: {}", appId, e.getMessage());
                            }
                        }
                        log.info("Loaded {} keys for appId {} from offline jwks.json", serviceKeys.size(), appId);
                    }
                } else {
                    log.warn("AppId section '{}' not found in jwks.json", appId);
                }
            } else {
                log.warn("Service JWKS file not found: classpath:/.well-known/jwks.json");
            }
        } catch (Exception e) {
            log.warn("Failed to load offline service JWKS file for appId {}: {}", appId, e.getMessage());
        }
        
        if (serviceKeys.isEmpty()) {
            log.warn("No service JWKS keys loaded for appId {} in offline mode", appId);
        }
    }
    
    /**
     * Get public key for user token validation by kid.
     * Only looks in user JWT cache from auth-server.
     */
    public PublicKey getUserPublicKey(String kid) {
        initializeUserKeysIfNeeded();
        refreshUserKeysIfNeeded();
        
        if (StringUtils.hasText(kid)) {
            PublicJsonWebKey jwk = userJwtCache.get(kid);
            if (jwk != null) {
                return jwk.getPublicKey();
            }
        }
        
        return null;
    }
    
    /**
     * Get service public key by appId (issuer) and kid with strict appId validation.
     * Only returns key if it exists in the specified appId cache for security isolation.
     *
     * @param appId The application ID (issuer) that must match the key's appId
     * @param kid The key ID
     * @return PublicKey if found in the appId cache, null otherwise
     */
    public PublicKey getServicePublicKeyByIssuerAndKid(String appId, String kid) {
        if (!StringUtils.hasText(appId) || !StringUtils.hasText(kid)) {
            return null;
        }
        
        // Initialize keys for this appId if needed
        initializeServiceKeysIfNeeded(appId);
        refreshServiceKeysIfNeeded(appId);
        
        // Get the cache for this specific appId
        Map<String, PublicJsonWebKey> appCache = serviceKeysByAppId.get(appId);
        if (appCache != null) {
            PublicJsonWebKey jwk = appCache.get(kid);
            if (jwk != null) {
                log.debug("Found service key with kid: {} for appId: {}", kid, appId);
                return jwk.getPublicKey();
            }
        }
        
        log.debug("No service key found for appId: {}, kid: {}", appId, kid);
        return null;
    }
    
    /**
     * Get the verification key resolver for service tokens.
     */
    public VerificationKeyResolver getKeyResolver() {
        refreshServiceKeysIfNeeded("auth-server"); // Default to auth-server keys
        return keyResolver;
    }
    
    /**
     * Auto-refresh user JWT cache if it's stale.
     */
    private void refreshUserKeysIfNeeded() {
        if (lastUserJwtRefresh == null || Duration.between(lastUserJwtRefresh, LocalDateTime.now()).compareTo(cacheTimeout) > 0) {
            log.info("User JWT cache is stale, refreshing...");
            refreshUserJwks();
        }
    }
    
    /**
     * Auto-refresh service keys cache for a specific appId if it's stale.
     */
    private void refreshServiceKeysIfNeeded(String appId) {
        if (lastServiceKeysRefresh == null || Duration.between(lastServiceKeysRefresh, LocalDateTime.now()).compareTo(cacheTimeout) > 0) {
            log.info("Service keys cache for appId {} is stale, refreshing...", appId);
            refreshServiceJwksForAppId(appId);
        }
    }
    
    /**
     * Application-callable async refresh method for user keys.
     */
    @Async
    public CompletableFuture<Void> refreshUserKeysAsync() {
        return CompletableFuture.runAsync(this::refreshUserJwks);
    }
    
    /**
     * Application-callable async refresh method for service keys for a specific appId.
     */
    @Async
    public CompletableFuture<Void> refreshServiceKeysAsync(String appId) {
        return CompletableFuture.runAsync(() -> refreshServiceJwksForAppId(appId));
    }
    
    /**
     * Get cache statistics for monitoring.
     */
    public Map<String, Object> getCacheStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("userJwtCacheSize", userJwtCache.size());
        stats.put("serviceKeysByAppIdSize", serviceKeysByAppId.size());
        stats.put("initializedAppIds", new ArrayList<>(initializedAppIds));
        stats.put("lastUserJwtRefresh", lastUserJwtRefresh);
        stats.put("lastServiceKeysRefresh", lastServiceKeysRefresh);
        stats.put("cacheTimeout", cacheTimeout.toString());
        stats.put("offlineMode", properties.getAuthServer().isOfflineMode());
        stats.put("userJwtKeysInitialized", userJwtKeysInitialized);
        return stats;
    }
    
    /**
     * Check if service auth is enabled.
     */
    public boolean isServiceAuthEnabled() {
        return !properties.getApplication().getServiceAuth().isDisabled();
    }
    
    /**
     * Get all available user JWT key IDs.
     */
    public Set<String> getAvailableUserJwtKids() {
        initializeUserKeysIfNeeded();
        return new HashSet<>(userJwtCache.keySet());
    }
    
    /**
     * Get all available JWKS key IDs (legacy compatibility).
     */
    public Set<String> getAvailableJwksKids() {
        return getAvailableUserJwtKids();
    }
    
    /**
     * Get all available service key IDs for a specific appId.
     */
    public Set<String> getAvailableServiceKids(String appId) {
        initializeServiceKeysIfNeeded(appId);
        Map<String, PublicJsonWebKey> appCache = serviceKeysByAppId.get(appId);
        return appCache != null ? new HashSet<>(appCache.keySet()) : new HashSet<>();
    }
}