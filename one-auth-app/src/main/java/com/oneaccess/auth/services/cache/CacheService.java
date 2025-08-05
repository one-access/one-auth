package com.oneaccess.auth.services.cache;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * Simple cache service facade.
 * Delegates to the underlying SimpleCache implementation (InMemory or Redis).
 */
@Slf4j
@Service
public class CacheService {

    private final SimpleCache cache;

    public CacheService(SimpleCache cache) {
        this.cache = cache;
    }

    /**
     * Store a value with TTL.
     * @param cacheName Cache namespace (e.g., "oauth2_auth_codes")
     * @param key The cache key
     * @param value The value to cache
     * @param ttl Time to live
     */
    public void put(String cacheName, String key, Object value, Duration ttl) {
        String fullKey = buildKey(cacheName, key);
        cache.put(fullKey, value, ttl);
    }

    /**
     * Retrieve a value.
     * @param cacheName Cache namespace
     * @param key The cache key
     * @param valueType Expected type of the cached value
     * @return The cached value or null if not found
     */
    @SuppressWarnings("unchecked")
    public <T> T get(String cacheName, String key, Class<T> valueType) {
        String fullKey = buildKey(cacheName, key);
        Object value = cache.get(fullKey);
        return value != null ? (T) value : null;
    }

    /**
     * Remove a value.
     * @param cacheName Cache namespace
     * @param key The cache key
     */
    public void evict(String cacheName, String key) {
        String fullKey = buildKey(cacheName, key);
        cache.evict(fullKey);
    }

    /**
     * Check if key exists.
     * @param cacheName Cache namespace
     * @param key The cache key
     * @return true if key exists and not expired
     */
    public boolean exists(String cacheName, String key) {
        String fullKey = buildKey(cacheName, key);
        return cache.exists(fullKey);
    }

    private String buildKey(String cacheName, String key) {
        return cacheName + ":" + key;
    }
}