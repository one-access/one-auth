package com.oneaccess.auth.services.cache;

import java.time.Duration;

/**
 * Simple cache interface with TTL support.
 * Clean and minimal API for both in-memory and Redis implementations.
 */
public interface SimpleCache {
    
    /**
     * Store a value with TTL.
     * @param key The cache key
     * @param value The value to cache
     * @param ttl Time to live
     */
    void put(String key, Object value, Duration ttl);
    
    /**
     * Retrieve a value.
     * @param key The cache key
     * @return The cached value or null if not found/expired
     */
    Object get(String key);
    
    /**
     * Remove a value.
     * @param key The cache key
     */
    void evict(String key);
    
    /**
     * Check if key exists.
     * @param key The cache key
     * @return true if key exists and not expired
     */
    boolean exists(String key);
}