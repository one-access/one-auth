package com.oneaccess.auth.services.cache;

import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple in-memory cache implementation with TTL support.
 * Uses ConcurrentHashMap for thread safety and stores expiration time with each entry.
 */
@Slf4j
public class InMemoryCache implements SimpleCache {
    
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();
    
    private static class CacheEntry {
        final Object value;
        final Instant expiresAt;
        
        CacheEntry(Object value, Instant expiresAt) {
            this.value = value;
            this.expiresAt = expiresAt;
        }
        
        boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }
    
    @Override
    public void put(String key, Object value, Duration ttl) {
        if (key == null || value == null || ttl == null) {
            return;
        }
        
        Instant expiresAt = Instant.now().plus(ttl);
        cache.put(key, new CacheEntry(value, expiresAt));
        log.debug("Cached key: {} with TTL: {}", key, ttl);
    }
    
    @Override
    public Object get(String key) {
        if (key == null) {
            return null;
        }
        
        CacheEntry entry = cache.get(key);
        if (entry == null) {
            return null;
        }
        
        if (entry.isExpired()) {
            cache.remove(key);
            return null;
        }
        
        return entry.value;
    }
    
    @Override
    public void evict(String key) {
        if (key != null) {
            cache.remove(key);
            log.debug("Evicted key: {}", key);
        }
    }
    
    @Override
    public boolean exists(String key) {
        return get(key) != null;
    }
}