package com.oneaccess.auth.services.cache;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;

/**
 * Simple Redis cache implementation with TTL support.
 * Thin wrapper around RedisTemplate for clean cache operations.
 */
@Slf4j
public class RedisCache implements SimpleCache {
    
    private final RedisTemplate<String, Object> redisTemplate;
    private static final String KEY_PREFIX = "oneauth:";
    
    public RedisCache(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }
    
    @Override
    public void put(String key, Object value, Duration ttl) {
        if (key == null || value == null || ttl == null) {
            return;
        }
        
        String redisKey = KEY_PREFIX + key;
        redisTemplate.opsForValue().set(redisKey, value, ttl);
        log.debug("Cached in Redis: {} with TTL: {}", key, ttl);
    }
    
    @Override
    public Object get(String key) {
        if (key == null) {
            return null;
        }
        
        String redisKey = KEY_PREFIX + key;
        return redisTemplate.opsForValue().get(redisKey);
    }
    
    @Override
    public void evict(String key) {
        if (key != null) {
            String redisKey = KEY_PREFIX + key;
            redisTemplate.delete(redisKey);
            log.debug("Evicted from Redis: {}", key);
        }
    }
    
    @Override
    public boolean exists(String key) {
        if (key == null) {
            return false;
        }
        
        String redisKey = KEY_PREFIX + key;
        return Boolean.TRUE.equals(redisTemplate.hasKey(redisKey));
    }
}