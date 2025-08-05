package com.oneaccess.auth.config;

import com.oneaccess.auth.services.cache.InMemoryCache;
import com.oneaccess.auth.services.cache.RedisCache;
import com.oneaccess.auth.services.cache.SimpleCache;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Simplified cache configuration.
 * Returns either InMemoryCache or RedisCache based on configuration.
 */
@Slf4j
@Configuration
public class CacheConfig {

    /**
     * In-memory cache for development/testing.
     */
    @Bean
    @Primary
    @ConditionalOnProperty(name = "myapp.cache.type", havingValue = "memory", matchIfMissing = true)
    public SimpleCache inMemoryCache() {
        log.info("Using in-memory cache");
        return new InMemoryCache();
    }

    /**
     * Redis cache for production.
     */
    @Bean
    @ConditionalOnProperty(name = "myapp.cache.type", havingValue = "redis")
    public SimpleCache redisCache(RedisTemplate<String, Object> redisTemplate) {
        log.info("Using Redis cache");
        return new RedisCache(redisTemplate);
    }

    /**
     * RedisTemplate configuration for Redis cache.
     */
    @Bean
    @ConditionalOnProperty(name = "myapp.cache.type", havingValue = "redis")
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        template.afterPropertiesSet();
        return template;
    }
}