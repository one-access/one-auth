package com.oneaccess.authjar;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.oneaccess.authjar.config.OneAuthProperties;
import com.oneaccess.authjar.config.YamlPropertySourceFactory;
import com.oneaccess.authjar.service.JwksManager;
import com.oneaccess.authjar.service.OneAuthJwtService;
import com.oneaccess.authjar.utils.AuthCommonUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.util.StringUtils;

@Slf4j
@Configuration
@EnableConfigurationProperties(OneAuthProperties.class)
@ComponentScan(basePackages = "com.oneaccess.authjar")
@PropertySource(value = "classpath:one-auth-internal.yml", factory = YamlPropertySourceFactory.class)
public class OneAuthBeanConfiguration {

    @Bean(name = "oneAuth_objectMapper")
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = JsonMapper.builder()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .findAndAddModules()
                .build();
        return mapper;
    }

    @Bean
    public AuthCommonUtil authCommonUtils(@Qualifier("oneAuth_objectMapper") ObjectMapper objectMapper) {
        return new AuthCommonUtil(objectMapper);
    }

    @Bean(name = "oneAuth_restTemplate")
    public org.springframework.web.client.RestTemplate restTemplate() {
        return new org.springframework.web.client.RestTemplate();
    }

    @Bean
    public JwksManager jwksManager(OneAuthProperties properties, @Qualifier("oneAuth_objectMapper") ObjectMapper objectMapper,
                                  org.springframework.web.client.RestTemplate restTemplate,
                                  org.springframework.core.io.ResourceLoader resourceLoader) {
        log.info("OneAuth JWKS manager is active");
        return new JwksManager(properties, objectMapper, restTemplate, resourceLoader);
    }
    
    @Bean
    public OneAuthJwtService oneAuthJwtService(OneAuthProperties properties, JwksManager jwksManager) {
        log.info("OneAuth JWT service is active");
        return new OneAuthJwtService(properties, jwksManager);
    }

    @Bean
    public OneAuthFilter oneAuthFilter(OneAuthProperties properties, OneAuthJwtService jwtService) {
        log.info("OneAuth filter is configured");
        return new OneAuthFilter(properties, jwtService);
    }
}