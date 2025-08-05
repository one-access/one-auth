package com.oneaccess.authjar;

import com.oneaccess.authjar.config.OneAuthProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Default security configuration for OneAuth.
 * This provides a sensible default SecurityFilterChain when consumer apps don't define their own.
 * If consumer apps provide their own SecurityFilterChain, this won't be used.
 * This ensures that including one-auth-jar always results in a working security setup.
 */
@Slf4j
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(SecurityFilterChain.class)
@EnableConfigurationProperties(OneAuthProperties.class)
public class OneAuthDefaultSecurityConfiguration {

    /**
     * Default SecurityFilterChain with OneAuth JWT authentication.
     * Only created if no other SecurityFilterChain bean exists.
     * Consumer apps can override by providing their own @Bean SecurityFilterChain.
     */
    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain oneAuthDefaultSecurityFilterChain(HttpSecurity http, OneAuthFilter oneAuthFilter, OneAuthProperties properties) throws Exception {
        log.info("OneAuth Default SecurityFilterChain, appExclusionPatterns: {} serviceExclusionPatterns: {}", properties.getApplication().getAppExclusionPatterns(),
                properties.getApplication().getServiceAuth().getServiceExclusionPatterns());
        log.debug("Consumer app can override default SecurityFilterChain by providing their own SecurityFilterChain bean");

        http
                .cors(withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable())
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(properties.getApplication().getAppExclusionPatterns().toArray(new String[0])).permitAll()
                        .anyRequest().authenticated()
                );
        
        // Add clean JWT filter (handles user and service tokens with merged authorities)
        http.addFilterBefore(oneAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}