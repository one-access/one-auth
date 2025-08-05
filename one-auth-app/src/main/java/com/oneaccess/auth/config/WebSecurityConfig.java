package com.oneaccess.auth.config;

import com.oneaccess.auth.security.CustomAuthenticationEntryPoint;
import com.oneaccess.auth.security.CustomUserDetailsService;
import com.oneaccess.auth.security.oauth.CustomOAuth2UserService;
import com.oneaccess.auth.security.oauth.OAuth2AuthenticationFailureHandler;
import com.oneaccess.auth.security.oauth.OAuth2AuthenticationSuccessHandler;
import com.oneaccess.auth.security.oauth.HttpCookieOAuth2AuthorizationRequestRepository;
import com.oneaccess.auth.security.oauth.PKCEAuthorizationRequestResolver;
import com.oneaccess.authjar.OneAuthFilter;
import com.oneaccess.authjar.config.OneAuthProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true,
        prePostEnabled = true
)
@Slf4j
public class WebSecurityConfig {

    // CustomUserDetailsService - To process custom user SignUp/SignIn request
    // CustomOAuth2UserService - To process OAuth user SignUp/SignIn request
    private final CustomUserDetailsService customUserDetailsService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OneAuthFilter oneAuthFilter;
    private final OneAuthProperties oneAuthProperties;

    // CustomAuthenticationEntryPoint - Unauthorized Access handler
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    // Cookie based repository, OAuth2 Success and Failure Handler
    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;
    private final ClientRegistrationRepository clientRegistrationRepository;

    public WebSecurityConfig(CustomUserDetailsService customUserDetailsService,
                             CustomOAuth2UserService customOAuth2UserService, 
                             OneAuthFilter oneAuthFilter, 
                             OneAuthProperties oneAuthProperties,
                             CustomAuthenticationEntryPoint customAuthenticationEntryPoint,
                             HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository,
                             OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler,
                             OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler,
                             ClientRegistrationRepository clientRegistrationRepository) {
        this.customUserDetailsService = customUserDetailsService;
        this.customOAuth2UserService = customOAuth2UserService;
        this.oneAuthFilter = oneAuthFilter;
        this.oneAuthProperties = oneAuthProperties;
        this.customAuthenticationEntryPoint = customAuthenticationEntryPoint;
        this.httpCookieOAuth2AuthorizationRequestRepository = httpCookieOAuth2AuthorizationRequestRepository;
        this.oAuth2AuthenticationSuccessHandler = oAuth2AuthenticationSuccessHandler;
        this.oAuth2AuthenticationFailureHandler = oAuth2AuthenticationFailureHandler;
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Primary
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        log.info("App SecurityFilterChain, appExclusionPatterns: {}, serviceExclusionPatterns: {}", oneAuthProperties.getApplication().getAppExclusionPatterns(),
                oneAuthProperties.getApplication().getServiceAuth().getServiceExclusionPatterns());

        http
                .cors(withDefaults()) // Use spring.web.cors.* properties
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable()) // Correct for JWT-based API with separate frontend
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .headers(withDefaults()) // Use Spring Security defaults for security headers
                .exceptionHandling(e -> e
                    .authenticationEntryPoint(customAuthenticationEntryPoint)
                )
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(oneAuthProperties.getApplication().getAppExclusionPatterns().toArray(new String[0])).permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                    .authorizationEndpoint(auth -> auth
                        .baseUri("/oauth2/authorize")
                        .authorizationRequestRepository(httpCookieOAuth2AuthorizationRequestRepository)
                        .authorizationRequestResolver(pkceAuthorizationRequestResolver())
                    )
                    .redirectionEndpoint(redir -> redir
                        .baseUri("/oauth2/callback/*")
                    )
                    .userInfoEndpoint(userInfo -> userInfo
                        .userService(customOAuth2UserService)
                    )
                    .successHandler(oAuth2AuthenticationSuccessHandler)
                    .failureHandler(oAuth2AuthenticationFailureHandler)
                );

         http.addFilterBefore(oneAuthFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PKCEAuthorizationRequestResolver pkceAuthorizationRequestResolver() {
        return new PKCEAuthorizationRequestResolver(clientRegistrationRepository);
    }
}
