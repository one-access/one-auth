package com.oneaccess.auth.config;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "myapp")
@Slf4j
@Getter
@Setter
public class AppProperties {

    public AppProperties() {
        log.info("Application Properties Initialized");
    }

    private String appName = "My Stater App";

    private String officialCompanyName = "";

    private String officialCompanyDomain = "";

    // Mail config
    private Mail mail = new Mail();

    // CORS configuration
    private Cors cors = new Cors();

    // JWT token generation related properties
    private Jwt jwt = new Jwt();

    // Custom specific OAuth2 Properties
    private OAuth2 oAuth2 = new OAuth2();

    // Custom Defaults App/Web/Rest/Misc Properties
    private Defaults defaults = new Defaults();

    @Getter
    @Setter
    @Data
    public static class Mail {
        private String defaultEmailAddress;
        private Duration verificationCodeExpirationSeconds = Duration.ofMinutes(10);
    }

    @Getter
    @Setter
    @Data
    public static class Cors {

        private String[] allowedOrigins;
        private String[] allowedMethods = {"GET", "POST", "PUT", "DELETE", "OPTIONS"};
        private String[] allowedHeaders = {"*"};
        private String[] exposedHeaders = {"*"};
        private Duration maxAge = Duration.ofSeconds(3600);
    }

    @Getter
    @Setter
    @Data
    public static class Jwt {
        private String privateKeyB64;
        private String publicKeyB64;
        private Duration expiration;
    }

    @Getter
    @Setter
    public static class OAuth2 {
        private String[] authorizedRedirectOrigins;
        private int cookieExpireSeconds = 120; // Two minutes
    }

    @Getter
    @Setter
    @Data
    public static class Defaults {
        private int defaultPageStart = 0;
        private int defaultPageSize = 50;
    }

}
