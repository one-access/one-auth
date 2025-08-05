package com.oneaccess.authjar.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

/**
 * Configuration properties for OneAuth authentication.
 */
@ConfigurationProperties(prefix = "one-auth")
@Data
public class OneAuthProperties {

    private Application application = new Application();
    
    private AuthServer authServer = new AuthServer();

    @Data
    public static class Application {
        
        private String appId = "";

        private String appName = "";
        
        private KeyPair keyPair = new KeyPair();
        
        private List<String> appExclusionPatterns = new ArrayList<>();
        
        private ServiceAuth serviceAuth = new ServiceAuth();
        
        @Data
        public static class KeyPair {
            private String currentKid = "";
            
            // DEPRECATED: Use environment variables or secure key management instead
            @Deprecated(since = "1.0.0", forRemoval = true)
            private String privateKeyB64 = "";
            
            @Deprecated(since = "1.0.0", forRemoval = true)
            private String publicKeyB64 = "";
            
            // NEW: Environment variable names for secure key retrieval
            private String privateKeyEnv = "";
            private String publicKeyEnv = "";
            
            /**
             * Get private key from environment variable.
             * Falls back to deprecated privateKeyB64 if environment variable not set.
             */
            public String getPrivateKeyB64() {
                if (org.springframework.util.StringUtils.hasText(privateKeyEnv)) {
                    String envValue = System.getenv(privateKeyEnv);
                    if (org.springframework.util.StringUtils.hasText(envValue)) {
                        return envValue;
                    }
                }
                return privateKeyB64; // Fallback to deprecated field
            }
            
            /**
             * Get public key from environment variable.
             * Falls back to deprecated publicKeyB64 if environment variable not set.
             */
            public String getPublicKeyB64() {
                if (org.springframework.util.StringUtils.hasText(publicKeyEnv)) {
                    String envValue = System.getenv(publicKeyEnv);
                    if (org.springframework.util.StringUtils.hasText(envValue)) {
                        return envValue;
                    }
                }
                return publicKeyB64; // Fallback to deprecated field
            }
        }
        
        @Data
        public static class ServiceAuth {
            
            private boolean disabled;
            
            private List<ApiPattern> apiPatterns = new ArrayList<>();

            private List<String> serviceExclusionPatterns = new ArrayList<>();

            private Duration serviceJwtTokenValidity = Duration.ofDays(1); // Set to 1 hour for prod
            
            public boolean isServiceAuthEnabled() {
                return !disabled; // Secure by default - when enabled, all APIs are protected unless excluded
            }
        }
        
        @Data
        public static class ApiPattern {
            private String pattern;
            private Map<String, List<String>> appPermissions = new HashMap<>();
        }
    }
    
    @Data
    public static class AuthServer {
        
        private String baseUrl;
        
        private String jwksApi = "/.well-known/jwks.json";
        
        private boolean offlineMode = false;
    }
}