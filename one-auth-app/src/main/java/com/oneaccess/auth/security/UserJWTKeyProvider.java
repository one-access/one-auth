package com.oneaccess.auth.security;

import com.oneaccess.authjar.config.OneAuthProperties;
import com.oneaccess.authjar.service.OneAuthJwtService;
import com.oneaccess.authjar.user.CustomUserDetails;
import com.oneaccess.authjar.utils.SecurityUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.time.Duration;

@Slf4j
@Component
public class UserJWTKeyProvider {

    private final OneAuthProperties oneAuthProperties;
    private final OneAuthJwtService oneAuthJwtService;

    /**
     * Constructor with required dependencies.
     *
     * @param oneAuthProperties The OneAuth properties
     */
    public UserJWTKeyProvider(OneAuthProperties oneAuthProperties, OneAuthJwtService oneAuthJwtService) {
        this.oneAuthProperties = oneAuthProperties;
        this.oneAuthJwtService = oneAuthJwtService;
    }

    /**
     * Create a user JWT token with kid for key rotation.
     * Note: Only invoked by Authorization Server
     *
     * @param customUserDetails User details
     * @return JWT token string or null if service identity is not configured
     */
    public String createUserToken(CustomUserDetails customUserDetails) {
        OneAuthProperties.Application.KeyPair keyPair = oneAuthProperties.getApplication().getKeyPair();
        String appId = oneAuthProperties.getApplication().getAppId();

        if (appId == null || appId.isEmpty() ||
                keyPair.getCurrentKid().isEmpty() || keyPair.getPrivateKeyB64().isEmpty()) {
            log.warn("App identity is not configured. Cannot create user token.");
            return null;
        }

        try {
            String kid = keyPair.getCurrentKid();
            PrivateKey privateKey = SecurityUtil.loadPrivateKey(keyPair.getPrivateKeyB64());
            long validityInMilliseconds = Duration.ofDays(1).toMillis(); // Default 1 day validity

            return oneAuthJwtService.createUserJWTToken(
                    customUserDetails,
                    privateKey,
                    validityInMilliseconds,
                    kid // Pass the kid for key rotation
            );
        } catch (Exception e) {
            log.error("Failed to create user token: {}", e.getMessage(), e);
            return null;
        }
    }
}
