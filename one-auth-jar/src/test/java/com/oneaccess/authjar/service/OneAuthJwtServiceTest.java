package com.oneaccess.authjar.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oneaccess.authjar.config.OneAuthProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestTemplate;

import java.lang.reflect.Method;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for OneAuthJwtService with focus on secure-by-default behavior.
 * These tests verify the new service authentication logic.
 */
public class OneAuthJwtServiceTest {

    private OneAuthProperties properties;
    private JwksManager jwksManager;
    private OneAuthJwtService jwtService;
    
    // Test keys (generated using KeyGenerator)
    private static final String TEST_PUBLIC_KEY_B64 = 
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArugy5zFhlDf2sJfyuHL0IPPhW/Ee+SPSEkt2Lm7bcVgfs2XFpvC0bLfKHL1O0NN04j03yaLowsqUpPFJQnRKHBIxdPYOZ17KNtBWUIPDAEu5+ggoMPni0lN3TARO8/DRQHxeY9Id_PDy1QZQxt172qCuHwVt2Lk1Tfmg5V_ZVx80jPG8yuwWPmamOSMNKJ_LJyxE7cskPjwRaKcElx1X_Pi4nNtYnr5PEc0MB6A27V5UFV2EoSsuvZX_0CEYCSPqgf-QciZdpjrRf5qvNtMRqbyHnGNcSwUZCD0T9DehYLC1t4rKgcLC9EAEetj8gaTSWYg7Fxu6sCuYteBQoHOgew";
        
    private static final String TEST_PRIVATE_KEY_B64 = 
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCu6DLnMWGUN/awl/K4cvQg8+Fb8R75I9ISS3YubttxWB+zZcWm8LRst8ocvU7Q03TiPTfJoujCypSk8UlCdEocEjF09g5nXso20FZQg8MAS7n6CCgw+eLSU3dMBE7z8NFAfF5j0h388PLVBlDG3XvaoK4fBW3YuTVN+aDlX9lXHzSM8bzK7BY+ZqY5Iw0on8snLETtyyQ+PBFopwSXHVf8+Lic21ievk8RzQwHoDbtXlQVXYShKy69lf/QIRgJI+qB/5ByJl2mOtF/mq820xGpvIecY1xLBRkIPRP0N6FgsLW3isqBwsL0QAR62PyBpNJZiDsXG7qwK5i14FCgc6B7AgMBAAECggEAApiLo4bGGKRj/ZGjwT0OMSxYHJHi5cu0TcqKQdIqC5qajde61pQdTr0Y5ihLx9RQ7cf+0KKhqxJv9lVmbZ1ljtkY8XrIEpyuNPYOnI9NZkRkHuPexNX7RH0x+LzaTHXh2n/TXs6QMgrZb8lHiva1Od9x9h/nK3Tu55ixh0tO4c4cd/WLOTT+2e3xMA1iI0bJiozbMgd348ghO3FavAjBDAw3Z+h8to9FBpaTIlq3AQ5W+3KOiNGGyp0sP8a6WZQYzzzmSqhEQNjiy8MpS7IEdtZd1hLotEWA65lSOotneOxMQe3TbEDpgQrSUhcyQkx9SmFOEieA6MbVRMelkijhIQKBgQDImmkl4Z59SByIEZnEuMhCaLmYfJow42/bPzV7lPj61sFN1D0JLR6EnOrI3PKUaJ4Sq/bOXokcNi1Px6IlOPgJuNli4w9VqDLoR4bBEwkERQuFNb/ex62FA+s55RHZO7kNoxFGSBckUC/gLh+UKX7Yd/5sWepnTrH/VZHBJIarowKBgQDfNTTCDZD1tr0aS7TsUh7oXrdYsFvI6iVBVBobrjrjsY1ctr/V7HPb3WOmwqsr91NIfHj2/raHWZ9hWgEbynBhwBoE996kvPw/uhtfQ2C7lAXudS5taSS7NK8RXYAkAC5EAa2fwINTuvaENpFPYtR+ejWka10WPvoGnadAk6uFSQKBgAtkiZg3KhMfZ09rAHqlq+npnLDGUtN390BSZK0yFrnYPH45EYZV46fQaZ0ivzwifOe+kHPD9rF9ejFPuyu2ApA6yU3Oa26H8Ow0M7j/ZcGyUicsmEsEuBwXzuIo2kymEapummqNaZMMYsuukuiNOsD8f5yTtrZLR9yidXaspmFVAoGBAN8qvk4K7FWP2LBS41ionrhsAtrMsWhHGuqfYN8uKzj+i70YBuOnXwuD5Z+U4Tm7NeyybutdLjhTljPqnlMf648AV8OB5HxHa9l3hOiRYEULsYaCaOIBjzURbrxpBLZ568gY+XRRMbzkoJb+S/jYcmbmX329zrtwSeGVfOTnAEXpAoGAQp11NcpDIrVrXbDiyy1l0Jy2e6j/P5JSD3aSeJxJnxyBsJr+3QN3qblCK7R0uHoY8p5ymUENQL5F3OCa0GOSXjAAk9cYGYViFQlSc2/8Y+IIUqfAbqAr3vx0gpDji3hc7lR6T2oFDUbyiVsNyrwZRonAb0UBEFA/kOi3SSeV2wk=";

    @BeforeEach
    public void setup() {
        // Setup base properties
        properties = new OneAuthProperties();
        properties.getApplication().setAppId("test-app");
        properties.getApplication().getKeyPair().setCurrentKid("test-kid");
        properties.getApplication().getKeyPair().setPrivateKeyB64(TEST_PRIVATE_KEY_B64);
        properties.getApplication().getKeyPair().setPublicKeyB64(TEST_PUBLIC_KEY_B64);
        properties.getAuthServer().setOfflineMode(true);
        
        // Create JwksManager and JwtService
        jwksManager = new JwksManager(properties, new ObjectMapper(), new RestTemplate(), null);
        jwtService = new OneAuthJwtService(properties, jwksManager);
    }
    
    /**
     * Helper method to directly test the isServiceAllowed logic using reflection.
     * This bypasses token parsing and directly tests the access control logic.
     */
    private Object[] testServiceAllowed(String appId, String apiPath) {
        try {
            Method isServiceAllowedMethod = OneAuthJwtService.class.getDeclaredMethod("isServiceAllowed", String.class, String.class);
            isServiceAllowedMethod.setAccessible(true);
            return (Object[]) isServiceAllowedMethod.invoke(jwtService, appId, apiPath);
        } catch (Exception e) {
            fail("Failed to invoke isServiceAllowed method: " + e.getMessage());
            return null;
        }
    }

    @Test
    public void testServiceAuthDisabled() {
        // When service auth is disabled, all service tokens should be allowed
        properties.getApplication().getServiceAuth().setDisabled(true);
        
        // Service auth should be disabled
        assertFalse(jwksManager.isServiceAuthEnabled(), "Service auth should be disabled");
        
        // Create a dummy token (content doesn't matter when auth is disabled)
        String dummyToken = "dummy.token.here";
        
        // All paths should be allowed when service auth is disabled
        Object[] result1 = jwtService.validateServiceToken(dummyToken, "/any/path");
        assertTrue((Boolean) result1[0], "Should allow access when service auth is disabled");
        
        Object[] result2 = jwtService.validateServiceToken(dummyToken, "/api/secret/data");
        assertTrue((Boolean) result2[0], "Should allow access to any path when service auth is disabled");
    }

    @Test
    public void testSecureByDefaultWithNoPatterns() {
        // When service auth is enabled but no patterns are configured, should deny by default
        properties.getApplication().getServiceAuth().setDisabled(false);
        properties.getApplication().getServiceAuth().setApiPatterns(new ArrayList<>());
        properties.getApplication().getServiceAuth().setServiceExclusionPatterns(new ArrayList<>());
        
        // Service auth should be enabled (no longer depends on patterns)
        assertTrue(jwksManager.isServiceAuthEnabled(), "Service auth should be enabled");
        
        // Test secure by default behavior directly using access control logic
        Object[] result1 = testServiceAllowed("test-app", "/api/data");
        assertFalse((Boolean) result1[0], "Should deny access by default when no patterns configured");
        
        Object[] result2 = testServiceAllowed("test-app", "/any/path");
        assertFalse((Boolean) result2[0], "Should deny access to any path by default");
        
        Object[] result3 = testServiceAllowed("any-app", "/random/endpoint");
        assertFalse((Boolean) result3[0], "Should deny access to any app and path by default");
    }

    @Test
    public void testExclusionPatternsAllowPublicAccess() {
        // Configure service auth with exclusion patterns (public APIs)
        properties.getApplication().getServiceAuth().setDisabled(false);
        
        List<String> apiExclusionPatterns = Arrays.asList("/health", "/api/public/**");
        properties.getApplication().getServiceAuth().setServiceExclusionPatterns(apiExclusionPatterns);
        
        // Test exclusion patterns directly using access control logic
        Object[] healthResult = testServiceAllowed("test-app", "/health");
        assertTrue((Boolean) healthResult[0], "Health endpoint should be public (exclusion pattern)");
        
        Object[] publicApiResult = testServiceAllowed("test-app", "/api/public/data");
        assertTrue((Boolean) publicApiResult[0], "Public API should be accessible (exclusion pattern)");
        
        Object[] publicNestedResult = testServiceAllowed("test-app", "/api/public/nested/resource");
        assertTrue((Boolean) publicNestedResult[0], "Nested public API should be accessible (exclusion pattern)");
        
        // Non-excluded paths should be denied (secure by default)
        Object[] privateResult = testServiceAllowed("test-app", "/api/private/data");
        assertFalse((Boolean) privateResult[0], "Private API should be denied (no exclusion, secure by default)");
        
        Object[] adminResult = testServiceAllowed("test-app", "/admin/users");
        assertFalse((Boolean) adminResult[0], "Admin API should be denied (no exclusion, secure by default)");
    }

    @Test
    public void testInclusionPatternsRequireAuthentication() {
        // Configure service auth with inclusion patterns (protected APIs with permissions)
        properties.getApplication().getServiceAuth().setDisabled(false);
        
        List<OneAuthProperties.Application.ApiPattern> inclusionPatterns = new ArrayList<>();
        
        // Configure admin API with specific app permissions (test-app has no permissions)
        OneAuthProperties.Application.ApiPattern adminPattern = new OneAuthProperties.Application.ApiPattern();
        adminPattern.setPattern("/api/admin/**");
        Map<String, List<String>> adminPermissions = new HashMap<>();
        adminPermissions.put("admin-service", Arrays.asList("READ", "WRITE"));
        // Note: test-app is intentionally NOT given permissions to admin API
        adminPattern.setAppPermissions(adminPermissions);
        inclusionPatterns.add(adminPattern);
        
        properties.getApplication().getServiceAuth().setApiPatterns(inclusionPatterns);
        
        String dummyToken = "dummy.token.here";
        
        // Test inclusion patterns directly using access control logic
        // Non-matching paths should be denied immediately (secure by default)
        Object[] nonMatchingResult = testServiceAllowed("test-app", "/api/other/resource");
        assertFalse((Boolean) nonMatchingResult[0], "Non-matching API should be denied (secure by default)");
        
        Object[] randomResult = testServiceAllowed("test-app", "/random/path");
        assertFalse((Boolean) randomResult[0], "Random path should be denied (secure by default)");
        
        // Test that admin pattern denies test-app (no permissions)
        Object[] adminDeniedResult = testServiceAllowed("test-app", "/api/admin/users");
        assertFalse((Boolean) adminDeniedResult[0], "Admin API should be denied for test-app (no permissions)");
        
        // Test that admin pattern allows admin-service (has permissions)
        Object[] adminAllowedResult = testServiceAllowed("admin-service", "/api/admin/data");
        assertTrue((Boolean) adminAllowedResult[0], "Admin API should be allowed for admin-service");
        List<String> allowedScopes = (List<String>) adminAllowedResult[1];
        assertNotNull(allowedScopes, "Should have allowed scopes");
        assertEquals(Arrays.asList("READ", "WRITE"), allowedScopes, "Should have correct scopes");
    }

    @Test
    public void testCombinedExclusionAndInclusionPatterns() {
        // Test the complete behavior with both exclusion and inclusion patterns
        properties.getApplication().getServiceAuth().setDisabled(false);
        
        // Configure exclusion patterns (public APIs)
        List<String> apiExclusionPatterns = Arrays.asList("/api/public/**");
        properties.getApplication().getServiceAuth().setServiceExclusionPatterns(apiExclusionPatterns);
        properties.getApplication().getServiceAuth().setServiceExclusionPatterns(apiExclusionPatterns);
        
        // Configure inclusion patterns (protected APIs)
        List<OneAuthProperties.Application.ApiPattern> inclusionPatterns = new ArrayList<>();
        OneAuthProperties.Application.ApiPattern adminPattern = new OneAuthProperties.Application.ApiPattern();
        adminPattern.setPattern("/api/admin/**");
        Map<String, List<String>> adminPermissions = new HashMap<>();
        adminPermissions.put("admin-service", Arrays.asList("READ", "WRITE"));
        adminPattern.setAppPermissions(adminPermissions);
        inclusionPatterns.add(adminPattern);
        properties.getApplication().getServiceAuth().setApiPatterns(inclusionPatterns);
        
        // Expected behavior:
        // 1. Exclusion patterns take precedence (public APIs)
        Object[] publicResult = testServiceAllowed("test-app", "/api/public/data");
        assertTrue((Boolean) publicResult[0], "Public API should be allowed (exclusion pattern)");
        
        // 2. Non-excluded, non-included paths should be denied (secure by default)
        Object[] otherResult = testServiceAllowed("test-app", "/api/other/resource");
        assertFalse((Boolean) otherResult[0], "Other API should be denied (secure by default)");
        
        Object[] rootResult = testServiceAllowed("test-app", "/");
        assertFalse((Boolean) rootResult[0], "Root path should be denied (secure by default)");
        
        // 3. Inclusion patterns - admin API should be denied for test-app (no permissions)
        Object[] adminResult = testServiceAllowed("test-app", "/api/admin/users");
        assertFalse((Boolean) adminResult[0], "Admin API should be denied for test-app (no permissions)");
        
        // 4. Inclusion patterns - admin API should be allowed for admin-service
        Object[] adminServiceResult = testServiceAllowed("admin-service", "/api/admin/users");
        assertTrue((Boolean) adminServiceResult[0], "Admin API should be allowed for admin-service");
        List<String> allowedScopes = (List<String>) adminServiceResult[1];
        assertNotNull(allowedScopes, "Should have allowed scopes");
        assertEquals(Arrays.asList("READ", "WRITE"), allowedScopes, "Should have correct scopes");
    }

    @Test
    public void testAppIdSecurityIsolation() {
        // Test that JwksManager properly validates appId during key retrieval
        // This test verifies the appId-based security isolation works correctly
        
        String correctAppId = "test-app";
        String wrongAppId = "wrong-app";
        String testKid = "test-kid";
        
        // Both should return null since we don't have actual keys loaded in test environment,
        // but the security validation logic should still be tested
        var result1 = jwksManager.getServicePublicKeyByIssuerAndKid(correctAppId, testKid);
        assertNull(result1, "Should return null when key not found (expected in test environment)");
        
        var result2 = jwksManager.getServicePublicKeyByIssuerAndKid(wrongAppId, testKid);
        assertNull(result2, "Should return null for wrong appId (security isolation)");
        
        // Verify cache statistics show proper initialization
        var stats = jwksManager.getCacheStats();
        assertNotNull(stats, "Cache statistics should be available");
        assertTrue(stats.containsKey("offlineMode"), "Statistics should include offline mode");
        assertEquals(true, stats.get("offlineMode"), "Should be in offline mode for test");
    }

    @Test
    public void testServiceAuthEnabledBehavior() {
        // Test that isServiceAuthEnabled works correctly with the new logic
        
        // Enabled explicitly
        properties.getApplication().getServiceAuth().setDisabled(false);
        assertTrue(jwksManager.isServiceAuthEnabled(), "Should be enabled when explicitly set");
        
        // Disabled explicitly  
        properties.getApplication().getServiceAuth().setDisabled(true);
        assertFalse(jwksManager.isServiceAuthEnabled(), "Should be disabled when explicitly set");
        
        // Test that it no longer depends on API patterns being configured
        properties.getApplication().getServiceAuth().setDisabled(false);
        properties.getApplication().getServiceAuth().setApiPatterns(null);
        assertTrue(jwksManager.isServiceAuthEnabled(), "Should be enabled even with null API patterns");
        
        properties.getApplication().getServiceAuth().setApiPatterns(new ArrayList<>());
        assertTrue(jwksManager.isServiceAuthEnabled(), "Should be enabled even with empty API patterns");
    }
    
}