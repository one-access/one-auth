package com.oneaccess.authjar.utils;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class SecurityUtil {

    public static PrivateKey loadPrivateKey(String pem) throws Exception {
        try {
            byte[] keyBytes = parseBase64Pem(pem);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (Exception e) {
            throw new Exception("Failed to load private key: " + e.getMessage(), e);
        }
    }

    public static PublicKey loadPublicKey(String pem) throws Exception {
        try {
            byte[] keyBytes = parseBase64Pem(pem);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (Exception e) {
            throw new Exception("Failed to load public key: " + e.getMessage(), e);
        }
    }

    /**
     * Load private key from environment variable.
     */
    public static PrivateKey loadPrivateKeyFromEnv(String envVarName) throws Exception {
        String pemContent = loadKeyContentFromEnv(envVarName);
        return loadPrivateKey(pemContent);
    }

    /**
     * Load public key from environment variable.
     */
    public static PublicKey loadPublicKeyFromEnv(String envVarName) throws Exception {
        String pemContent = loadKeyContentFromEnv(envVarName);
        return loadPublicKey(pemContent);
    }

    /**
     * Load key content from environment variable.
     */
    private static String loadKeyContentFromEnv(String envVarName) throws Exception {
        if (envVarName == null || envVarName.trim().isEmpty()) {
            throw new IllegalArgumentException("Environment variable name cannot be null or empty");
        }

        String pemContent = System.getenv(envVarName);
        if (pemContent == null || pemContent.trim().isEmpty()) {
            throw new IllegalArgumentException("Environment variable not found or empty: " + envVarName);
        }

        return pemContent;
    }

    public static byte[] parseBase64Pem(String pem) {
        if (pem == null || pem.trim().isEmpty()) {
            throw new IllegalArgumentException("PEM string cannot be null or empty");
        }
        
        try {
            // 1) Remove PEM header/footer
            String withoutHeaders = pem
                    .replaceAll("-----BEGIN [^-]+-----", "")
                    .replaceAll("-----END [^-]+-----", "");
            
            // 2) Remove all whitespace (newlines, spaces, tabs, carriage returns)
            String normalized = withoutHeaders.replaceAll("\\s+", "");
            
            // 3) Remove any non-base64 characters that might have been introduced
            // Base64 alphabet: A-Z, a-z, 0-9, +, /, = (padding)
            normalized = normalized.replaceAll("[^A-Za-z0-9+/=]", "");
            
            // 4) Validate that we have some content left
            if (normalized.isEmpty()) {
                throw new IllegalArgumentException("PEM string contains no valid base64 content after header/footer removal");
            }
            
            // 5) Decode
            return Base64.getDecoder().decode(normalized);
        } catch (IllegalArgumentException e) {
            // Provide more helpful debugging information
            String cleanedForLogging = pem.replaceAll("\\s+", " ").substring(0, Math.min(100, pem.length()));
            throw new IllegalArgumentException("Failed to parse PEM string: " + e.getMessage() + 
                ". PEM preview (first 100 chars): '" + cleanedForLogging + "...' " +
                "Check for invalid characters like @ or other non-base64 characters in your PEM content.", e);
        }
    }
}
