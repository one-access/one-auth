package com.oneaccess.authjar.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for generating RSA key pairs and converting them to various formats.
 * <p>
 * This class provides a main method that can be run to generate keys for use with one-auth-jar.
 * To use, simply configure the variables in the {@code main} method and run the script.
 * </p>
 * Note: This class is in the test package as it's intended for development/testing purposes only.
 */
public class KeyGenerator {
    private static final Logger log = LoggerFactory.getLogger(KeyGenerator.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final String KEY_ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;
    private static final String SIGNATURE_ALGORITHM = AlgorithmIdentifiers.RSA_USING_SHA256;

    /**
     * A record to hold the generated key artifacts.
     *
     * @param jwkSet           The public key in JWK Set format (JSON string).
     * @param privateKeyPem    The private key in PEM format.
     * @param privateKeyBase64 The raw private key (PKCS#8), Base64 encoded.
     * @param publicKeyBase64  The raw public key (X.509), Base64 encoded.
     */
    public record KeyArtifacts(String jwkSet, String privateKeyPem, String privateKeyBase64, String publicKeyBase64) {}

    /**
     * Main method to generate and display RSA key pairs.
     * <p>
     * --- CONFIGURATION ---
     * Set the variables below before running.
     * </p>
     *
     * @param args Command line arguments (not used).
     */
    /**
     * JUnit test to generate and display RSA key pairs.
     * This test will generate a key pair and output the JWK set and private key.
     */
    @Test
    public void generateKeys() throws JoseException, IOException {
        // --- CONFIGURE THESE VALUES ---
        final String appId = "my-service";
        final String kid = appId + "-key-1"; // A unique identifier for this key
        final String outputDir = "target/generated-keys"; // Directory to save the key files
        // -----------------------------

        log.info("=== One Auth Key Generator ===");
        log.info("Configuration:");
        log.info("  - App ID: {}", appId);
        log.info("  - Key ID (kid): {}", kid);
        log.info("  - Output Directory: {}", outputDir);
        log.info("---------------------------------");

        try {
            KeyArtifacts artifacts = generateAndSaveKeys(appId, kid, outputDir);

            // Print results to console
            log.info("\n✅ Keys generated successfully!");

            log.info("\n1. JWK Set (for public key sharing):");
            log.info(artifacts.jwkSet());

            log.info("\n2. Private Key (Base64 for application.yml):");
            log.info(artifacts.privateKeyBase64());

            log.info("\n3. Private Key (PEM Format):");
            log.info(artifacts.privateKeyPem());

            log.info("\n=== Configuration Example ===");
            log.info("Add the following to your application.yml:");
            log.info("one-auth:");
            log.info("  app-identity:");
            log.info("    app-id: \"{}\"", appId);
            log.info("    current-kid: \"{}\"", kid);
            log.info("    # Option: Use base64 encoded private key directly (for testing/simplicity)");
            log.info("    private-key-b64: \"{}\"", artifacts.privateKeyBase64());
            log.info("    public-key-b64: \"{}\"", artifacts.publicKeyBase64());

            log.info("\n=== JWKS.json Example ===");
            log.info("Add the following to your jwks.json file:");
            log.info(generateJwksJsonExample(appId, artifacts.jwkSet()));

            log.info("\n=== Next Steps ===");
            log.info("1. Supply the generated '{}-private-key' base64 to your service's app identity via env.", appId);
            log.info("2. Send the public JWK Set to the authhub-server team to add to the jwks.json file to enable token validation by other services.");

        } catch (Exception e) {
            log.error("❌ Error generating keys: {}", e.getMessage(), e);
        }
    }


    /**
     * Generates a key pair using jose4j, formats it, saves it to files, and returns the artifacts.
     *
     * @param appId     The application ID, used for naming the private key file.
     * @param kid       The Key ID for the JWK.
     * @param outputDir The directory where the key files will be saved.
     * @return A {@link KeyArtifacts} record containing the generated keys.
     * @throws JoseException if there is an error generating the JWK.
     * @throws IOException   if there is an error writing the key files.
     */
    public static KeyArtifacts generateAndSaveKeys(String appId, String kid, String outputDir)
            throws JoseException, IOException {

        // 1. Generate the RSA key pair using jose4j
        log.info("\n🔄 Generating {}-bit RSA key pair...", KEY_SIZE);
        RsaJsonWebKey rsaJwk = RsaJwkGenerator.generateJwk(KEY_SIZE);
        rsaJwk.setKeyId(kid);
        rsaJwk.setAlgorithm(SIGNATURE_ALGORITHM);
        rsaJwk.setUse("sig");
        
        // 2. Create the different key formats
        String jwkSet = new JsonWebKeySet(rsaJwk).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        String privateKeyPem = generatePrivateKeyPem(rsaJwk.getPrivateKey());
        String privateKeyBase64 = Base64.getEncoder().encodeToString(rsaJwk.getPrivateKey().getEncoded());
        String publicKeyBase64 = Base64.getEncoder().encodeToString(rsaJwk.getPublicKey().getEncoded());

        // 3. Save keys to files
        Path outputPath = Paths.get(outputDir);
        if (!Files.exists(outputPath)) {
            Files.createDirectories(outputPath);
        }

        Path jwkPath = outputPath.resolve("jwk-public-key.json");
        Path privateKeyPath = outputPath.resolve(appId + "-private-key.pem");

        Files.writeString(jwkPath, jwkSet);
        Files.writeString(privateKeyPath, privateKeyPem);

        log.info("  - Public JWK saved to: {}", jwkPath.toAbsolutePath());
        log.info("  - Private Key PEM saved to: {}", privateKeyPath.toAbsolutePath());

        return new KeyArtifacts(jwkSet, privateKeyPem, privateKeyBase64, publicKeyBase64);
    }

    /**
     * Generates a JWKS.json example with the app ID and JWK set.
     *
     * @param appId  The application ID.
     * @param jwkSet The JWK set as a JSON string.
     * @return A formatted JWKS.json example.
     * @throws IOException if there is an error parsing the JSON.
     */
    public static String generateJwksJsonExample(String appId, String jwkSet) throws IOException {
        ObjectNode jwksJson = objectMapper.createObjectNode();
        ObjectNode appNode = jwksJson.putObject(appId);
        
        // Parse the JWK set and extract the keys array
        ObjectNode jwkSetNode = (ObjectNode) objectMapper.readTree(jwkSet);
        ArrayNode keysArray = (ArrayNode) jwkSetNode.get("keys");
        
        // For each key in the keys array, extract the kid and create an entry in the app node
        for (int i = 0; i < keysArray.size(); i++) {
            ObjectNode jwk = (ObjectNode) keysArray.get(i);
            String kid = jwk.get("kid").asText();
            appNode.set(kid, jwk);
        }
        
        return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(jwksJson);
    }
/**
 * Generates a PEM-encoded private key (PKCS#8 format).
 *
 * @param privateKey RSA private key.
 * @return PEM-encoded private key as a string.
 */
public static String generatePrivateKeyPem(PrivateKey privateKey) {
    // Use MIME encoder to get the Base64 string with standard line breaks
    String base64encoded = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(privateKey.getEncoded());

    return "-----BEGIN PRIVATE KEY-----\n" +
            base64encoded +
            "\n-----END PRIVATE KEY-----\n";
}


}