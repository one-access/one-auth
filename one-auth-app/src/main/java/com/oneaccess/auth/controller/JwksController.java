package com.oneaccess.auth.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

@Slf4j
@RestController
public class JwksController {

    private final Map<String, Object> serviceJwks; // All service keys with appId field

    /**
     * Constructor to load both service and user JWKS files at application startup.
     * Keys contain appId field for security validation.
     * It uses constructor injection, a Spring best practice.
     *
     * @param objectMapper         The Jackson ObjectMapper to parse the JSON.
     * @param serviceJwksResource  The resource pointing to the jwks.json file (service keys with appId).
     * @throws IOException if any JWKS file cannot be read or parsed, causing application startup to fail.
     */
    public JwksController(ObjectMapper objectMapper, 
                         @Value("classpath:/.well-known/jwks.json") Resource serviceJwksResource) throws IOException {
        
        // Load service keys (all service public keys with appId field)
        try (InputStream inputStream = serviceJwksResource.getInputStream()) {
            this.serviceJwks = objectMapper.readValue(inputStream, new TypeReference<>() {});
            log.info("Successfully loaded service JWKS from {}", serviceJwksResource.getURI());
        } catch (IOException e) {
            log.error("Failed to load or parse service JWKS file from: {}", serviceJwksResource, e);
            throw new IOException("Failed to initialize JwksController due to missing or invalid service JWKS file.", e);
        }
    }

    /**
     * Serves the JSON Web Key Set (JWKS) with appId-based filtering.
     * The JWKS is pre-loaded from static files for performance and simplicity.
     *
     * @param appId specific appId (e.g., "payment-service"), returns keys for that service only.
     * @return A ResponseEntity containing the JWKS.
     */
    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, List<?>>> getJwks(@RequestParam(required = true) String appId) {
        log.debug("Serving service keys for appId: {}", appId);
        Map<String, List<?>> filteredServiceKeys = (Map<String, List<?>>) serviceJwks.get(appId);
        if (filteredServiceKeys == null) {
            return (ResponseEntity<Map<String, List<?>>>) Map.of("keys", List.of());
        }
        return ResponseEntity.ok(filteredServiceKeys);
    }

}