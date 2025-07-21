package com.oneaccess.auth.security;

import com.oneaccess.auth.config.AppProperties;
import com.oneaccess.auth.entities.UserEntity;
import com.oneaccess.auth.services.webapp.user.UserMapper;
import com.oneaccess.auth.services.webapp.user.dto.UserDTO;
import com.oneaccess.auth.utils.AppUtils;
import io.jsonwebtoken.*;
import io.jsonwebtoken.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * Util based class that generates JWT token, create Authentication Object from token string and Validates token string
 */
@Component
@Slf4j
public class JWTTokenProvider {

    private static final String HEADER_AUTHORIZATION = HttpHeaders.AUTHORIZATION;
    private static final String BEARER_TOKEN_START = "Bearer ";

    // Initialized from configuration properties
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private long validityInMilliseconds;

    @Autowired
    private AppProperties appProperties;

    @Autowired
    private UserMapper userMapper;

    @PostConstruct
    protected void init() {
        try {
            String privateKeyB64 = appProperties.getJwt().getPrivateKeyB64();
            String publicKeyB64 = appProperties.getJwt().getPublicKeyB64();
            if (StringUtils.hasText(privateKeyB64) && StringUtils.hasText(publicKeyB64) ) {
                log.info("Loading RSA key pair from Base64 properties");
                privateKey = SecurityUtils.loadPrivateKey(privateKeyB64);
                publicKey = SecurityUtils.loadPublicKey(publicKeyB64);
            } else {
                log.warn("--- DEV MODE --- privateKeyB64 not set. Generating new RSA key pair");
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                privateKey = kp.getPrivate();
                publicKey = kp.getPublic();
            }
        } catch (Exception e) {
            throw new IllegalStateException("Unable to load or generate JWT keys", e);
        }
        validityInMilliseconds = appProperties.getJwt().getExpiration().toMillis();
    }

    public String createJWTToken(Authentication authentication) {
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
        Set<String> authoritiesSet = AppSecurityUtils.convertGrantedAuthorityListToRolesSet(customUserDetails.getAuthorities());

        String authoritiesJsonValue = AppUtils.toJson(authoritiesSet);
        String attributesJsonValue = AppUtils.toJson(customUserDetails.getAttributes());
        String userJsonValue = AppUtils.toJson(userMapper.toDto(customUserDetails.getUserEntity()));

        Claims claims = Jwts.claims().setSubject(customUserDetails.getEmail());
        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put("email", customUserDetails.getEmail());
        claimsMap.put("user", userJsonValue);
        claimsMap.put("authorities", authoritiesJsonValue);
        claimsMap.put("attributes", attributesJsonValue);
        claims.putAll(claimsMap);

        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()
                .setSubject(customUserDetails.getEmail())
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }

    public Authentication getAuthenticationFromToken(String token) {
        Claims body = Jwts.parser()
                .setSigningKey(publicKey)
                .parseClaimsJws(token)
                .getBody();

        // Parsing Claims Data
        String email = (String) body.get("email");
        UserDTO userDTO = AppUtils.fromJson(body.get("user").toString(), UserDTO.class);
        UserEntity userEntity = userMapper.toEntity(userDTO);
        Set<String> authoritiesSet = AppUtils.fromJson(body.get("authorities").toString(), (Class<Set<String>>) ((Class) Set.class));
        Collection<? extends GrantedAuthority> grantedAuthorities = AppSecurityUtils.convertRolesSetToGrantedAuthorityList(authoritiesSet);
        Map<String, Object> attributes = AppUtils.fromJson(body.get("attributes").toString(), (Class<Map<String, Object>>) (Class) Map.class);

        // Setting Principle Object

        CustomUserDetails customUserDetails = CustomUserDetails.buildWithAuthAttributesAndAuthorities(userEntity, grantedAuthorities, attributes);
        customUserDetails.setAttributes(attributes);
        return new UsernamePasswordAuthenticationToken(customUserDetails, "", customUserDetails.getAuthorities());
    }

    public String getBearerTokenFromRequestHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader(HEADER_AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_TOKEN_START)) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }

    public boolean validateJWTToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token);
            if (claims.getBody().getExpiration().before(new Date())) {
                return false;
            }
            return true;
        } catch (SignatureException e) {
            log.info("Invalid JWT signature.");
            log.trace("Invalid JWT signature trace: {}", e);
        } catch (MalformedJwtException e) {
            log.info("Invalid JWT token.");
            log.trace("Invalid JWT token trace: {}", e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT token.");
            log.trace("Expired JWT token trace: {}", e);
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT token.");
            log.trace("Unsupported JWT token trace: {}", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT token compact of handler are invalid.");
            log.trace("JWT token compact of handler are invalid trace: {}", e);
        }
        return false;
    }

}
