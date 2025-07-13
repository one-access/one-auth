package com.oneaccess.auth.springcustomizedstarterexample.security;

import com.oneaccess.auth.springcustomizedstarterexample.config.AppProperties;
import com.oneaccess.auth.springcustomizedstarterexample.entities.UserEntity;
import com.oneaccess.auth.springcustomizedstarterexample.services.webapp.user.UserMapper;
import com.oneaccess.auth.springcustomizedstarterexample.services.webapp.user.dto.UserDTO;
import com.oneaccess.auth.springcustomizedstarterexample.utils.AppUtils;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.*;
import org.springframework.util.ResourceUtils;

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
            String privateKeyPem = Files.readString(
                    ResourceUtils.getFile(appProperties.getJwt().getPrivateKeyPath()).toPath(),
                    StandardCharsets.UTF_8);
            String publicKeyPem = Files.readString(
                    ResourceUtils.getFile(appProperties.getJwt().getPublicKeyPath()).toPath(),
                    StandardCharsets.UTF_8);
            privateKey = loadPrivateKey(privateKeyPem);
            publicKey = loadPublicKey(publicKeyPem);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to load JWT keys", e);
        }
        validityInMilliseconds = appProperties.getJwt().getExpirationMillis();
    }

    private PrivateKey loadPrivateKey(String keyPem) throws Exception {
        String key = keyPem
                .replaceAll("-----BEGIN (.*)-----", "")
                .replaceAll("-----END (.*)-----", "")
                .replaceAll("\n", "");
        byte[] decoded = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private PublicKey loadPublicKey(String keyPem) throws Exception {
        String key = keyPem
                .replaceAll("-----BEGIN (.*)-----", "")
                .replaceAll("-----END (.*)-----", "")
                .replaceAll("\n", "");
        byte[] decoded = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
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
