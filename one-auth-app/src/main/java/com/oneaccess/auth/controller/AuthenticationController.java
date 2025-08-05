package com.oneaccess.auth.controller;

import com.oneaccess.auth.security.UserJWTKeyProvider;
import com.oneaccess.auth.security.oauth.OAuth2AuthenticationSuccessHandler;
import com.oneaccess.auth.services.auth.AuthenticationService;
import com.oneaccess.auth.services.auth.dtos.AuthResponseDTO;
import com.oneaccess.auth.services.auth.dtos.LoginRequestDTO;
import com.oneaccess.auth.services.auth.dtos.RegisterUserRequestDTO;
import com.oneaccess.auth.services.auth.dtos.TokenExchangeRequestDTO;
import com.oneaccess.auth.services.common.GenericResponseDTO;
import com.oneaccess.auth.services.webapp.user.UserService;
import com.oneaccess.auth.services.webapp.user.dto.ForgotPasswordRequestDTO;
import com.oneaccess.auth.services.webapp.user.dto.ResetPasswordRequestDTO;
import com.oneaccess.auth.services.webapp.user.dto.UserDTO;
import com.oneaccess.auth.services.webapp.user.dto.VerifyEmailRequestDTO;
import com.oneaccess.authjar.user.CustomUserDetails;
import com.oneaccess.authjar.user.OneAuthUser;
import io.micrometer.common.util.StringUtils;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.lang.StringUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Slf4j
@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final UserService userService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final UserJWTKeyProvider userJWTKeyProvider;

    public AuthenticationController(AuthenticationService authenticationService,
                                    UserService userService,
                                    OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler,
                                    UserJWTKeyProvider userJWTKeyProvider) {
        this.authenticationService = authenticationService;
        this.userService = userService;
        this.oAuth2AuthenticationSuccessHandler = oAuth2AuthenticationSuccessHandler;
        this.userJWTKeyProvider = userJWTKeyProvider;
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestParam(name = "original_request_uri", required = false) String originalRequestUri, @RequestBody LoginRequestDTO loginRequest) {
        log.info("Authentication API: loginUser: ", loginRequest.getEmail());
        AuthResponseDTO authResponseDTO = authenticationService.loginUser(loginRequest);
        String requestUri = StringUtils.isBlank(originalRequestUri) ? "/" : originalRequestUri;
        var response = extractUserInfo(authResponseDTO.getOneAuthUser(), authResponseDTO.getAccessToken(), "refreshToken", requestUri);
        log.info("Token exchange successful for user: {}", loginRequest.getEmail());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegisterUserRequestDTO registerUserRequestDTO) {
        log.info("Authentication API: registerUser: ", registerUserRequestDTO.getEmail());
        UserDTO userDTO = authenticationService.registerUser(registerUserRequestDTO);
        return new ResponseEntity<>(userDTO, HttpStatus.OK);
    }

    @GetMapping("/resend-verification-email")
    public ResponseEntity<?> resendVerificationEmail(@RequestParam("email") String email) {
        log.info("Authentication API: resendVerificationEmail: ", email);
        GenericResponseDTO<Boolean> resendVerificationEmailStatus = userService.sendVerificationEmail(email);
        return new ResponseEntity<>(resendVerificationEmailStatus, HttpStatus.OK);
    }

    @PostMapping("/check-verification-code")
    public ResponseEntity<?> checkVerificationCode(@RequestBody VerifyEmailRequestDTO verifyEmailRequestDTO) {
        log.info("Authentication API: checkVerificationCode: ", verifyEmailRequestDTO.getEmail());
        GenericResponseDTO<Boolean> checkVerificationCodeStatus = userService.verifyEmailAddress(verifyEmailRequestDTO);
        return new ResponseEntity<>(checkVerificationCodeStatus, HttpStatus.OK);
    }

    @PostMapping("/send-forgot-password")
    public ResponseEntity<?> sendResetPasswordEmail(@RequestBody ForgotPasswordRequestDTO forgotPasswordRequestDTO) {
        log.info("Authentication API: sendResetPasswordEmail: ", forgotPasswordRequestDTO.getEmail());
        GenericResponseDTO<Boolean> resendVerificationEmailStatus = userService.sendResetPasswordEmail(forgotPasswordRequestDTO);
        return new ResponseEntity<>(resendVerificationEmailStatus, HttpStatus.OK);
    }

    @PostMapping("/process-password-reset")
    public ResponseEntity<?> verifyAndProcessPasswordResetRequest(@RequestBody ResetPasswordRequestDTO resetPasswordRequestDTO) {
        log.info("Authentication API: verifyAndProcessPasswordResetRequest: ", resetPasswordRequestDTO.getEmail());
        GenericResponseDTO<Boolean> checkVerificationCodeStatus = userService.verifyAndProcessPasswordResetRequest(resetPasswordRequestDTO);
        return new ResponseEntity<>(checkVerificationCodeStatus, HttpStatus.OK);
    }

    /**
     * Token exchange endpoint for PKCE OAuth2 flow.
     * Exchanges authorization code for JWT tokens with PKCE validation.
     * Uses secure flow: peek → validate → consume to prevent code verifier leakage.
     */
    @PostMapping("/exchange")
    public ResponseEntity<?> exchangeCodeForToken(@Valid @RequestBody TokenExchangeRequestDTO request) {
        log.info("Authentication API: exchangeCodeForToken for code: {}", 
                request.getCode() != null ? request.getCode().substring(0, Math.min(request.getCode().length(), 10)) + "..." : "null");
        log.debug("Token exchange request - redirectUri: {}, hasCodeVerifier: {}", 
                 request.getRedirectUri(), request.getCodeVerifier() != null);
        
        try {
            // Step 1: Peek at authorization code without consuming it
            OAuth2AuthenticationSuccessHandler.AuthCodeData authCodeData = 
                oAuth2AuthenticationSuccessHandler.peekAuthorizationCode(request.getCode());
            
            if (authCodeData == null) {
                log.warn("Invalid or expired authorization code during peek: {}", request.getCode());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid or expired authorization code");
            }
            
            log.debug("Authorization code peek successful - frontendProvidedPkce: {}, hasCodeChallenge: {}", 
                     authCodeData.frontendProvidedPkce, authCodeData.codeChallenge != null);
            
            // Step 2: Validate PKCE code verifier BEFORE consuming the code
            if (authCodeData.frontendProvidedPkce) {
                // For frontend-provided PKCE, validate the frontend's verifier against stored challenge
                if (authCodeData.codeChallenge == null) {
                    log.warn("Frontend PKCE expected but no code challenge found for code: {}", request.getCode());
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("PKCE code challenge not found");
                }
                
                if (!validatePKCE(request.getCodeVerifier(), authCodeData.codeChallenge)) {
                    log.warn("Frontend PKCE validation failed for code: {} - challenge mismatch", request.getCode());
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("PKCE validation failed");
                }
                log.debug("Frontend PKCE validation successful");
            } else {
                // For server-generated PKCE, validate stored verifier against stored challenge  
                if (authCodeData.codeVerifier == null || authCodeData.codeChallenge == null) {
                    log.warn("Server PKCE expected but missing verifier or challenge for code: {}", request.getCode());
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("PKCE parameters missing");
                }
                
                if (!validatePKCE(authCodeData.codeVerifier, authCodeData.codeChallenge)) {
                    log.warn("Server PKCE validation failed for code: {} - challenge mismatch", request.getCode());
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("PKCE validation failed");
                }
                log.debug("Server PKCE validation successful");
            }
            
            // Step 3: Validate redirect URI (optional additional security)
            // Note: This is more of a best practice, OAuth2 spec doesn't require it for token exchange
            log.debug("Redirect URI validation - provided: {}", request.getRedirectUri());
            
            // Step 4: Only now consume the authorization code after all validations pass
            authCodeData = oAuth2AuthenticationSuccessHandler.exchangeAuthorizationCode(request.getCode());
            String originalRequestUri = authCodeData.frontendOriginalRequestUri;

            if (authCodeData == null) {
                log.error("Authorization code was consumed between peek and exchange - possible race condition for code: {}", request.getCode());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Authorization code already consumed");
            }
            
            // Generate JWT tokens
            CustomUserDetails userDetails = (CustomUserDetails) authCodeData.authentication.getPrincipal();
            String accessToken = userJWTKeyProvider.createUserToken(userDetails);
            
            // For now, we'll use the same token as refresh token
            // In production, you should generate a separate refresh token with longer expiry
            String refreshToken = userJWTKeyProvider.createUserToken(userDetails);
            
            // Build response
            var response = extractUserInfo(userDetails.getOneAuthUser(), accessToken, refreshToken, originalRequestUri);

            log.info("Token exchange successful for user: {}", userDetails.getUserUniqueId());
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Token exchange failed", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Token exchange failed");
        }
    }

    /**
     * Validates PKCE code verifier against the stored code challenge.
     */
    private boolean validatePKCE(String codeVerifier, String storedCodeChallenge) {
        if (codeVerifier == null || storedCodeChallenge == null) {
            return false;
        }
        
        try {
            // Generate code challenge from verifier
            byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(bytes, 0, bytes.length);
            byte[] digest = messageDigest.digest();
            String computedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            
            return storedCodeChallenge.equals(computedChallenge);
            
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to validate PKCE", e);
            return false;
        }
    }

    /**
     * Extracts user information from CustomUserDetails for the response.
     */
    private Object extractUserInfo(OneAuthUser oneAuthUser, String accessToken, String refreshToken, String originalRequestUri) {
        return new Object() {
            public final String token_type = "Bearer";
            public final int expires_in = 3600; // 1 hour
            public final String token = accessToken;
            public final String refresh_token = refreshToken;
            public final OneAuthUser auth_user = oneAuthUser;
            public final String original_request_uri = originalRequestUri;
        };
    }
}
