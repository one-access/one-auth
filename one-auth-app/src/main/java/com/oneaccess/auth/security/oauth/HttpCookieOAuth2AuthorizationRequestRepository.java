package com.oneaccess.auth.security.oauth;

import com.oneaccess.auth.utils.AppWebUtils;
import com.oneaccess.authjar.utils.AuthCommonUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Optional;

/**
 * Cookie based repository for storing Authorization requests
 * <p>
 * By default, Spring OAuth2 uses HttpSessionOAuth2AuthorizationRequestRepository to save
 * the authorization request. But, since our service is stateless, we can't save it in the session.
 * We'll use cookie instead.
 */
@Slf4j
@Component
public class HttpCookieOAuth2AuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    public static final String OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request";
    public static final String REDIRECT_URI_PARAM_COOKIE_NAME = "redirect_uri";
    public static final String ORIGINAL_REQUEST_URI_PARAM_COOKIE_NAME = "original_request_uri";
    public static final String PKCE_CODE_VERIFIER_COOKIE_NAME = "pkce_code_verifier";
    public static final String PKCE_CODE_CHALLENGE_COOKIE_NAME = "pkce_code_challenge";
    public static final String FRONTEND_STATE_COOKIE_NAME = "frontend_state";
    private static final int COOKIE_EXPIRE_SECONDS = 180;

    /**
     * Load authorization request from cookie
     */
    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {

        return AppWebUtils.getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
                .filter(s -> StringUtils.hasText(s.getValue()))
                .map(s -> AuthCommonUtil.<OAuth2AuthorizationRequest>deserialize(s.getValue()))
                .orElse(null);
    }

    /**
     * Save authorization request in cookie
     */
    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest,
                                         HttpServletRequest request,
                                         HttpServletResponse response) {

        if (authorizationRequest == null) {
            removeAuthorizationRequest(request, response);
            return;
        }

        // Setting up authorizationRequest COOKIE, redirectUri COOKIE, originalRequestUri COOKIE, and PKCE COOKIES
        String redirectUri = request.getParameter(REDIRECT_URI_PARAM_COOKIE_NAME);
        String originalRequestUri = request.getParameter(ORIGINAL_REQUEST_URI_PARAM_COOKIE_NAME);
        AppWebUtils.addCookie(response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME, AuthCommonUtil.serialize(authorizationRequest));
        
        if (StringUtils.hasText(redirectUri)) {
            AppWebUtils.addCookie(response, REDIRECT_URI_PARAM_COOKIE_NAME, redirectUri);
        }
        if (StringUtils.hasText(originalRequestUri)) {
            AppWebUtils.addCookie(response, ORIGINAL_REQUEST_URI_PARAM_COOKIE_NAME, originalRequestUri);
        }
        
        // Store frontend PKCE challenge from authorization request attributes
        // Note: We only store the challenge, not the verifier (frontend keeps the verifier)
        String frontendCodeChallenge = (String) authorizationRequest.getAttributes().get("frontend_code_challenge");
        Boolean frontendProvidedPkce = (Boolean) authorizationRequest.getAttributes().get("frontend_provided_pkce");
        
        if (Boolean.TRUE.equals(frontendProvidedPkce) && StringUtils.hasText(frontendCodeChallenge)) {
            AppWebUtils.addCookie(response, PKCE_CODE_CHALLENGE_COOKIE_NAME, frontendCodeChallenge);
            log.debug("Stored frontend PKCE challenge in cookie for /auth/exchange validation");
        }
        
        // Store frontend state from authorization request attributes
        String frontendState = (String) authorizationRequest.getAttributes().get("frontend_state");
        if (StringUtils.hasText(frontendState)) {
            AppWebUtils.addCookie(response, FRONTEND_STATE_COOKIE_NAME, frontendState);
            log.debug("Stored frontend state in cookie for later retrieval");
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = loadAuthorizationRequest(request);
        if (oAuth2AuthorizationRequest != null) {
            AppWebUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
        }
        return oAuth2AuthorizationRequest;
    }

    public void removeAllAuthorizationRequestCookies(HttpServletRequest request, HttpServletResponse response) {
        AppWebUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
        AppWebUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME);
        AppWebUtils.deleteCookie(request, response, ORIGINAL_REQUEST_URI_PARAM_COOKIE_NAME);
        AppWebUtils.deleteCookie(request, response, PKCE_CODE_VERIFIER_COOKIE_NAME);
        AppWebUtils.deleteCookie(request, response, PKCE_CODE_CHALLENGE_COOKIE_NAME);
        AppWebUtils.deleteCookie(request, response, FRONTEND_STATE_COOKIE_NAME);
    }

    /**
     * Retrieves the PKCE code verifier from cookies.
     */
    public String getCodeVerifier(HttpServletRequest request) {
        return AppWebUtils.getCookie(request, PKCE_CODE_VERIFIER_COOKIE_NAME)
                .map(cookie -> cookie.getValue())
                .orElse(null);
    }

    /**
     * Retrieves the PKCE code challenge from cookies.
     */
    public String getCodeChallenge(HttpServletRequest request) {
        return AppWebUtils.getCookie(request, PKCE_CODE_CHALLENGE_COOKIE_NAME)
                .map(cookie -> cookie.getValue())
                .orElse(null);
    }

    /**
     * Retrieves the frontend state from cookies.
     */
    public String getFrontendState(HttpServletRequest request) {
        return AppWebUtils.getCookie(request, FRONTEND_STATE_COOKIE_NAME)
                .map(cookie -> cookie.getValue())
                .orElse(null);
    }

    private Optional<String> getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    return Optional.of(cookie.getValue());
                }
            }
        }
        return Optional.empty();
    }
}
