package com.oneaccess.auth.security.oauth.common;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Base64;
import java.util.Optional;

/**
 * Cookie based repository for storing Authorization requests
 * <p>
 * By default, Spring OAuth2 uses HttpSessionOAuth2AuthorizationRequestRepository to save
 * the authorization request. But, since our service is stateless, we can't save it in the session.
 * We'll use cookie instead.
 */
@Component
public class HttpCookieOAuth2AuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    public static final String OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request";
    public static final String REDIRECT_URI_PARAM_COOKIE_NAME = "redirect_uri";
    public static final String ORIGINAL_REQUEST_URI_PARAM_COOKIE_NAME = "original_request_uri";
    private static final int COOKIE_EXPIRE_SECONDS = 180;

    /**
     * Load authorization request from cookie
     */
    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {

        return getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
                .map(this::deserialize)
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

            removeAuthorizationRequestCookies(request, response);
            return;
        }

        // Setting up authorizationRequest COOKIE, redirectUri COOKIE and originalRequestUri COOKIE
        String redirectUri = request.getParameter(REDIRECT_URI_PARAM_COOKIE_NAME);
        String originalRequestUri = request.getParameter(ORIGINAL_REQUEST_URI_PARAM_COOKIE_NAME);
        addCookie(response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME, serialize(authorizationRequest), COOKIE_EXPIRE_SECONDS);
        if (StringUtils.hasText(redirectUri)) {
            addCookie(response, REDIRECT_URI_PARAM_COOKIE_NAME, redirectUri, COOKIE_EXPIRE_SECONDS);
        }
        if (StringUtils.hasText(originalRequestUri)) {
            addCookie(response, ORIGINAL_REQUEST_URI_PARAM_COOKIE_NAME, originalRequestUri, COOKIE_EXPIRE_SECONDS);
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        OAuth2AuthorizationRequest originalRequest = loadAuthorizationRequest(request);
        if (originalRequest != null) {
            removeAuthorizationRequestCookies(request, response);
        }
        return originalRequest;
    }

    public void removeAuthorizationRequestCookies(HttpServletRequest request,
                                                  HttpServletResponse response) {
        removeCookies(request, response);
    }

    private void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }

    private void removeCookies(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME) ||
                    cookie.getName().equals(REDIRECT_URI_PARAM_COOKIE_NAME) ||
                    cookie.getName().equals(ORIGINAL_REQUEST_URI_PARAM_COOKIE_NAME)) {
                    cookie.setValue("");
                    cookie.setPath("/");
                    cookie.setMaxAge(0);
                    response.addCookie(cookie);
                }
            }
        }
    }

    private String serialize(OAuth2AuthorizationRequest authorizationRequest) {
        return Base64.getEncoder().encodeToString(authorizationRequest.toString().getBytes());
    }

    private OAuth2AuthorizationRequest deserialize(String serializedRequest) {
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(serializedRequest);
            String decodedString = new String(decodedBytes);
            // Implement proper deserialization logic here
            return null;
        } catch (Exception e) {
            return null;
        }
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
