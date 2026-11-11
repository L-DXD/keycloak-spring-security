package com.ids.keycloak.security.web.logout;

import java.io.IOException;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * back-channel 로그아웃 주소에서 형식이 틀린 {@code logout_token}을 400으로 돌린다 (BCL-02).
 * <p>
 * Spring Security 7.1은 서명이 맞지만 필수 클레임({@code events} 등)이 빠진 토큰에서 {@link AuthenticationServiceException}
 * (원인 {@link IllegalArgumentException})을 던져 500이 된다. 규격은 잘못된 logout_token에 400을 요구하고, 인증 없이 부를 수 있는
 * 주소에서 500(ERROR 로그)이 쌓이지 않게 이 경우만 400 {@code invalid_request}로 바꾼다. 그 밖의 예외는 그대로 둔다.
 */
public class KeycloakBackChannelLogoutErrorFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(KeycloakBackChannelLogoutErrorFilter.class);
    private static final String SPEC = "https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation";

    private final RequestMatcher backChannel;
    private final OAuth2ErrorHttpMessageConverter errors = new OAuth2ErrorHttpMessageConverter();

    public KeycloakBackChannelLogoutErrorFilter(RequestMatcher backChannel) {
        this.backChannel = Objects.requireNonNull(backChannel);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !backChannel.matches(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws ServletException, IOException {
        try {
            chain.doFilter(request, response);
        } catch (AuthenticationServiceException e) {
            if (!(e.getCause() instanceof IllegalArgumentException) || response.isCommitted()) {
                throw e;
            }
            log.debug("[KSS] 형식이 틀린 logout_token을 거절합니다: {}", e.getMessage());
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
            errors.write(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, e.getMessage(), SPEC), MediaType.APPLICATION_JSON,
                new ServletServerHttpResponse(response));
        }
    }
}
