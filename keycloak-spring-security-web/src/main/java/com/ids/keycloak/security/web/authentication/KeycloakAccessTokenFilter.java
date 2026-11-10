package com.ids.keycloak.security.web.authentication;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ids.keycloak.security.authentication.KeycloakPrincipalConverter;
import com.ids.keycloak.security.error.KeycloakErrorCode;
import com.ids.keycloak.security.event.KeycloakSessionEndReason;
import com.ids.keycloak.security.token.AccessTokenValidationResult;
import com.ids.keycloak.security.token.KeycloakAccessTokenValidator;
import com.ids.keycloak.security.web.cookie.KeycloakCookie;
import com.ids.keycloak.security.web.cookie.KeycloakCookieWriter;
import com.ids.keycloak.security.web.error.KeycloakErrorResponseWriter;
import com.ids.keycloak.security.web.logout.KeycloakLocalLogoutHandler;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 요청 인증 (V3-08, 01 설계 4-2): at 쿠키의 액세스 토큰을 로컬에서 검증해 보안 컨텍스트에 넣는다. Keycloak도 DB도 부르지 않는다.
 * <ul>
 *   <li>통과: {@link KeycloakPrincipalConverter}가 만든 인증을 넣는다</li>
 *   <li>at 쿠키 없음·만료: 로그인 안 한 채로 넘긴다 (갱신은 {@link #onAccessTokenMissing}·{@link #onAccessTokenExpired}, #85)</li>
 *   <li>그 밖의 검증 실패: 로컬 로그아웃(행·쿠키 삭제, 사유 {@code invalid_token}) 뒤 로그인 안 한 채로 넘긴다. 갱신하지 않는다</li>
 *   <li>서명 키(JWKS)를 못 받음: 토큰 탓이 아니므로 로그아웃하지 않고 503</li>
 * </ul>
 * 로그인 필요 여부는 뒤의 인가가 정한다(permit-all 경로는 로그인 없이 통과). HttpSession은 쓰지 않는다.
 * 앞에서 이미 인증이 세워졌으면(다른 방식) 건드리지 않는다.
 */
public class KeycloakAccessTokenFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(KeycloakAccessTokenFilter.class);

    private final KeycloakAccessTokenValidator validator;
    private final KeycloakPrincipalConverter converter;
    private final KeycloakCookieWriter cookies;
    private final KeycloakLocalLogoutHandler localLogout;
    private final KeycloakErrorResponseWriter errors;

    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    public KeycloakAccessTokenFilter(KeycloakAccessTokenValidator validator, KeycloakPrincipalConverter converter,
                                     KeycloakCookieWriter cookies, KeycloakLocalLogoutHandler localLogout,
                                     KeycloakErrorResponseWriter errors) {
        this.validator = Objects.requireNonNull(validator);
        this.converter = Objects.requireNonNull(converter);
        this.cookies = Objects.requireNonNull(cookies);
        this.localLogout = Objects.requireNonNull(localLogout);
        this.errors = Objects.requireNonNull(errors);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws ServletException, IOException {
        if (alreadyAuthenticated()) {
            chain.doFilter(request, response);
            return;
        }
        Optional<String> accessToken = cookies.read(request, KeycloakCookie.ACCESS_TOKEN);
        if (accessToken.isEmpty()) {
            onAccessTokenMissing(request, response, chain);
            return;
        }
        AccessTokenValidationResult result = validator.validate(accessToken.get());
        switch (result.status()) {
            case VALID -> {
                authenticate(request, response, result.jwt());
                chain.doFilter(request, response);
            }
            case EXPIRED -> onAccessTokenExpired(request, response, chain, result);
            case INVALID -> onAccessTokenInvalid(request, response, chain, result);
            case UNAVAILABLE -> onKeycloakUnavailable(request, response, result);
        }
    }

    /** at 쿠키가 없다. 기본: 로그인 안 한 채로 넘긴다. */
    protected void onAccessTokenMissing(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws ServletException, IOException {
        chain.doFilter(request, response);
    }

    /** 만료만 걸렸다. 기본: 로그인 안 한 채로 넘긴다. */
    protected void onAccessTokenExpired(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                        AccessTokenValidationResult result) throws ServletException, IOException {
        log.debug("[KSS] 액세스 토큰이 만료됐습니다: {}", result.reason());
        chain.doFilter(request, response);
    }

    /** 만료 말고 다른 검증 실패. 로컬 로그아웃 뒤 로그인 안 한 채로 넘긴다 (REQ-04). */
    protected void onAccessTokenInvalid(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                        AccessTokenValidationResult result) throws ServletException, IOException {
        log.info("[KSS] 액세스 토큰 검증 실패, 로컬 로그아웃합니다: {}", result.reason());
        localLogout.logout(request, response, KeycloakSessionEndReason.INVALID_TOKEN);
        chain.doFilter(request, response);
    }

    /** JWKS를 받지 못했다. 로그아웃하지 않고 503. */
    protected void onKeycloakUnavailable(HttpServletRequest request, HttpServletResponse response, AccessTokenValidationResult result)
        throws IOException {
        log.warn("[KSS] Keycloak 서명 키를 받지 못해 요청을 처리하지 못했습니다: {}", result.reason());
        errors.write(request, response, KeycloakErrorCode.KEYCLOAK_UNAVAILABLE);
    }

    /** 검증한 토큰으로 인증을 만들어 보안 컨텍스트(요청 안에서만)에 넣는다. */
    protected void authenticate(HttpServletRequest request, HttpServletResponse response, Jwt accessToken) {
        Authentication authentication;
        try {
            authentication = converter.convert(accessToken);
        } catch (AuthenticationException e) {
            log.debug("[KSS] 인증 변환이 거절했습니다: {}", e.getMessage());
            return;
        }
        if (authentication == null) {
            return;
        }
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);
    }

    private boolean alreadyAuthenticated() {
        Authentication existing = securityContextHolderStrategy.getContext().getAuthentication();
        return existing != null && existing.isAuthenticated() && !(existing instanceof AnonymousAuthenticationToken);
    }

    public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
        this.securityContextHolderStrategy = Objects.requireNonNull(securityContextHolderStrategy);
    }

    public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
        this.securityContextRepository = Objects.requireNonNull(securityContextRepository);
    }
}
