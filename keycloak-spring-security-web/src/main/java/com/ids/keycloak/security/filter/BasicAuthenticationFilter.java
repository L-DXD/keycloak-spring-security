package com.ids.keycloak.security.filter;

import com.ids.keycloak.security.authentication.BasicAuthenticationToken;
import com.ids.keycloak.security.ratelimit.AuthenticationEventLogger;
import com.ids.keycloak.security.util.ClientIpResolver;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * {@code Authorization: Basic} 헤더를 파싱하여 Keycloak Direct Access Grants 인증을 시도하는 필터입니다.
 * <p>
 * Basic 헤더가 없으면 다음 필터로 넘기고 (기존 OIDC 쿠키 인증 흐름),
 * Basic 헤더가 있으면 credentials를 디코딩하여 {@link BasicAuthenticationToken}을 생성하고
 * {@link AuthenticationManager}에 인증을 위임합니다.
 * </p>
 * <p>
 * Basic Auth는 stateless로 동작합니다. 매 요청마다 인증하며 세션을 생성하지 않습니다.
 * </p>
 * <p>
 * Basic 인증 시도(형식 오류/자격증명 실패/Base64 디코딩 실패)가 실패해도, 이 필터가 실행되기 전에
 * 이미 다른 인증(선행 필터·핸드오프)이 SecurityContext에 세워져 있다면 그 인증을 지우지 않습니다.
 * {@link #clearContextUnlessAlreadyAuthenticated()} 참고.
 * </p>
 */
@Slf4j
public class BasicAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BASIC_PREFIX = "Basic ";
    private static final String X_FORWARDED_FOR_HEADER = "X-Forwarded-For";

    private final AuthenticationManager authenticationManager;

    /**
     * X-Forwarded-For 헤더에서 신뢰할 프록시 홉 수.
     * 기본값 0: XFF 헤더를 완전히 무시하고 TCP 연결 원격 주소를 사용합니다(보안상 기본값).
     * {@code KeycloakHttpConfigurer}에서 {@code keycloak.security.trusted-proxy-count} 값을 주입합니다.
     * {@link ClientIpResolver} 참고.
     */
    private int trustedProxyCount = 0;

    public BasicAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * 신뢰 프록시 홉 수를 설정합니다.
     *
     * @param trustedProxyCount 신뢰 프록시 홉 수 (0: XFF 무시, -1: 레거시 동작, N>0: 홉 기반 파싱)
     */
    public void setTrustedProxyCount(int trustedProxyCount) {
        this.trustedProxyCount = trustedProxyCount;
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {

        String authHeader = request.getHeader(AUTHORIZATION_HEADER);

        // Basic 헤더가 없으면 다음 필터로 넘김 (OIDC 쿠키 흐름)
        if (authHeader == null || !authHeader.startsWith(BASIC_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("[BasicAuthFilter] Authorization: Basic 헤더 감지. 인증 시도.");

        String parsedUsername = null;
        try {
            // Base64 디코딩 → username:password 분리
            String base64Credentials = authHeader.substring(BASIC_PREFIX.length()).trim();
            String credentials = new String(Base64.getDecoder().decode(base64Credentials), StandardCharsets.UTF_8);
            int colonIndex = credentials.indexOf(':');

            if (colonIndex < 0) {
                log.warn("[BasicAuthFilter] 잘못된 Basic 인증 형식 (콜론 없음).");
                clearContextUnlessAlreadyAuthenticated();
                filterChain.doFilter(request, response);
                return;
            }

            parsedUsername = credentials.substring(0, colonIndex);
            String password = credentials.substring(colonIndex + 1);

            // BasicAuthenticationToken 생성 및 인증 시도
            BasicAuthenticationToken authRequest = new BasicAuthenticationToken(parsedUsername, password);
            Authentication result = authenticationManager.authenticate(authRequest);

            // 인증 성공 → SecurityContext에 설정
            SecurityContextHolder.getContext().setAuthentication(result);
            log.debug("[BasicAuthFilter] Basic Auth 인증 성공: {}", result.getName());
            AuthenticationEventLogger.logSuccess(
                AuthenticationEventLogger.METHOD_BASIC, getClientIp(request), parsedUsername);

        } catch (AuthenticationException | com.ids.keycloak.security.exception.KeycloakSecurityException e) {
            clearContextUnlessAlreadyAuthenticated();
            log.warn("[BasicAuthFilter] Basic Auth 인증 실패: {}", e.getMessage());
            AuthenticationEventLogger.logFailure(
                AuthenticationEventLogger.METHOD_BASIC, getClientIp(request), parsedUsername, "invalid_credentials");
            // 인증 실패 시에도 filterChain을 진행하여 EntryPoint가 401 처리
        } catch (IllegalArgumentException e) {
            clearContextUnlessAlreadyAuthenticated();
            log.warn("[BasicAuthFilter] Base64 디코딩 실패: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private String getClientIp(HttpServletRequest request) {
        return ClientIpResolver.resolve(
            request.getHeader(X_FORWARDED_FOR_HEADER),
            request.getRemoteAddr(),
            trustedProxyCount
        );
    }

    /**
     * Basic 인증 시도가 실패했을 때만 SecurityContext를 비웁니다.
     * <p>
     * 앞단 필터(예: 요청 파이프라인 상 이 필터보다 먼저 실행되는 인증 필터, 혹은 선행 핸드오프 필터)가
     * 이미 유효한 인증을 세워둔 상태라면, 이 필터에서의 Basic 인증 형식 오류·실패는 그 인증과 무관한
     * 시도이므로 기존 인증을 지우지 않습니다. {@code KeycloakAuthenticationFilter#handleOidcCookieAuth}의
     * "이미 인증됨" 판정(비-Anonymous {@link Authentication} 존재 여부)과 동일한 기준을 사용합니다.
     * </p>
     */
    private void clearContextUnlessAlreadyAuthenticated() {
        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
        boolean alreadyAuthenticated = existingAuth != null
            && existingAuth.isAuthenticated()
            && !(existingAuth instanceof AnonymousAuthenticationToken);
        if (alreadyAuthenticated) {
            log.debug(
                "[BasicAuthFilter] 이미 인증된 사용자 '{}'가 있어 Basic 인증 실패에도 SecurityContext를 유지합니다.",
                existingAuth.getName());
            return;
        }
        SecurityContextHolder.clearContext();
    }
}
