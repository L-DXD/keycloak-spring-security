package com.ids.keycloak.security.filter;

import com.ids.keycloak.security.authentication.AuthenticationMethod;
import com.ids.keycloak.security.authentication.AuthenticationMethodDetector;
import com.ids.keycloak.security.authentication.KeycloakAuthentication;
import com.ids.keycloak.security.authentication.KeycloakAuthenticationProvider;
import com.ids.keycloak.security.exception.AuthenticationFailedException;
import com.ids.keycloak.security.ratelimit.AuthenticationEventLogger;
import com.ids.keycloak.security.exception.ErrorCode;
import com.ids.keycloak.security.exception.IntrospectionFailedException;
import com.ids.keycloak.security.exception.KeycloakSecurityException;
import com.ids.keycloak.security.exception.RefreshTokenException;
import com.ids.keycloak.security.exception.UserInfoFetchException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.ids.keycloak.security.util.ClientIpResolver;
import com.ids.keycloak.security.util.CookieUtil;
import com.ids.keycloak.security.util.JwtUtil;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * HTTP 요청의 쿠키에서 Keycloak 토큰을 읽어 인증을 시도하는 필터입니다.
 * HTTP Session에서 Refresh Token을 조회하여 토큰 재발급에 사용합니다.
 * <p>
 * OIDC 쿠키 방식 전용 필터입니다. Bearer/Basic/Credential-Login 등 stateless 인증 방식은
 * {@link AuthenticationMethodDetector}가 감지하여 pass-through 처리하므로 세션을 요구하지 않습니다.
 * </p>
 * <p>
 * <b>H-2 트레이드오프:</b> {@code security-context-repository}가 {@code HTTP_SESSION}/
 * {@code DELEGATING}이면, 이 필터는 principal이 {@link KeycloakPrincipal}인 기존 Authentication을
 * 만나도 "이미 인증됨"으로 스킵하지 않고 매 요청 OIDC 쿠키+세션의 Refresh Token으로 재검증한다
 * (stale 권한 방지, 토큰 폐기·만료·재발급 반영). 반대로 이는 HTTP_SESSION 모드를 쓰더라도 이
 * 필터가 담당하는 요청에서는 매 요청 재검증 비용(토큰 파싱/검증, 필요 시 Keycloak 재발급 호출)을
 * 그대로 지불한다는 뜻이다 — HTTP_SESSION 모드가 기대하는 "세션에 있으면 재계산 생략"의 성능 이점은
 * (원리상) 이 라이브러리 자신의 인증에는 적용되지 않으며, 오직 이 필터 체인보다 앞서 실행되는
 * 애플리케이션 자체 핸드오프 필터의 인증을 보존하는 데만 쓰인다.
 * </p>
 */
@Slf4j
public class KeycloakAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final KeycloakAuthenticationProvider authenticationProvider;
    private final KeycloakSessionManager sessionManager;
    private final KeycloakClient keycloakClient;
    private final List<String> skipPaths;
    private final AuthenticationMethodDetector methodDetector;

    /**
     * skipPaths의 Ant 패턴(예: {@code /css/**})을 지원하기 위한 매처(항목 3).
     * <p>
     * {@link org.springframework.security.web.util.matcher.AntPathRequestMatcher}가 아닌 순수
     * 문자열 매칭기({@code org.springframework.util.AntPathMatcher})를 사용한다 —
     * {@code AntPathRequestMatcher}는 기본적으로 {@code getServletPath()}/{@code getPathInfo()}
     * 기반으로 경로를 계산해, 기존에 {@code getRequestURI()}만으로 정확히 동작하던 exact-match
     * skipPaths(토큰 발급 API 등)의 동작을 바꿔버릴 위험이 있다. 순수 문자열 매칭으로 기존
     * {@code getRequestURI()} 기반 동작을 그대로 유지하면서 와일드카드만 추가로 지원한다.
     * </p>
     */
    private static final AntPathMatcher SKIP_PATH_MATCHER = new AntPathMatcher();

    /**
     * 신뢰 프록시 홉 수. 기본값 0 = XFF 무시, remoteAddr 사용.
     * {@link ClientIpResolver} 참고.
     */
    private int trustedProxyCount = 0;

    public KeycloakAuthenticationFilter(
        AuthenticationManager authenticationManager,
        KeycloakAuthenticationProvider authenticationProvider,
        KeycloakSessionManager sessionManager,
        KeycloakClient keycloakClient
    ) {
        this(authenticationManager, authenticationProvider, sessionManager, keycloakClient, List.of());
    }

    public KeycloakAuthenticationFilter(
        AuthenticationManager authenticationManager,
        KeycloakAuthenticationProvider authenticationProvider,
        KeycloakSessionManager sessionManager,
        KeycloakClient keycloakClient,
        List<String> skipPaths
    ) {
        this.authenticationManager = authenticationManager;
        this.authenticationProvider = authenticationProvider;
        this.sessionManager = sessionManager;
        this.keycloakClient = keycloakClient;
        this.skipPaths = skipPaths != null ? skipPaths : List.of();
        this.methodDetector = new AuthenticationMethodDetector(List.of("/api/keycloak/login"));
    }

    /**
     * 명시적 login-paths를 주입받는 생성자입니다.
     * {@code KeycloakHttpConfigurer}에서 properties 기반 login-paths를 전달할 때 사용합니다.
     */
    public KeycloakAuthenticationFilter(
        AuthenticationManager authenticationManager,
        KeycloakAuthenticationProvider authenticationProvider,
        KeycloakSessionManager sessionManager,
        KeycloakClient keycloakClient,
        List<String> skipPaths,
        List<String> loginPaths
    ) {
        this.authenticationManager = authenticationManager;
        this.authenticationProvider = authenticationProvider;
        this.sessionManager = sessionManager;
        this.keycloakClient = keycloakClient;
        this.skipPaths = skipPaths != null ? skipPaths : List.of();
        this.methodDetector = new AuthenticationMethodDetector(loginPaths);
    }

    /**
     * 신뢰 프록시 홉 수를 설정합니다.
     * {@code KeycloakHttpConfigurer}에서 {@code keycloak.security.trusted-proxy-count} 값을 주입합니다.
     *
     * @param trustedProxyCount 신뢰 프록시 홉 수 (0: XFF 무시, -1: 레거시 동작, N>0: 홉 기반 파싱)
     */
    public void setTrustedProxyCount(int trustedProxyCount) {
        this.trustedProxyCount = trustedProxyCount;
    }

    /**
     * 명시적으로 등록된 skipPaths에 해당하는 경로만 필터를 건너뜁니다.
     * 인증 방식별 분기는 {@link #doFilterInternal}의 {@link AuthenticationMethodDetector}가 담당합니다.
     * <p>
     * 항목 3: 완전일치 외에 Ant 패턴({@code /css/**} 등)도 지원한다. 완전일치 경로(예:
     * {@code /auth/token})는 Ant 패턴으로도 자기 자신과 그대로 일치하므로 기존 동작과 회귀가 없다.
     * </p>
     * <p>
     * <b>M-1 (context-path 불일치):</b> {@link HttpServletRequest#getRequestURI()}는 context-path가
     * 배포된 환경에서 그 context-path를 포함한다({@code /myapp/css/a.css}). skipPaths 패턴은
     * context-path 없는 형태({@code /css/**})로 작성되므로 이 환경에서는 매칭이 실패해 인증은
     * permitAll로 통과하지만 필터 자체(원격 호출)는 스킵되지 않는 불일치가 생긴다.
     * {@link HttpServletRequest#getContextPath()}를 제거한 경로를 사용해 이를 바로잡는다
     * (context-path가 없는 환경에서는 결과가 {@code getRequestURI()}와 동일하므로 회귀가 없다).
     * </p>
     * <p>
     * <b>M-2 (경로 조작 우회):</b> 정규화되지 않은 원시 경로({@code /css/../api/secret})가
     * {@code /css/**} 패턴에 매칭될 수 있다. {@code StrictHttpFirewall}이 기본적으로 이런 요청을
     * 막지만, 방어 계층을 하나만 신뢰하지 않기 위해 여기서도
     * {@link StringUtils#cleanPath(String)}로 {@code ..}/{@code .} 세그먼트를 해석한 뒤 매칭한다.
     * </p>
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = resolveNormalizedPath(request);
        for (String skipPath : skipPaths) {
            if (SKIP_PATH_MATCHER.match(skipPath, path)) {
                log.debug("[Filter] 경로 '{}' — skipPaths 패턴 '{}' 매칭, 필터 스킵", path, skipPath);
                return true;
            }
        }
        return false;
    }

    /**
     * skipPaths 매칭에 사용할 경로를 정규화합니다 (M-1: context-path 제거, M-2: {@code ..}/{@code .}
     * 세그먼트 해석).
     * <p>
     * {@code UrlPathHelper}는 {@code getContextPath()}가 절대 {@code null}이 아니라는 서블릿 컨테이너
     * 계약에 의존하므로, 직접 문자열 비교로 context-path를 제거해 그 계약이 성립하지 않는 환경(테스트
     * 더블 등)에서도 안전하게 동작하도록 한다.
     * </p>
     */
    private String resolveNormalizedPath(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        if (requestUri == null || requestUri.isEmpty()) {
            requestUri = "/";
        }
        String contextPath = request.getContextPath();
        String pathWithinApplication = requestUri;
        if (StringUtils.hasLength(contextPath) && requestUri.startsWith(contextPath)) {
            pathWithinApplication = requestUri.substring(contextPath.length());
        }
        String cleaned = StringUtils.cleanPath(pathWithinApplication);
        return cleaned.isEmpty() ? "/" : cleaned;
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {

        // 인증 방식 판별 — 진입부에서 단일 판별, 이후 분기
        AuthenticationMethod method = methodDetector.detect(request);

        switch (method) {
            case BEARER, BASIC, CREDENTIAL_LOGIN -> {
                AuthenticationEventLogger.logSkipped(method.name(), getClientIp(request), "stateless 인증 경로");
                filterChain.doFilter(request, response);
                return;
            }
            case NONE -> {
                filterChain.doFilter(request, response);
                return;
            }
            case OIDC_COOKIE -> handleOidcCookieAuth(request, response, filterChain);
        }
    }

    /**
     * OIDC 쿠키 기반 인증을 처리합니다.
     * 세션 없음은 예외가 아닌 정상 비로그인 상태로 처리합니다.
     */
    private void handleOidcCookieAuth(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {

        // H-2: 이 라이브러리가 만들지 않은 인증(비-KeycloakPrincipal 기반)일 때만 스킵한다.
        // 배경: SecurityContextRepositoryMode.HTTP_SESSION(또는 DELEGATING)을 사용하면
        // OAuth2LoginAuthenticationFilter가 OidcLoginSuccessHandler 호출 "전"에 SecurityContext를
        // 세션에 저장하므로, 세션에는 (principal 교체 전) DefaultOidcUser 기반 OAuth2AuthenticationToken이
        // 남아 있을 수 있다. 과거에는 "인증됨 + 비-Anonymous"만으로 스킵했기 때문에, 이런 stale
        // Authentication이 세션에서 복원될 때마다 이 필터가 항상 "이미 인증됨" 판단을 내려 OIDC 쿠키
        // 재검증(introspect 등)이 영구적으로 스킵되고 ROLE_REALM_*/ROLE_CLIENT_* 권한이 절대
        // 부여되지 않는 문제가 있었다. 이제는 principal이 이 라이브러리의 {@link KeycloakPrincipal}
        // 인 경우(=이 필터 또는 OidcLoginSuccessHandler가 만든 인증)라면 스킵하지 않고 항상 OIDC 쿠키로
        // 재계산한다 — 이 필터의 나머지 로직 자체가 매 요청 쿠키/세션 기반으로 새로 인증을 도출하므로
        // stale 상태가 고착되지 않는다. Basic Auth(BasicAuthenticationFilter)/Bearer Token처럼
        // 완전히 다른 인증 방식은 이 필터 이전에 AuthenticationMethodDetector가 별도 분기로 처리해
        // 이 메서드(OIDC_COOKIE 분기) 자체에 진입하지 않으므로, 여기서 만나는 "우리가 만들지 않은
        // 인증"은 애플리케이션이 직접 등록한 핸드오프 필터가 세운 인증(SecurityContextRepositoryMode
        // Javadoc 참고)뿐이며, 그 경우에만 보존을 위해 스킵한다.
        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
        if (existingAuth != null && existingAuth.isAuthenticated()
                && !(existingAuth instanceof org.springframework.security.authentication.AnonymousAuthenticationToken)
                && !(existingAuth.getPrincipal() instanceof KeycloakPrincipal)) {
            // L-A: principal이 null인 Authentication도 위 instanceof 검사(음성 판정)를 통과해 이
            // 블록에 진입할 수 있다. existingAuth.getPrincipal()을 로그 문에서 한 번 더 호출해
            // .getClass()를 부르면 NPE가 발생해(이 try/catch 밖이므로) 요청이 500으로 실패한다.
            // 지역 변수로 한 번만 조회하고 null 가드를 둔다.
            Object principal = existingAuth.getPrincipal();
            log.debug("[Filter] 이 라이브러리가 만들지 않은 인증 '{}'(principal={}) 보존 — OIDC 쿠키 인증 스킵.",
                existingAuth.getName(), principal != null ? principal.getClass().getSimpleName() : "null");
            filterChain.doFilter(request, response);
            return;
        }

        String idTokenValue = CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME).orElse(null);
        String accessTokenValue = CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME).orElse(null);

        try {
            HttpSession session = request.getSession(false);
            if (session == null) {
                // 세션 없음은 정상 비로그인 상태 — 예외 발생 없이 pass-through
                AuthenticationEventLogger.logNoSession(
                    AuthenticationEventLogger.METHOD_OIDC_COOKIE, getClientIp(request));
                CookieUtil.deleteAllTokenCookies(response);
                filterChain.doFilter(request, response);
                return;
            }

            String refreshToken = sessionManager.getRefreshToken(session).orElse(null);
            if (refreshToken == null) {
                // 세션은 있으나 Refresh Token이 없는 상태 — 세션 없음(logNoSession)보다 이례적인
                // 상황(세션 스토어 정리/수동 삭제 등)이므로 감사 로그를 남긴다(항목 6).
                log.debug("[Filter] HTTP Session에 Refresh Token이 없음 - 쿠키 삭제 후 다음 필터로 진행");
                AuthenticationEventLogger.logFailure(
                    AuthenticationEventLogger.METHOD_OIDC_COOKIE, getClientIp(request), "unknown",
                    ErrorCode.REFRESH_TOKEN_NOT_FOUND.getCode());
                CookieUtil.deleteAllTokenCookies(response);
                filterChain.doFilter(request, response);
                return;
            }

            log.debug("[Filter] HTTP Session에서 Refresh Token 로드 성공.");

            KeycloakPrincipal principal = createPrincipalFromIdToken(idTokenValue);
            KeycloakAuthentication authRequest = new KeycloakAuthentication(
                principal, idTokenValue, accessTokenValue, false);
            log.debug("[Filter] 인증 전 Authentication 객체 생성: {}", principal.getName());

            Authentication successfulAuthentication;
            try {
                log.debug("[Filter] AuthenticationManager에 인증 위임...");
                successfulAuthentication = authenticationManager.authenticate(authRequest);
                log.debug("[Filter] 인증 성공: {}", successfulAuthentication.getName());

            } catch (IntrospectionFailedException | NullPointerException | UserInfoFetchException e) {
                log.warn("[Filter] 온라인 검증 실패, Refresh Token으로 재발급 시도. 원인: {}", e.getMessage());
                successfulAuthentication = refreshAndAuthenticate(session, response, refreshToken);
            }

            SecurityContext securityContext = SecurityContextHolder.getContext();
            securityContext.setAuthentication(successfulAuthentication);
            log.debug("[Filter] SecurityContext에 인증된 사용자 '{}' 등록 완료.", successfulAuthentication.getName());
            AuthenticationEventLogger.logSuccess(
                AuthenticationEventLogger.METHOD_OIDC_COOKIE, getClientIp(request), successfulAuthentication.getName());

        } catch (KeycloakSecurityException e) {
            // 이 라이브러리가 던지는 구조화된 인증 실패(TokenBindingException/RefreshTokenException/
            // AuthenticationFailedException 등)는 오설정·재발급으로 해소되지 않는 예상된 인증 실패
            // 사유이므로(Advisory 1, 항목 6), generic catch(Exception)의 "예상치 못한 오류" 스택트레이스
            // 로깅 대신 ErrorCode(사유 코드)를 감사 로그에 남긴다(로그 노이즈 정리 + ELK 등에서
            // reason=TOKEN_BINDING_FAILED 처럼 코드 기반 검색/집계가 가능해짐).
            SecurityContextHolder.clearContext();
            log.warn("[Filter] 인증 실패 (errorCode={}): {}", e.getErrorCode().getCode(), e.getMessage());
            AuthenticationEventLogger.logFailure(
                AuthenticationEventLogger.METHOD_OIDC_COOKIE, getClientIp(request), "unknown",
                e.getErrorCode().getCode());
            CookieUtil.deleteAllTokenCookies(response);
            sessionManager.invalidateSession(request.getSession());
        } catch (AuthenticationException e) {
            SecurityContextHolder.clearContext();
            log.warn("[Filter] Keycloak 인증에 실패했습니다: {}", e.getMessage());
            AuthenticationEventLogger.logFailure(
                AuthenticationEventLogger.METHOD_OIDC_COOKIE, getClientIp(request), "unknown", e.getMessage());
            CookieUtil.deleteAllTokenCookies(response);
            sessionManager.invalidateSession(request.getSession());
        } catch (Exception e) {
            // 예기치 못한 예외 — warn 레벨로 기록하되 stacktrace 유지
            SecurityContextHolder.clearContext();
            log.warn("[Filter] Keycloak 인증 과정에서 예상치 못한 오류가 발생했습니다.", e);
            AuthenticationEventLogger.logFailure(
                AuthenticationEventLogger.METHOD_OIDC_COOKIE, getClientIp(request), "unknown", e.getMessage());
            CookieUtil.deleteAllTokenCookies(response);
            sessionManager.invalidateSession(request.getSession());
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Refresh Token을 사용하여 토큰을 재발급받고, 인증 객체를 생성합니다.
     * 재발급된 토큰으로 세션과 쿠키를 업데이트합니다.
     *
     * @param session      HTTP Session
     * @param response     HTTP Response (쿠키 업데이트용)
     * @param refreshToken Refresh Token
     * @return 인증된 Authentication 객체
     */
    private Authentication refreshAndAuthenticate(HttpSession session, HttpServletResponse response, String refreshToken) {
        log.debug("[Filter] Keycloak에 토큰 재발급 요청...");

        KeycloakTokenInfo newTokens = refreshTokens(refreshToken);
        log.debug("[Filter] 토큰 재발급 성공. 세션 및 쿠키 업데이트.");

        if (newTokens.getRefreshToken() != null) {
            sessionManager.saveRefreshToken(session, newTokens.getRefreshToken());
        }

        updateCookies(response, newTokens);

        log.debug("[Filter] 재발급된 토큰으로 인증 객체 생성.");
        return authenticationProvider.createAuthenticatedToken(newTokens.getIdToken(), newTokens.getAccessToken());
    }

    /**
     * Refresh Token을 사용하여 새로운 토큰을 발급받습니다.
     *
     * @param refreshToken Refresh Token
     * @return 새로 발급된 토큰 정보
     * @throws RefreshTokenException         Refresh Token이 만료되었거나 유효하지 않은 경우
     * @throws AuthenticationFailedException 그 외 인증 실패
     */
    private KeycloakTokenInfo refreshTokens(String refreshToken) {
        try {
            KeycloakResponse<KeycloakTokenInfo> response = keycloakClient.auth().reissueToken(refreshToken);
            int status = response.getStatus();

            return switch (status) {
                case 200 -> {
                    log.debug("[Filter] 토큰 재발급 성공.");
                    yield response.getBody()
                        .orElseThrow(() -> new RefreshTokenException("토큰 재발급 실패: 응답 본문이 없습니다."));
                }
                case 401 -> {
                    log.warn("[Filter] Refresh Token이 만료되었거나 유효하지 않습니다.");
                    throw new RefreshTokenException("Refresh Token이 만료되었거나 유효하지 않습니다.");
                }
                default -> {
                    log.error("[Filter] 토큰 재발급 중 예상치 못한 응답. 상태 코드: {}", status);
                    throw new AuthenticationFailedException("토큰 재발급 실패. 상태 코드: " + status);
                }
            };
        } catch (RestClientException e) {
            log.error("[Filter] Keycloak 서버와 통신 중 오류 발생: {}", e.getMessage());
            throw new AuthenticationFailedException("Keycloak 서버와 통신할 수 없습니다: " + e.getMessage());
        }
    }

    private void updateCookies(HttpServletResponse response, KeycloakTokenInfo newTokens) {
        log.debug("[Filter] 토큰이 재발급되어 쿠키를 업데이트합니다.");
        int maxAge = newTokens.getExpireTime();
        CookieUtil.addTokenCookies(response, newTokens.getAccessToken(), maxAge, newTokens.getIdToken(), maxAge);
    }

    private String getClientIp(HttpServletRequest request) {
        return ClientIpResolver.resolve(
            request.getHeader("X-Forwarded-For"),
            request.getRemoteAddr(),
            trustedProxyCount
        );
    }

    private KeycloakPrincipal createPrincipalFromIdToken(String idToken) {
        String subject = JwtUtil.parseSubjectWithoutValidation(idToken);
        if (subject == null || subject.isBlank()) {
            subject = "unknown";
        }
        return new KeycloakPrincipal(subject, Collections.emptyList(), null, null);
    }
}
