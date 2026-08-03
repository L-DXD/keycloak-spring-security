package com.ids.keycloak.security.authentication;

import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.ids.keycloak.security.util.CookieUtil;
import com.ids.keycloak.security.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * OIDC 리다이렉트 흐름을 거치지 않고, 이미 발급받은 Keycloak 토큰으로 인증 세션을 세우는
 * 프로그래밍 방식 로그인(programmatic login) 파사드입니다.
 *
 * <p><b>용도:</b> Token Exchange 결과, 커스텀 SSO 핸드오프, 테스트 코드 등에서 OIDC
 * authorization code 리다이렉트를 강제하지 않고, 이미 확보한 ID/Access(/Refresh) Token으로
 * {@code OidcLoginSuccessHandler}가 OIDC 로그인 성공 시 수행하는 것과 동등한 결과(인증된
 * {@code SecurityContext}, 토큰 쿠키, 세션 데이터)를 만들어내기 위해 사용합니다.</p>
 *
 * <p><b>검증 경유(choke point) — 검증 우회 금지:</b> 전달된 토큰은 반드시
 * {@link KeycloakAuthenticationProvider#createAuthenticatedToken(String, String)}을 통해 검증됩니다.
 * ID Token 서명·iss·exp·nbf 검증, UserInfo 조회, ID/Access Token 결합 검증(sub/aud/azp) 중 하나라도
 * 실패하면 {@code KeycloakAuthenticationProvider}가 던지는 기존 예외
 * (예: {@link com.ids.keycloak.security.exception.TokenBindingException},
 * {@link com.ids.keycloak.security.exception.UserInfoFetchException}) 그대로 전파되며, 인증 세션은
 * 세워지지 않습니다.</p>
 *
 * <p><b>세션 고정 방지:</b> 호출 시점에 이미 세션이 존재했다면
 * {@link HttpServletRequest#changeSessionId()}로 세션 ID를 회전합니다. 이는 라이브러리가
 * OIDC 로그인 성공 시 이미 사용하는 {@code ChangeSessionIdAuthenticationStrategy}와 동일한 기준
 * (기존 세션이 없으면 회전하지 않음)입니다. Back-Channel 로그아웃 인덱싱을 위한 Principal Name
 * 저장에는 세션이 반드시 필요하므로, 세션이 없었다면 새로 생성합니다.</p>
 *
 * <p><b>SecurityContext 영속화 — {@code security-context-repository} 정책을 존중:</b>
 * 생성자로 주입된 {@link SecurityContextRepository}에 {@code saveContext}를 호출합니다. 이 저장소는
 * {@code keycloak.security.authentication.security-context-repository} 프로퍼티(기본값 {@code NULL})로
 * 선택된 정책과 동일하게 구성됩니다. <b>기본값({@code NULL})에서는 {@code SecurityContext}가 세션에
 * 저장되지 않으므로</b>, 이후 요청에서 인증을 유지하려면 {@code KeycloakAuthenticationFilter}가 매 요청
 * 재계산하는 방식(쿠키+세션의 Refresh Token)에 의존해야 합니다. 앞단 필터·핸드오프 필터가 이 인증을
 * 세션을 통해 이어받아야 한다면 {@code security-context-repository=HTTP_SESSION}(또는
 * {@code DELEGATING})으로 opt-in 하세요.</p>
 *
 * <p><b>사용 예시:</b>
 * <pre>
 * KeycloakTokens tokens = KeycloakTokens.of(idToken, accessToken, refreshToken);
 * Authentication authentication = keycloakLoginService.authenticate(request, response, tokens);
 * </pre>
 * </p>
 */
@Slf4j
public class KeycloakLoginService {

    private static final String SID_CLAIM = "sid";
    private static final String EXP_CLAIM = "exp";

    private final KeycloakAuthenticationProvider authenticationProvider;
    private final KeycloakSessionManager sessionManager;
    private final SecurityContextRepository securityContextRepository;

    /**
     * @param authenticationProvider    토큰 검증의 단일 진입점. 반드시 이 provider의
     *                                   {@code createAuthenticatedToken}을 경유해야 검증 우회가 없다.
     * @param sessionManager             Refresh Token/Principal Name/Keycloak Session ID를 세션에 저장.
     * @param securityContextRepository  {@code keycloak.security.authentication.security-context-repository}
     *                                   정책에 따라 선택된 저장소 (기본값 {@code NULL}이면 영속화되지 않음).
     */
    public KeycloakLoginService(
        KeycloakAuthenticationProvider authenticationProvider,
        KeycloakSessionManager sessionManager,
        SecurityContextRepository securityContextRepository
    ) {
        this.authenticationProvider = authenticationProvider;
        this.sessionManager = sessionManager;
        this.securityContextRepository = securityContextRepository;
    }

    /**
     * ID Token/Access Token으로 인증 세션을 세웁니다 (Refresh Token 없음).
     *
     * @see #authenticate(HttpServletRequest, HttpServletResponse, KeycloakTokens)
     */
    public Authentication authenticate(
        HttpServletRequest request,
        HttpServletResponse response,
        String idToken,
        String accessToken
    ) {
        return authenticate(request, response, KeycloakTokens.of(idToken, accessToken));
    }

    /**
     * ID Token/Access Token/Refresh Token으로 인증 세션을 세웁니다.
     *
     * @see #authenticate(HttpServletRequest, HttpServletResponse, KeycloakTokens)
     */
    public Authentication authenticate(
        HttpServletRequest request,
        HttpServletResponse response,
        String idToken,
        String accessToken,
        String refreshToken
    ) {
        return authenticate(request, response, KeycloakTokens.of(idToken, accessToken, refreshToken));
    }

    /**
     * 전달된 {@link KeycloakTokens}로 인증 세션을 세웁니다.
     *
     * <p>처리 순서: (1) {@code KeycloakAuthenticationProvider}로 토큰 검증 및 인증 객체 생성 →
     * (2) 세션 고정 방지 → (3) {@code SecurityContext} 설정 및 저장 → (4) 토큰 쿠키 발급 →
     * (5) Refresh Token/Principal Name/Keycloak Session ID를 세션에 저장.</p>
     *
     * @param request  현재 요청 (세션 조회/생성에 사용)
     * @param response 현재 응답 (토큰 쿠키 발급에 사용)
     * @param tokens   검증할 토큰 묶음
     * @return 검증을 통과한 {@link Authentication} ({@code SecurityContextHolder}에도 동일하게 설정됨)
     * @throws com.ids.keycloak.security.exception.KeycloakSecurityException 토큰 검증 실패 시
     *         (서명·클레임 검증 실패, ID/Access Token 결합 검증 실패, UserInfo 조회 실패 등)
     */
    public Authentication authenticate(
        HttpServletRequest request,
        HttpServletResponse response,
        KeycloakTokens tokens
    ) {
        Objects.requireNonNull(request, "request는 null일 수 없습니다.");
        Objects.requireNonNull(response, "response는 null일 수 없습니다.");
        Objects.requireNonNull(tokens, "tokens는 null일 수 없습니다.");

        log.debug("[LoginService] 프로그래밍 방식 로그인 시작.");

        // 1. 검증 파이프라인의 단일 진입점(choke point)을 경유한다 — 검증 우회 금지.
        //    실패 시 KeycloakAuthenticationProvider가 던지는 기존 KeycloakSecurityException 계열이
        //    그대로 전파되며, 이 메서드는 어떤 SecurityContext도 세우지 않는다.
        Authentication authentication =
            authenticationProvider.createAuthenticatedToken(tokens.idToken(), tokens.accessToken());

        // 2. 세션 고정 방지: 기존 세션이 있었다면 changeSessionId()로 회전한다.
        //    (ChangeSessionIdAuthenticationStrategy와 동일 기준 — 세션이 없었다면 회전하지 않는다)
        HttpSession existingSession = request.getSession(false);
        if (existingSession != null) {
            request.changeSessionId();
            log.debug("[LoginService] 기존 세션의 ID를 회전했습니다(세션 고정 방지).");
        }
        // Back-Channel 로그아웃 인덱싱(Principal Name)을 위해 세션이 반드시 필요하므로 없으면 생성한다.
        HttpSession session = request.getSession(true);

        // 3. SecurityContext 설정 + 선택된 SecurityContextRepository에 저장.
        //    security-context-repository=NULL(기본값)이면 저장되지 않는다(클래스 Javadoc 참고).
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        // 4. 토큰 쿠키 발급
        issueTokenCookies(response, authentication, tokens);

        // 5. Refresh Token / Principal Name / Keycloak Session ID를 세션에 저장.
        //    Principal Name 저장은 Back-Channel 로그아웃 인덱스 조회에 필수다.
        if (tokens.refreshToken() != null) {
            sessionManager.saveRefreshToken(session, tokens.refreshToken());
        }
        sessionManager.savePrincipalName(session, authentication.getName());
        extractKeycloakSessionId(authentication)
            .ifPresent(sid -> sessionManager.saveKeycloakSessionId(session, sid));

        log.debug("[LoginService] 프로그래밍 방식 로그인 완료: {}", authentication.getName());
        return authentication;
    }

    /**
     * Access Token/ID Token 쿠키를 발급합니다. maxAge는 각 토큰의 실제 만료 시각을 기준으로 계산하며,
     * Access Token이 Opaque(비-JWT)라 만료 시각을 알 수 없으면 ID Token의 maxAge로 대체합니다.
     */
    private void issueTokenCookies(HttpServletResponse response, Authentication authentication, KeycloakTokens tokens) {
        int idTokenMaxAge = resolveIdTokenMaxAge(authentication);
        int accessTokenMaxAge = resolveAccessTokenMaxAge(tokens.accessToken(), idTokenMaxAge);
        CookieUtil.addTokenCookies(response, tokens.accessToken(), accessTokenMaxAge, tokens.idToken(), idTokenMaxAge);
    }

    private int resolveIdTokenMaxAge(Authentication authentication) {
        if (authentication.getPrincipal() instanceof KeycloakPrincipal principal && principal.getIdToken() != null) {
            return CookieUtil.calculateRestMaxAge(principal.getIdToken().getExpiresAt());
        }
        return -1;
    }

    /**
     * Access Token이 구조적으로 JWT일 때만 {@code exp} 클레임을 참고합니다(서명 미검증 파싱, 쿠키
     * 만료시간 산출이라는 보조 용도로만 사용 — {@link JwtUtil#parseClaimsWithoutValidation} Javadoc 참고).
     * Opaque 토큰이거나 {@code exp}가 없으면 ID Token의 maxAge를 그대로 사용합니다.
     */
    private int resolveAccessTokenMaxAge(String accessTokenValue, int fallbackMaxAge) {
        if (!JwtUtil.isStructurallyJwt(accessTokenValue)) {
            return fallbackMaxAge;
        }
        Map<String, Object> claims = JwtUtil.parseClaimsWithoutValidation(accessTokenValue);
        if (claims.get(EXP_CLAIM) instanceof Number exp) {
            return CookieUtil.calculateRestMaxAge(exp.longValue());
        }
        return fallbackMaxAge;
    }

    private Optional<String> extractKeycloakSessionId(Authentication authentication) {
        if (authentication.getPrincipal() instanceof KeycloakPrincipal principal && principal.getIdToken() != null) {
            return Optional.ofNullable(principal.getIdToken().getClaimAsString(SID_CLAIM));
        }
        return Optional.empty();
    }
}
