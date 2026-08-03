package com.ids.keycloak.security.authentication;

import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.ids.keycloak.security.util.CookieUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * OIDC 로그인 성공 후, Access Token과 ID Token을 쿠키에 저장하는 커스텀 핸들러입니다.
 * docs/04 아키텍처의 stateless 인증 흐름을 지원하기 위한 사전 작업을 수행합니다.
 * <p>
 * Spring Security가 생성한 OidcUser를 KeycloakPrincipal로 변환하여
 * OIDC 로그인과 API 요청 시점에서 동일한 Principal 타입을 사용합니다.
 * </p>
 */
@Slf4j
public class OidcLoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final KeycloakSessionManager sessionManager;
    private final SecurityContextRepository securityContextRepository;

    /**
     * 하위 호환 생성자입니다. {@link SecurityContextRepository}를 지정하지 않으면
     * {@link NullSecurityContextRepository}(no-op)를 사용합니다 — 기존 동작과 동일합니다.
     * <p>
     * {@code security-context-repository}를 {@code HTTP_SESSION}/{@code DELEGATING}으로 설정한
     * 소비자는 (H-2) {@link #OidcLoginSuccessHandler(OAuth2AuthorizedClientRepository,
     * KeycloakSessionManager, String, SecurityContextRepository)} 생성자로 실제 저장소를 주입해야
     * principal 교체 후 재검증 stale 문제가 발생하지 않습니다. Auto-Configuration 경로는 이미 이
     * 4-arg 생성자를 사용합니다.
     * </p>
     */
    public OidcLoginSuccessHandler(
        OAuth2AuthorizedClientRepository authorizedClientRepository,
        KeycloakSessionManager sessionManager,
        String defaultSuccessUrl
    ) {
        this(authorizedClientRepository, sessionManager, defaultSuccessUrl, new NullSecurityContextRepository());
    }

    /**
     * {@code security-context-repository} 정책에 맞는 {@link SecurityContextRepository}를 주입받는
     * 생성자입니다 (H-2).
     *
     * @param securityContextRepository {@code KeycloakHttpConfigurer}/{@code KeycloakLoginService}와
     *     동일한 정책으로 생성된 저장소({@code SecurityContextRepositoryFactory} 참고). {@code NULL}
     *     모드에서는 {@link NullSecurityContextRepository}(no-op)로 기존 동작과 동일합니다.
     */
    public OidcLoginSuccessHandler(
        OAuth2AuthorizedClientRepository authorizedClientRepository,
        KeycloakSessionManager sessionManager,
        String defaultSuccessUrl,
        SecurityContextRepository securityContextRepository
    ) {
        this.authorizedClientRepository = authorizedClientRepository;
        this.sessionManager = sessionManager;
        this.securityContextRepository = securityContextRepository;
        setDefaultTargetUrl(defaultSuccessUrl);
    }

    @Override
    public void onAuthenticationSuccess(
        HttpServletRequest request,
        HttpServletResponse response,
        Authentication authentication
    ) throws IOException, ServletException {

        if (!(authentication instanceof OAuth2AuthenticationToken oauthToken)) {
            log.warn("OAuth2AuthenticationToken 타입이 아니므로, 토큰 쿠키를 생성할 수 없습니다. Authentication type: {}", authentication.getClass().getName());
            redirectToTarget(request, response, authentication);
            return;
        }

        if (!(oauthToken.getPrincipal() instanceof OidcUser oidcUser)) {
            log.warn("OidcUser 타입이 아니므로, KeycloakPrincipal을 생성할 수 없습니다.");
            redirectToTarget(request, response, authentication);
            return;
        }

        log.debug("OIDC 로그인 성공 principal Name = {}", authentication.getName());
        log.debug("OIDC 로그인 성공. 토큰을 쿠키에 저장하고 KeycloakPrincipal을 생성합니다.");

        HttpSession session = request.getSession(false);

        // AuthorizedClient에서 Access Token과 Refresh Token 조회
        OAuth2AuthorizedClient authorizedClient = authorizedClientRepository.loadAuthorizedClient(
            oauthToken.getAuthorizedClientRegistrationId(),
            authentication,
            request
        );

        if (authorizedClient != null && authorizedClient.getAccessToken() != null) {
            String accessTokenValue = authorizedClient.getAccessToken().getTokenValue();

            // Access Token 쿠키 생성
            int accessTokenExpiresIn = CookieUtil.calculateRestMaxAge(authorizedClient.getAccessToken().getExpiresAt());
            CookieUtil.addCookie(response, CookieUtil.ACCESS_TOKEN_NAME, accessTokenValue, accessTokenExpiresIn);
            log.debug("access_token 쿠키를 생성했습니다.");

            // Refresh Token을 세션에 저장
            if (session != null && authorizedClient.getRefreshToken() != null) {
                log.debug("HTTP Session에 Refresh Token을 저장합니다.");
                sessionManager.saveRefreshToken(session, authorizedClient.getRefreshToken().getTokenValue());
            }
        } else {
            log.warn("AuthorizedClient 또는 Access Token을 찾을 수 없어 access_token 쿠키를 생성하지 못했습니다.");
        }

        // ID Token 쿠키 생성
        String idTokenValue = oidcUser.getIdToken().getTokenValue();
        int idTokenExpiresIn = CookieUtil.calculateRestMaxAge(oidcUser.getIdToken().getExpiresAt());
        CookieUtil.addCookie(response, CookieUtil.ID_TOKEN_NAME, idTokenValue, idTokenExpiresIn);
        log.debug("id_token 쿠키를 생성했습니다.");

        // KeycloakPrincipal 생성 및 SecurityContext 업데이트
        KeycloakPrincipal keycloakPrincipal = createKeycloakPrincipal(oidcUser);
        OAuth2AuthenticationToken newAuthToken = new OAuth2AuthenticationToken(
            keycloakPrincipal,
            keycloakPrincipal.getAuthorities(),
            oauthToken.getAuthorizedClientRegistrationId()
        );
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(newAuthToken);
        log.debug("SecurityContext에 KeycloakPrincipal 기반 Authentication을 설정했습니다.");

        // H-2: OAuth2LoginAuthenticationFilter는 이 성공 핸들러를 호출하기 "전"에 이미
        // securityContextRepository.saveContext(...)를 호출해, principal 교체 전(DefaultOidcUser
        // 기반) SecurityContext를 세션에 저장해둔다. security-context-repository가 HTTP_SESSION/
        // DELEGATING이면 위에서 교체한 KeycloakPrincipal 기반 Authentication을 다시 저장해야
        // 다음 요청부터 stale한 DefaultOidcUser 기반 Authentication이 복원되지 않는다. NULL
        // 모드(기본값)에서는 NullSecurityContextRepository가 주입되어 있어 이 호출은 no-op이다.
        securityContextRepository.saveContext(securityContext, request, response);
        log.debug("SecurityContextRepository에 갱신된 Authentication을 재저장했습니다.");

        // Back-Channel Logout을 위해 세션에 Principal Name과 Keycloak Session ID 저장
        if (session != null) {
            sessionManager.savePrincipalName(session, keycloakPrincipal.getName());

            String keycloakSid = oidcUser.getIdToken().getClaimAsString("sid");
            if (keycloakSid != null) {
                sessionManager.saveKeycloakSessionId(session, keycloakSid);
            }
        }

        redirectToTarget(request, response, newAuthToken);
    }

    /**
     * Spring Security의 OidcUser를 기반으로 KeycloakPrincipal을 생성합니다.
     * OidcUser의 authorities를 그대로 사용합니다.
     *
     * @param oidcUser Spring Security가 생성한 OidcUser
     * @return KeycloakPrincipal
     */
    private KeycloakPrincipal createKeycloakPrincipal(OidcUser oidcUser) {
        return new KeycloakPrincipal(
            oidcUser.getName(),
            oidcUser.getAuthorities(),
            oidcUser.getIdToken(),
            oidcUser.getUserInfo()
        );
    }

    /**
     * 리디렉션을 수행합니다.
     */
    private void redirectToTarget(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String targetUrl = determineTargetUrl(request, response, authentication);
        if (response.isCommitted()) {
            log.debug("응답이 이미 커밋되었습니다. 다음 URL로 리디렉션할 수 없습니다: " + targetUrl);
            return;
        }

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
        log.debug("OIDC 로그인 성공 후 리디렉션: {}", targetUrl);
    }
}
