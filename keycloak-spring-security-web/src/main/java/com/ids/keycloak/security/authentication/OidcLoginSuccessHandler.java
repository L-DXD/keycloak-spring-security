package com.ids.keycloak.security.authentication;

import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.ids.keycloak.security.util.CookieUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.session.FindByIndexNameSessionRepository;

/**
 * OIDC 로그인 성공 후, Access Token과 ID Token을 쿠키에 저장하는 커스텀 핸들러입니다.
 * docs/04 아키텍처의 stateless 인증 흐름을 지원하기 위한 사전 작업을 수행합니다.
 */
@Slf4j
@RequiredArgsConstructor
public class OidcLoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final KeycloakSessionManager sessionManager;

    @Override
    public void onAuthenticationSuccess(
        HttpServletRequest request,
        HttpServletResponse response,
        Authentication authentication
    ) throws IOException, ServletException {
        if (authentication instanceof OAuth2AuthenticationToken) {
            log.debug("OIDC 로그인 성공 principal Name = {}", authentication.getName());
            log.debug("OIDC 로그인 성공. 토큰을 쿠키에 저장합니다.");
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;

            // Back-Channel Logout을 위해 세션에 Principal Name과 Keycloak Session ID 저장
            HttpSession session = request.getSession(false);
            if (session != null) {
                String principalName = authentication.getName();
                sessionManager.savePrincipalName(session, principalName);

                // Keycloak sid 저장 (ID Token의 sid 클레임)
                if (oauthToken.getPrincipal() instanceof OidcUser oidcUser) {
                    String keycloakSid = oidcUser.getIdToken().getClaimAsString("sid");
                    if (keycloakSid != null) {
                        sessionManager.saveKeycloakSessionId(session, keycloakSid);
                    }
                }

            }

            // AuthenticationProvider에서 이미 authorizedClient를 저장했으므로, 여기서는 load하여 사용합니다.
            OAuth2AuthorizedClient authorizedClient = authorizedClientRepository.loadAuthorizedClient(
                oauthToken.getAuthorizedClientRegistrationId(),
                authentication, // Spring Security 6부터 principal.getName() 대신 authentication 객체 자체를 사용
                request
            );

            if (authorizedClient != null && authorizedClient.getAccessToken() != null) {
                // Access Token 추출 및 쿠키 생성
                String accessTokenValue = authorizedClient.getAccessToken().getTokenValue();
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

            // ID Token 추출 및 쿠키 생성
            if (oauthToken.getPrincipal() instanceof OidcUser) {
                OidcUser oidcUser = (OidcUser) oauthToken.getPrincipal();
                String idTokenValue = oidcUser.getIdToken().getTokenValue();
                int idTokenExpiresIn = CookieUtil.calculateRestMaxAge(oidcUser.getIdToken().getExpiresAt());
                CookieUtil.addCookie(response, CookieUtil.ID_TOKEN_NAME, idTokenValue, idTokenExpiresIn);
                log.debug("id_token 쿠키를 생성했습니다.");
            } else {
                log.warn("ID Token을 찾을 수 없어 id_token 쿠키를 생성하지 못했습니다.");
            }
        } else {
            log.warn("OAuth2AuthenticationToken 타입이 아니므로, 토큰 쿠키를 생성할 수 없습니다. Authentication type: {}", authentication.getClass().getName());
        }

        // 세션 무효화 충돌 방지를 위해 super.onAuthenticationSuccess() 호출 제거
        // 대신 직접 리디렉션 처리 (기본 SavedRequest 또는 루트)
        String targetUrl = determineTargetUrl(request, response, authentication);
        if (response.isCommitted()) {
            log.debug("응답이 이미 커밋되었습니다. 다음 URL로 리디렉션할 수 없습니다: " + targetUrl);
            return;
        }
        
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
        log.debug("OIDC 로그인 성공 후 리디렉션: {}", targetUrl);
    }
}
