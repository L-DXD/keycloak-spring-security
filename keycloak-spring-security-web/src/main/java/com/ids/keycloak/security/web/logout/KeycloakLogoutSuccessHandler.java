package com.ids.keycloak.security.web.logout;

import java.net.URI;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 로그아웃 뒤 어디로 보낼지 (V3-11): Keycloak 로그아웃이 됐거나 세션이 없었으면 화면 로그아웃 주소로 302.
 * Keycloak 로그아웃을 하지 못했으면 OIDC 로그아웃 주소({@code client_id}, {@code post_logout_redirect_uri}, {@code state})로 302해
 * 브라우저가 Keycloak SSO 세션을 끝내게 한다. ID 토큰을 두지 않으므로 {@code id_token_hint}는 없다(Keycloak이 확인 화면을 보여 준다).
 */
public class KeycloakLogoutSuccessHandler implements LogoutSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(KeycloakLogoutSuccessHandler.class);

    private final URI frontendLogoutUrl;
    private final URI endSessionEndpoint;
    private final String clientId;
    private final SecureRandom random = new SecureRandom();

    /**
     * @param frontendLogoutUrl  화면 로그아웃 주소 (Keycloak client의 post logout redirect URI와 같아야 한다)
     * @param endSessionEndpoint OIDC 로그아웃 주소. {@code null}이면 늘 화면 주소로 보낸다
     */
    public KeycloakLogoutSuccessHandler(URI frontendLogoutUrl, URI endSessionEndpoint, String clientId) {
        this.frontendLogoutUrl = Objects.requireNonNull(frontendLogoutUrl);
        this.endSessionEndpoint = endSessionEndpoint;
        this.clientId = Objects.requireNonNull(clientId);
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String target = KeycloakLogoutHandler.result(request) == KeycloakLogoutHandler.Result.KEYCLOAK_FAILED
            ? oidcLogoutUrl(request) : frontendLogoutUrl.toString();
        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("Location", target);
        response.setHeader("Cache-Control", "no-store");
    }

    /** OIDC 로그아웃 주소. 주소를 모르면 화면 주소. */
    protected String oidcLogoutUrl(HttpServletRequest request) {
        if (endSessionEndpoint == null) {
            log.warn("[KSS] Keycloak 설명 문서에 end_session_endpoint가 없어 화면 로그아웃 주소로 보냅니다");
            return frontendLogoutUrl.toString();
        }
        byte[] state = new byte[16];
        random.nextBytes(state);
        return UriComponentsBuilder.fromUri(endSessionEndpoint)
            .queryParam("client_id", clientId)
            .queryParam("post_logout_redirect_uri", frontendLogoutUrl.toString())
            .queryParam("state", Base64.getUrlEncoder().withoutPadding().encodeToString(state))
            .encode()
            .build()
            .toUriString();
    }
}
