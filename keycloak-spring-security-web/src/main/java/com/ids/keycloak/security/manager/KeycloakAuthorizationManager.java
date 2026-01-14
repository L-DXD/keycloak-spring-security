package com.ids.keycloak.security.manager;

import com.ids.keycloak.security.authentication.KeycloakAuthentication;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakAuthorizationResult;
import com.sd.KeycloakClient.factory.KeycloakClient;
import jakarta.servlet.http.HttpServletRequest;
import java.util.function.Supplier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * Keycloak Authorization Services를 이용한 커스텀 인가 관리자.
 * 요청마다 Keycloak에 권한 확인(Policy Enforcement)을 수행합니다.
 */
@RequiredArgsConstructor
@Slf4j
public class KeycloakAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final KeycloakClient keycloakClient;

    /**
     * 특정 요청(RequestAuthorizationContext)에 대한 접근 허용 여부를 결정합니다.
     */
    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext context) {
        HttpServletRequest request = context.getRequest();
        String method = request.getMethod();
        String endpoint = request.getRequestURI();

        log.debug("[Authorization] 인가 검증 시작: {} {}", method, endpoint);

        Authentication auth = authentication.get();
        if (!(auth instanceof KeycloakAuthentication keycloakAuth) || !auth.isAuthenticated()) {
            log.warn("[Authorization] 인증되지 않은 사용자이거나, 지원하지 않는 인증 토큰입니다.");
            return new AuthorizationDecision(false);
        }

        log.debug("[Authorization] Keycloak에 인가 요청...");
        String accessToken = keycloakAuth.getAccessToken();

        KeycloakResponse<KeycloakAuthorizationResult> response = keycloakClient.auth().authorization(accessToken, endpoint, method);

        boolean granted = response.getBody()
            .map(KeycloakAuthorizationResult::isGranted)
            .orElse(false);

        log.debug("[Authorization] 인가 결과: {} {} -> {}", method, endpoint, granted ? "허용" : "거부");

        return new AuthorizationDecision(granted);
    }
}
