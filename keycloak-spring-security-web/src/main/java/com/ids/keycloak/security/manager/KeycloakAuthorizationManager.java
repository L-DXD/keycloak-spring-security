package com.ids.keycloak.security.manager;

import com.ids.keycloak.security.authentication.AccessTokenHolder;
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
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.web.client.RestClientException;

/**
 * Keycloak Authorization Services를 사용하여 HTTP 요청에 대한 인가를 수행하는
 * {@link AuthorizationManager} 구현체입니다.
 * <p>
 * 다음 인증 타입을 지원합니다:
 * <ul>
 *   <li>{@link AccessTokenHolder} - {@code KeycloakAuthentication}, {@code BasicAuthenticationToken} 등
 *       라이브러리 자체 인증 토큰</li>
 *   <li>{@link BearerTokenAuthentication} - Spring Security OAuth2 Resource Server의 Bearer 토큰 인증</li>
 * </ul>
 * </p>
 */
@Slf4j
@RequiredArgsConstructor
public class KeycloakAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final KeycloakClient keycloakClient;

    /**
     * 현재 인증된 사용자가 요청한 HTTP 리소스에 접근할 수 있는지 Keycloak에 인가 요청을 보냅니다.
     *
     * @param authentication 현재 인증 정보 공급자
     * @param context        요청 인가 컨텍스트 (HTTP 메서드, 엔드포인트 포함)
     * @return 인가 결과 ({@code true}면 허용, {@code false}면 거부)
     */
    @Override
    public AuthorizationDecision check(
        Supplier<Authentication> authentication,
        RequestAuthorizationContext context
    ) {
        HttpServletRequest request = context.getRequest();
        String method = request.getMethod();
        String endpoint = request.getRequestURI();

        log.debug("[Authorization] 인가 요청 수신: {} {}", method, endpoint);

        Authentication auth = authentication.get();

        if (!auth.isAuthenticated()) {
            log.warn("[Authorization] 미인증 사용자 요청 거부: {} {}", method, endpoint);
            return new AuthorizationDecision(false);
        }

        String accessToken;
        if (auth instanceof AccessTokenHolder holder) {
            log.debug("[Authorization] AccessTokenHolder 인증 타입: {}", auth.getClass().getSimpleName());
            accessToken = holder.getAccessToken();
        } else if (auth instanceof BearerTokenAuthentication bearer) {
            log.debug("[Authorization] BearerTokenAuthentication 인증 타입");
            accessToken = bearer.getToken().getTokenValue();
        } else {
            log.warn("[Authorization] 지원하지 않는 인증 타입 거부: {}", auth.getClass().getSimpleName());
            return new AuthorizationDecision(false);
        }

        log.debug("[Authorization] Keycloak에 인가 요청...");

        KeycloakResponse<KeycloakAuthorizationResult> response;
        try {
            response = keycloakClient.auth().authorization(accessToken, endpoint, method);
        } catch (RestClientException e) {
            log.warn("[Authorization] Keycloak 인가 요청 실패 (통신 오류). 거부 처리: {} {} - {}", method, endpoint, e.getMessage());
            return new AuthorizationDecision(false);
        }

        KeycloakAuthorizationResult result = response.getBody().orElse(null);

        if (result == null) {
            log.warn("[Authorization] Keycloak 인가 응답 본문 없음. 거부 처리: {} {}", method, endpoint);
            return new AuthorizationDecision(false);
        }

        boolean granted = result.isGranted();
        log.debug("[Authorization] Keycloak 인가 결과: {} - {} {}", granted ? "허용" : "거부", method, endpoint);

        return new AuthorizationDecision(granted);
    }
}
