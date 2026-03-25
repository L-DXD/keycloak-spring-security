package com.ids.keycloak.security.authentication;

import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.util.KeycloakAuthorityExtractor;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakIntrospectResponse;
import com.sd.KeycloakClient.dto.user.KeycloakUserInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.web.client.RestClientException;

/**
 * Keycloak Introspect API를 통해 Bearer Token을 검증하고
 * {@link KeycloakPrincipal}을 생성하는 {@link OpaqueTokenIntrospector} 구현체입니다.
 * <p>
 * 기존 {@link KeycloakAuthenticationProvider}의 온라인 검증 패턴을 재사용합니다.
 * </p>
 */
@Slf4j
public class KeycloakOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private final KeycloakClient keycloakClient;
    private final String clientId;

    public KeycloakOpaqueTokenIntrospector(KeycloakClient keycloakClient, String clientId) {
        this.keycloakClient = keycloakClient;
        this.clientId = clientId;
    }

    /**
     * access_token을 Keycloak Introspect API로 검증하고 {@link KeycloakPrincipal}을 반환합니다.
     *
     * @param token access_token 문자열
     * @return {@link OAuth2AuthenticatedPrincipal} (실제로는 {@link KeycloakPrincipal})
     * @throws BadOpaqueTokenException 토큰이 유효하지 않은 경우
     */
    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        log.debug("[BearerToken] Introspect 검증 시작.");

        // 1. Keycloak introspect API 호출
        verifyTokenActive(token);

        // 2. UserInfo 조회
        OidcUserInfo oidcUserInfo = fetchUserInfo(token);

        // 3. UserInfo 클레임에서 권한 추출
        Map<String, Object> claims = (oidcUserInfo != null) ? oidcUserInfo.getClaims() : Map.of();
        Collection<GrantedAuthority> authorities = KeycloakAuthorityExtractor.extract(claims, clientId);

        // 4. OidcIdToken 생성 (Bearer에서는 access_token 기반)
        OidcIdToken oidcIdToken = new OidcIdToken(token, Instant.now(), null, Map.of("sub", extractSubject(claims)));

        // 5. KeycloakPrincipal 생성 및 반환
        String subject = extractSubject(claims);
        KeycloakPrincipal principal = new KeycloakPrincipal(subject, authorities, oidcIdToken, oidcUserInfo);
        log.debug("[BearerToken] Introspect 검증 성공. 사용자: {}", subject);
        return principal;
    }

    /**
     * Keycloak Introspect API를 호출하여 토큰이 active인지 확인합니다.
     */
    private void verifyTokenActive(String token) {
        try {
            KeycloakResponse<KeycloakIntrospectResponse> response =
                keycloakClient.auth().authenticationByIntrospect(token);
            int status = response.getStatus();

            if (status == 200) {
                KeycloakIntrospectResponse body = response.getBody()
                    .orElseThrow(() -> new BadOpaqueTokenException("Introspect 응답 본문이 없습니다."));

                if (!body.getActive()) {
                    log.debug("[BearerToken] 토큰이 비활성 상태입니다 (active=false).");
                    throw new BadOpaqueTokenException("토큰이 유효하지 않습니다.");
                }
                log.debug("[BearerToken] Introspect 검증 성공 (active=true).");
                return;
            }

            log.warn("[BearerToken] Introspect 검증 실패. 상태 코드: {}", status);
            throw new BadOpaqueTokenException("토큰 검증 실패. 상태 코드: " + status);
        } catch (RestClientException e) {
            log.error("[BearerToken] Keycloak 서버 통신 오류: {}", e.getMessage());
            throw new BadOpaqueTokenException("인증 서버 통신 실패: " + e.getMessage());
        }
    }

    /**
     * Keycloak UserInfo 엔드포인트를 호출하여 사용자 정보를 조회합니다.
     */
    private OidcUserInfo fetchUserInfo(String accessToken) {
        try {
            KeycloakResponse<KeycloakUserInfo> response = keycloakClient.user().getUserInfo(accessToken);
            int status = response.getStatus();

            if (status == 200) {
                KeycloakUserInfo keycloakUserInfo = response.getBody().orElse(null);
                if (keycloakUserInfo != null) {
                    log.debug("[BearerToken] UserInfo 조회 성공.");
                    return convertToOidcUserInfo(keycloakUserInfo);
                }
            }

            log.warn("[BearerToken] UserInfo 조회 실패. 상태 코드: {}", status);
            return null;
        } catch (RestClientException e) {
            log.warn("[BearerToken] UserInfo 조회 중 오류 발생: {}", e.getMessage());
            return null;
        }
    }

    /**
     * KeycloakUserInfo를 OidcUserInfo로 변환합니다.
     */
    private OidcUserInfo convertToOidcUserInfo(KeycloakUserInfo keycloakUserInfo) {
        Map<String, Object> claims = new HashMap<>();

        if (keycloakUserInfo.getSubject() != null) {
            claims.put("sub", keycloakUserInfo.getSubject());
        }
        if (keycloakUserInfo.getPreferredUsername() != null) {
            claims.put("preferred_username", keycloakUserInfo.getPreferredUsername());
        }
        if (keycloakUserInfo.getEmail() != null) {
            claims.put("email", keycloakUserInfo.getEmail());
        }
        if (keycloakUserInfo.getName() != null) {
            claims.put("name", keycloakUserInfo.getName());
        }

        claims.putAll(keycloakUserInfo.getOtherInfo());
        return new OidcUserInfo(claims);
    }

    /**
     * 클레임에서 subject(사용자 ID)를 추출합니다.
     */
    private String extractSubject(Map<String, Object> claims) {
        Object sub = claims.get("sub");
        return sub != null ? sub.toString() : "unknown";
    }
}
