package com.ids.keycloak.security.config;

import java.net.URI;
import java.util.Objects;

/**
 * 붙을 Keycloak realm과 client 정보. 스타터는 Spring OAuth2 Client 등록({@code spring.security.oauth2.client.*})에서 만든다.
 *
 * @param registrationId     OAuth2 등록 id (예: keycloak)
 * @param clientId           client id (azp, 기본 aud)
 * @param issuer             realm 주소 (iss). 예: https://sso.example.com/realms/demo
 * @param jwkSetUri          서명 키 주소 (JWKS)
 * @param tokenUri           토큰 주소 (갱신)
 * @param endSessionEndpoint OIDC 로그아웃 주소. 설명 문서에 없으면 {@code null}
 */
public record KeycloakProvider(String registrationId, String clientId, String issuer, URI jwkSetUri, URI tokenUri,
                               URI endSessionEndpoint) {

    public KeycloakProvider {
        Objects.requireNonNull(registrationId, "registrationId");
        Objects.requireNonNull(clientId, "clientId");
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(jwkSetUri, "jwkSetUri");
        Objects.requireNonNull(tokenUri, "tokenUri");
    }
}
