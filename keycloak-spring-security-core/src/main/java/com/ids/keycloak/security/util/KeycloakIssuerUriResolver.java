package com.ids.keycloak.security.util;

import lombok.experimental.UtilityClass;

/**
 * Keycloak Realm의 OIDC issuer URI(및 JWKS URI)를 {@code keycloak.base-url}/{@code keycloak.relative-path}/
 * {@code keycloak.realm-name} 설정으로부터 구성하는 유틸리티입니다.
 *
 * <p>이 세 값은 이미 이 라이브러리의 {@code KeycloakClient} 빈 생성에 필수({@code @Value}, 기본값 없음)이므로,
 * 별도의 {@code issuer-uri} 프로퍼티 설정 없이도 항상 계산 가능합니다. Servlet/WebFlux 오토설정에서
 * 공통으로 사용해 OIDC Cookie 인증 흐름의 {@code JwtDecoder}/{@code ReactiveJwtDecoder}를 구성합니다.</p>
 */
@UtilityClass
public class KeycloakIssuerUriResolver {

    private static final String REALMS_PATH = "/realms/";
    private static final String CERTS_PATH = "/protocol/openid-connect/certs";

    /**
     * Keycloak Realm의 issuer URI를 계산합니다. 형식: {@code {baseUrl}{relativePath}/realms/{realmName}}
     *
     * @param baseUrl      Keycloak 서버 base URL (예: {@code https://keycloak.example.com})
     * @param relativePath Keycloak 컨텍스트 경로 (없으면 {@code null} 또는 빈 문자열)
     * @param realmName    Realm 이름
     * @return issuer URI (예: {@code https://keycloak.example.com/realms/myrealm})
     */
    public static String resolveIssuerUri(String baseUrl, String relativePath, String realmName) {
        StringBuilder sb = new StringBuilder();
        if (baseUrl != null) {
            sb.append(baseUrl);
        }
        if (relativePath != null && !relativePath.isBlank()) {
            sb.append(relativePath);
        }
        sb.append(REALMS_PATH).append(realmName);
        return sb.toString();
    }

    /**
     * Keycloak Realm의 JWKS(공개키 세트) URI를 계산합니다.
     * 형식: {@code {issuerUri}/protocol/openid-connect/certs}
     *
     * @param issuerUri {@link #resolveIssuerUri(String, String, String)}로 계산한 issuer URI
     * @return JWKS URI
     */
    public static String resolveJwkSetUri(String issuerUri) {
        return issuerUri + CERTS_PATH;
    }
}
