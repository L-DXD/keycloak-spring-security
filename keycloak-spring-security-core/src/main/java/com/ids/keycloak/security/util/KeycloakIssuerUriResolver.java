package com.ids.keycloak.security.util;

import lombok.experimental.UtilityClass;

/**
 * Keycloak Realm의 OIDC issuer URI(및 JWKS URI)를 계산하는 유틸리티입니다.
 *
 * <p><b>보안 Advisory 1(High #1) 대응 — issuer 원천에 대한 중요한 주의사항:</b>
 * {@link #resolveIssuerUri(String, String, String)}은 {@code keycloak.base-url}/
 * {@code keycloak.relative-path}/{@code keycloak.realm-name}으로부터 issuer를 <b>파생(derive)</b>합니다.
 * 이 세 값은 이미 이 라이브러리의 {@code KeycloakClient} 빈 생성에 필수({@code @Value}, 기본값 없음)이므로
 * 항상 계산 가능하지만, {@code base-url}은 <b>이 애플리케이션이 Keycloak API를 호출하는 서버간 통신용
 * URL</b>이라 내부 네트워크 주소나 {@code /etc/hosts} 매핑된 호스트일 수 있습니다.</p>
 *
 * <p>반면 브라우저 로그인으로 발급된 토큰의 {@code iss} 클레임은 Keycloak의 <b>공개 URL(frontendUrl)</b>
 * 입니다. 두 값이 문자열로 다르면(예: base-url이 내부 서비스 DNS, iss는 공개 도메인) {@code JwtIssuerValidator}가
 * exact-match 비교에 실패해 <b>OIDC 쿠키 인증이 전면 장애</b>가 됩니다. base-url과 Keycloak 공개 URL이
 * 다른 환경에서는 반드시 {@code keycloak.security.authentication.issuer-uri}(또는 표준
 * {@code spring.security.oauth2.client.provider.keycloak.issuer-uri})를 실제 토큰 iss 값과 동일하게
 * 명시 설정해야 합니다. {@link #resolveEffectiveIssuerUri(String, String, String, String, String)}가
 * 이 우선순위를 반영해 계산합니다.</p>
 */
@UtilityClass
public class KeycloakIssuerUriResolver {

    private static final String REALMS_PATH = "/realms/";
    private static final String CERTS_PATH = "/protocol/openid-connect/certs";

    /**
     * Keycloak Realm의 issuer URI를 {@code base-url}/{@code relative-path}/{@code realm-name}으로부터
     * 파생(derive)합니다. 형식: {@code {baseUrl}{relativePath}/realms/{realmName}}
     *
     * <p>Low #1(슬래시 정규화): {@code baseUrl}/{@code relativePath}에 후행 슬래시가 있어도
     * {@code //realms} 형태의 잘못된 이중 슬래시가 생기지 않도록 정규화합니다.</p>
     *
     * <p><b>주의:</b> 이 메서드는 base-url로부터의 파생만 수행하며, 실제 토큰의 iss와 다를 수 있습니다
     * (클래스 javadoc 참고). 명시 설정 우선순위를 반영한 계산이 필요하면
     * {@link #resolveEffectiveIssuerUri(String, String, String, String, String)}을 사용하세요.</p>
     *
     * @param baseUrl      Keycloak 서버 base URL (예: {@code https://keycloak.example.com})
     * @param relativePath Keycloak 컨텍스트 경로 (없으면 {@code null} 또는 빈 문자열)
     * @param realmName    Realm 이름
     * @return issuer URI (예: {@code https://keycloak.example.com/realms/myrealm})
     */
    public static String resolveIssuerUri(String baseUrl, String relativePath, String realmName) {
        StringBuilder sb = new StringBuilder();
        if (baseUrl != null) {
            sb.append(stripTrailingSlashes(baseUrl));
        }
        if (relativePath != null && !relativePath.isBlank()) {
            sb.append(normalizeRelativePath(relativePath));
        }
        sb.append(REALMS_PATH).append(realmName);
        return sb.toString();
    }

    /**
     * 명시 설정을 우선하는 issuer URI 해석 — 다음 우선순위로 첫 번째로 존재하는 값을 사용합니다.
     * <ol>
     *   <li>{@code explicitIssuerUri} — {@code keycloak.security.authentication.issuer-uri}(라이브러리 전용
     *       명시 설정). 사용자가 base-url과 실제 토큰 iss가 다름을 알고 있을 때 직접 지정합니다.</li>
     *   <li>{@code standardIssuerUri} — 표준 Spring Boot OAuth2 Client/Resource-Server 프로퍼티
     *       ({@code spring.security.oauth2.resourceserver.jwt.issuer-uri} 또는
     *       {@code spring.security.oauth2.client.provider.keycloak.issuer-uri}). 이 값은 이미
     *       Back-Channel 로그아웃 {@code JwtDecoder}(및 {@code oauth2Login}의 {@code ClientRegistration})가
     *       사용하는 원천과 동일하므로, 설정만 해두면 신규 OIDC Cookie decoder와 자동으로 issuer가
     *       통일됩니다.</li>
     *   <li>{@code baseUrl}/{@code relativePath}/{@code realmName}으로부터 파생(레거시 기본 동작,
     *       하위 호환을 위한 최종 fallback).</li>
     * </ol>
     *
     * @param explicitIssuerUri {@code keycloak.security.authentication.issuer-uri} 값 (미설정 시 {@code null}/blank)
     * @param standardIssuerUri 표준 Spring Boot issuer-uri 프로퍼티 값 (미설정 시 {@code null}/blank)
     * @param baseUrl           Keycloak 서버 base URL (최종 fallback 파생에 사용)
     * @param relativePath      Keycloak 컨텍스트 경로 (최종 fallback 파생에 사용)
     * @param realmName         Realm 이름 (최종 fallback 파생에 사용)
     * @return 우선순위에 따라 결정된 issuer URI
     */
    public static String resolveEffectiveIssuerUri(
        String explicitIssuerUri, String standardIssuerUri, String baseUrl, String relativePath, String realmName) {
        if (explicitIssuerUri != null && !explicitIssuerUri.isBlank()) {
            return stripTrailingSlashes(explicitIssuerUri);
        }
        if (standardIssuerUri != null && !standardIssuerUri.isBlank()) {
            return stripTrailingSlashes(standardIssuerUri);
        }
        return resolveIssuerUri(baseUrl, relativePath, realmName);
    }

    /**
     * 후행 슬래시를 제거합니다(Low #1). 호출 전 {@code null}/blank 여부는 호출부에서 이미 검증됩니다.
     */
    private static String stripTrailingSlashes(String value) {
        String trimmed = value.trim();
        int end = trimmed.length();
        while (end > 0 && trimmed.charAt(end - 1) == '/') {
            end--;
        }
        return trimmed.substring(0, end);
    }

    /**
     * relativePath를 정규화합니다: 앞에 슬래시를 보장하고 후행 슬래시를 제거합니다.
     * 예: {@code "auth/"} -> {@code "/auth"}, {@code "/auth"} -> {@code "/auth"}, {@code "/"} -> {@code ""}.
     */
    private static String normalizeRelativePath(String relativePath) {
        String trimmed = relativePath.trim();
        if (!trimmed.startsWith("/")) {
            trimmed = "/" + trimmed;
        }
        return stripTrailingSlashes(trimmed);
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
