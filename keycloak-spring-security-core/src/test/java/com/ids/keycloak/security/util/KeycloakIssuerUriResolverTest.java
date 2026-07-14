package com.ids.keycloak.security.util;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * {@link KeycloakIssuerUriResolver} 단위 테스트.
 *
 * <p>보안 Advisory 1 High #1(issuer 원천 우선순위)과 Low #1(슬래시 정규화)을 검증합니다.</p>
 */
class KeycloakIssuerUriResolverTest {

    @Nested
    class resolveIssuerUri_테스트 {

        @Test
        void base_url과_relative_path_realm_name으로_issuer_uri를_계산한다() {
            String issuerUri = KeycloakIssuerUriResolver.resolveIssuerUri(
                "https://keycloak.example.com", "/auth", "myrealm");

            assertThat(issuerUri).isEqualTo("https://keycloak.example.com/auth/realms/myrealm");
        }

        @Test
        void relative_path가_없으면_base_url_바로_뒤에_realms가_붙는다() {
            String issuerUri = KeycloakIssuerUriResolver.resolveIssuerUri(
                "https://keycloak.example.com", null, "myrealm");

            assertThat(issuerUri).isEqualTo("https://keycloak.example.com/realms/myrealm");
        }

        @Test
        void relative_path가_빈_문자열이면_base_url_바로_뒤에_realms가_붙는다() {
            String issuerUri = KeycloakIssuerUriResolver.resolveIssuerUri(
                "https://keycloak.example.com", "", "myrealm");

            assertThat(issuerUri).isEqualTo("https://keycloak.example.com/realms/myrealm");
        }

        /**
         * Low #1: base-url에 후행 슬래시가 있어도 {@code //realms} 형태의 이중 슬래시가 생기지 않아야 한다.
         */
        @Test
        void base_url_후행_슬래시가_있어도_이중_슬래시가_생기지_않는다() {
            String issuerUri = KeycloakIssuerUriResolver.resolveIssuerUri(
                "https://keycloak.example.com/", null, "myrealm");

            assertThat(issuerUri).isEqualTo("https://keycloak.example.com/realms/myrealm");
        }

        /**
         * Low #1: relative-path가 {@code "/"}(슬래시 하나)여도 이중 슬래시가 생기지 않아야 한다.
         */
        @Test
        void relative_path가_슬래시_하나뿐이면_이중_슬래시가_생기지_않는다() {
            String issuerUri = KeycloakIssuerUriResolver.resolveIssuerUri(
                "https://keycloak.example.com", "/", "myrealm");

            assertThat(issuerUri).isEqualTo("https://keycloak.example.com/realms/myrealm");
        }

        /**
         * Low #1: relative-path에 후행 슬래시가 있어도(예: {@code "/auth/"}) 정규화되어야 한다.
         */
        @Test
        void relative_path_후행_슬래시가_있어도_이중_슬래시가_생기지_않는다() {
            String issuerUri = KeycloakIssuerUriResolver.resolveIssuerUri(
                "https://keycloak.example.com", "/auth/", "myrealm");

            assertThat(issuerUri).isEqualTo("https://keycloak.example.com/auth/realms/myrealm");
        }

        /**
         * Low #1: relative-path에 선행 슬래시가 없어도(예: {@code "auth"}) 정규화되어야 한다.
         */
        @Test
        void relative_path에_선행_슬래시가_없어도_정규화된다() {
            String issuerUri = KeycloakIssuerUriResolver.resolveIssuerUri(
                "https://keycloak.example.com", "auth", "myrealm");

            assertThat(issuerUri).isEqualTo("https://keycloak.example.com/auth/realms/myrealm");
        }

        @Test
        void base_url과_relative_path_모두_후행_슬래시가_있어도_정규화된다() {
            String issuerUri = KeycloakIssuerUriResolver.resolveIssuerUri(
                "https://keycloak.example.com/", "/auth/", "myrealm");

            assertThat(issuerUri).isEqualTo("https://keycloak.example.com/auth/realms/myrealm");
        }
    }

    @Nested
    class resolveJwkSetUri_테스트 {

        @Test
        void issuer_uri_뒤에_certs_경로가_붙는다() {
            String jwkSetUri = KeycloakIssuerUriResolver.resolveJwkSetUri(
                "https://keycloak.example.com/realms/myrealm");

            assertThat(jwkSetUri)
                .isEqualTo("https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs");
        }
    }

    @Nested
    class resolveEffectiveIssuerUri_테스트 {

        private static final String BASE_URL = "https://internal-keycloak.svc.cluster.local:8080";
        private static final String RELATIVE_PATH = "";
        private static final String REALM_NAME = "myrealm";

        /**
         * High #1 핵심 시나리오: base-url이 서버간 통신용 내부 URL이고 실제 토큰의 iss(공개 URL)와
         * 다를 때, 명시 설정({@code keycloak.security.authentication.issuer-uri})이 최우선으로 사용되어야
         * 한다.
         */
        @Test
        void 명시_issuer_uri가_설정되어_있으면_base_url_파생보다_우선한다() {
            String explicit = "https://sso.example.com/realms/myrealm";

            String issuerUri = KeycloakIssuerUriResolver.resolveEffectiveIssuerUri(
                explicit, null, BASE_URL, RELATIVE_PATH, REALM_NAME);

            assertThat(issuerUri).isEqualTo(explicit);
        }

        /**
         * High #1: 명시 issuer-uri가 없으면 표준 Spring Boot 프로퍼티
         * ({@code spring.security.oauth2.client.provider.keycloak.issuer-uri} 등)가 base-url 파생보다
         * 우선한다 — Back-Channel 로그아웃 decoder와 동일 원천으로 자동 통일된다.
         */
        @Test
        void 명시_issuer_uri가_없으면_표준_프로퍼티가_base_url_파생보다_우선한다() {
            String standard = "https://sso.example.com/realms/myrealm";

            String issuerUri = KeycloakIssuerUriResolver.resolveEffectiveIssuerUri(
                null, standard, BASE_URL, RELATIVE_PATH, REALM_NAME);

            assertThat(issuerUri).isEqualTo(standard);
        }

        @Test
        void 명시_issuer_uri와_표준_프로퍼티_모두_없으면_base_url로부터_파생한다() {
            String issuerUri = KeycloakIssuerUriResolver.resolveEffectiveIssuerUri(
                null, null, BASE_URL, RELATIVE_PATH, REALM_NAME);

            assertThat(issuerUri).isEqualTo(BASE_URL + "/realms/" + REALM_NAME);
        }

        @Test
        void 빈_문자열_설정은_미설정으로_간주되어_다음_우선순위로_넘어간다() {
            String standard = "https://sso.example.com/realms/myrealm";

            String issuerUri = KeycloakIssuerUriResolver.resolveEffectiveIssuerUri(
                "  ", standard, BASE_URL, RELATIVE_PATH, REALM_NAME);

            assertThat(issuerUri).isEqualTo(standard);
        }

        @Test
        void 명시_issuer_uri에_후행_슬래시가_있으면_정규화된다() {
            String issuerUri = KeycloakIssuerUriResolver.resolveEffectiveIssuerUri(
                "https://sso.example.com/realms/myrealm/", null, BASE_URL, RELATIVE_PATH, REALM_NAME);

            assertThat(issuerUri).isEqualTo("https://sso.example.com/realms/myrealm");
        }
    }
}
