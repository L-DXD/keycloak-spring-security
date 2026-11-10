package com.ids.keycloak.security.sample.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;

import com.ids.keycloak.security.token.AccessTokenValidationResult;
import com.ids.keycloak.security.token.KeycloakAccessTokenValidator;

/**
 * V3-04: 실제 Keycloak이 준 액세스 토큰이 라이브러리 로컬 검증(JWT-01)을 통과한다.
 * <p>
 * realm 설정(audience mapper, typ, sid)과 검증 규칙이 맞물리는지 본다. 요청마다 Keycloak을 부르지 않는 것(JWT-09)은 #83·#84 뒤에 본다.
 */
@E2eTest
class E2eJwtRealTokenTest {

    private final E2eEnvironment env = E2eEnvironment.get();

    @Test
    @DisplayName("JWT-01 (실제 Keycloak) 로그인으로 받은 액세스 토큰이 통과하고 sub, sid가 나온다")
    void realAccessTokenPassesLocalValidation() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "bob", "bob-test-password");
        }
        OAuth2AuthorizedClient client = app.context().getBean(OAuth2AuthorizedClientService.class)
            .loadAuthorizedClient("keycloak", "bob");
        KeycloakAccessTokenValidator validator = app.context().getBean(KeycloakAccessTokenValidator.class);

        AccessTokenValidationResult result = validator.validate(client.getAccessToken().getTokenValue());

        assertThat(result.isValid()).as(result.toString()).isTrue();
        assertThat(result.subject()).isNotBlank();
        assertThat(result.sessionId()).as("back-channel 로그아웃에 쓰는 sid").isNotBlank();
        assertThat(result.jwt().getAudience()).contains("demo");
        assertThat(result.jwt().getClaimAsString("azp")).isEqualTo("demo");
    }

    @Test
    @DisplayName("JWT-05 (실제 Keycloak) 리프레시 토큰을 액세스 토큰 자리에 넣으면 거절하고, 갱신 대상도 아니다")
    void realRefreshTokenIsRejected() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
        }
        var session = app.context().getBean(OAuth2AuthorizedClientService.class).loadAuthorizedClient("keycloak", "alice");
        assertThat(session).isNotNull();
        KeycloakAccessTokenValidator validator = app.context().getBean(KeycloakAccessTokenValidator.class);

        AccessTokenValidationResult refresh = validator.validate(session.getRefreshToken().getTokenValue());

        assertThat(refresh.isValid()).isFalse();
        assertThat(refresh.isRefreshable()).isFalse();
    }
}
