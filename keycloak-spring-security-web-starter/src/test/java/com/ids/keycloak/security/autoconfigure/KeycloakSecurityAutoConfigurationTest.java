package com.ids.keycloak.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.LazyInitializationExcludeFilter;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.diagnostics.FailureAnalysis;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import com.ids.keycloak.security.config.KeycloakProvider;
import com.ids.keycloak.security.config.KeycloakSecurityConfigurationException;
import com.ids.keycloak.security.config.KeycloakSecuritySettings;
import com.ids.keycloak.security.config.SessionStoreType;
import com.ids.keycloak.security.token.AccessTokenValidationResult;
import com.ids.keycloak.security.token.DefaultKeycloakAccessTokenValidator;
import com.ids.keycloak.security.token.JwkSetFetcher;
import com.ids.keycloak.security.token.KeycloakAccessTokenValidator;
import com.ids.keycloak.security.token.NimbusJwkSetFetcher;

/**
 * V3-03 설정과 기동 검사 (CONF-01~05).
 */
@ExtendWith(OutputCaptureExtension.class)
class KeycloakSecurityAutoConfigurationTest {

    static final String KEY = Base64.getEncoder().encodeToString("kss-test-key-0123456789abcdefghi".getBytes());
    static final String CLIENT_SECRET = "demo-client-secret-value";

    static final String ISSUER = "https://sso.example.com/realms/demo";

    /** Keycloak 등록. issuer-uri로 설명 문서를 받는 대신 주소를 직접 넣는다 (테스트에서 네트워크를 쓰지 않으려고). */
    static ClientRegistration registration(String issuer) {
        return ClientRegistration.withRegistrationId("keycloak")
            .clientId("demo")
            .clientSecret(CLIENT_SECRET)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .scope("openid")
            .authorizationUri(ISSUER + "/protocol/openid-connect/auth")
            .tokenUri(ISSUER + "/protocol/openid-connect/token")
            .jwkSetUri(ISSUER + "/protocol/openid-connect/certs")
            .issuerUri(issuer)
            .providerConfigurationMetadata(Map.of("end_session_endpoint", ISSUER + "/protocol/openid-connect/logout"))
            .build();
    }

    static WebApplicationContextRunner runnerWith(ClientRegistration registration) {
        return new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(OAuth2ClientAutoConfiguration.class, KeycloakSecurityAutoConfiguration.class))
            .withBean(ClientRegistrationRepository.class, () -> new InMemoryClientRegistrationRepository(registration))
            .withPropertyValues(
                "keycloak.security.frontend.base-url=https://app.example.com",
                "keycloak.security.crypto.active-key-id=k1",
                "keycloak.security.crypto.keys.k1=" + KEY);
    }

    final WebApplicationContextRunner runner = runnerWith(registration(ISSUER));

    @Test
    @DisplayName("CONF-01 필수 설정이 모두 있으면 기동하고, 기동 로그에 v3·세션 저장소·앱 이름·화면 주소가 찍힌다 (비밀값 없음)")
    void startsAndLogsSummaryWithoutSecrets(CapturedOutput output) {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            KeycloakSecuritySettings settings = context.getBean(KeycloakSecuritySettings.class);
            assertThat(settings.cookieAppName()).as("앱 이름 기본값은 client id").isEqualTo("demo");
            assertThat(settings.requiredAudience()).as("aud 기본값은 client id").isEqualTo("demo");
            assertThat(settings.sessionStore()).isEqualTo(SessionStoreType.JDBC);
        });

        assertThat(output).contains("[KSS] keycloak-spring-security v3", "세션 저장소=jdbc(auth_session)", "앱 이름=demo",
            "화면 주소=https://app.example.com", "활성 키=k1");
        assertThat(output).doesNotContain(KEY).doesNotContain(CLIENT_SECRET);
    }

    @Test
    @DisplayName("CONF-02 frontend.base-url이 없으면 기동이 실패하고, 빠진 설정 이름이 오류에 나온다")
    void failsWithoutFrontendBaseUrl() {
        runner.withPropertyValues("keycloak.security.frontend.base-url=").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                .rootCause()
                .isInstanceOf(KeycloakSecurityConfigurationException.class)
                .hasMessageContaining("keycloak.security.frontend.base-url");

            FailureAnalysis analysis = new KeycloakSecurityConfigurationFailureAnalyzer().analyze(context.getStartupFailure());
            assertThat(analysis.getDescription()).contains("keycloak.security.frontend.base-url");
            assertThat(analysis.getAction()).contains("application.yml");
        });
    }

    @Test
    @DisplayName("CONF-03 암호 키가 없으면 기동이 실패한다")
    void failsWithoutKeys() {
        new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(OAuth2ClientAutoConfiguration.class, KeycloakSecurityAutoConfiguration.class))
            .withBean(ClientRegistrationRepository.class, () -> new InMemoryClientRegistrationRepository(registration(ISSUER)))
            .withPropertyValues("keycloak.security.frontend.base-url=https://app.example.com")
            .run(context -> assertThat(context.getStartupFailure())
                .rootCause()
                .hasMessageContaining("keycloak.security.crypto.keys")
                .hasMessageContaining("keycloak.security.crypto.active-key-id"));
    }

    @Test
    @DisplayName("CONF-03 암호 키가 32바이트보다 짧으면 기동이 실패하고, 오류에 키 값이 없다")
    void failsWithShortKey() {
        String shortKey = Base64.getEncoder().encodeToString("only-31-bytes-0123456789abcdefg".getBytes());

        runner.withPropertyValues("keycloak.security.crypto.keys.k1=" + shortKey).run(context -> assertThat(context.getStartupFailure())
            .rootCause()
            .hasMessageContaining("keycloak.security.crypto.keys.k1")
            .hasMessageNotContaining(shortKey));
    }

    @Test
    @DisplayName("CONF-04 frontend.base-url이 https가 아니고 localhost도 아니면 기동이 실패한다")
    void failsWithPlainHttpFrontend() {
        runner.withPropertyValues("keycloak.security.frontend.base-url=http://app.example.com").run(context ->
            assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("keycloak.security.frontend.base-url"));

        runner.withPropertyValues("keycloak.security.frontend.base-url=http://localhost:5173").run(context ->
            assertThat(context).hasNotFailed());
    }

    @Test
    @DisplayName("CONF-05 session.store=memory면 기동하지만 \"여러 대에서 쓰면 안 된다\" 경고가 찍힌다")
    void warnsOnMemoryStore(CapturedOutput output) {
        runner.withPropertyValues("keycloak.security.session.store=memory").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(KeycloakSecuritySettings.class).sessionStore()).isEqualTo(SessionStoreType.MEMORY);
        });

        assertThat(output).contains("WARN").contains("세션 저장소가 memory입니다", "서버를 여러 대 띄우면");
    }

    @Test
    @DisplayName("OAuth2 Client 등록이 없으면 기동이 실패하고, 등록 설정 이름이 오류에 나온다")
    void failsWithoutRegistration() {
        new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(OAuth2ClientAutoConfiguration.class, KeycloakSecurityAutoConfiguration.class))
            .withPropertyValues(
                "keycloak.security.frontend.base-url=https://app.example.com",
                "keycloak.security.crypto.active-key-id=k1",
                "keycloak.security.crypto.keys.k1=" + KEY)
            .run(context -> assertThat(context.getStartupFailure())
                .rootCause()
                .hasMessageContaining("spring.security.oauth2.client.registration.keycloak"));
    }

    @Test
    @DisplayName("issuer-uri가 없으면 기동이 실패하고, 설정 이름이 오류에 나온다 (토큰 iss 검사에 필요)")
    void failsWithoutIssuer() {
        runnerWith(registration(null))
            .run(context -> assertThat(context.getStartupFailure())
                .rootCause()
                .hasMessageContaining("spring.security.oauth2.client.provider.keycloak.issuer-uri"));
    }

    @Test
    @DisplayName("V3-04 액세스 토큰 검증기와 Keycloak 정보가 올라간다")
    void accessTokenValidator() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(KeycloakAccessTokenValidator.class);
            assertThat(context.getBean(KeycloakAccessTokenValidator.class)).isInstanceOf(DefaultKeycloakAccessTokenValidator.class);
            KeycloakProvider provider = context.getBean(KeycloakProvider.class);
            assertThat(provider.issuer()).isEqualTo(ISSUER);
            assertThat(provider.clientId()).isEqualTo("demo");
            assertThat(provider.jwkSetUri()).hasToString(ISSUER + "/protocol/openid-connect/certs");
            assertThat(provider.endSessionEndpoint()).hasToString(ISSUER + "/protocol/openid-connect/logout");
            assertThat(context.getBean(JwkSetFetcher.class)).isInstanceOf(NimbusJwkSetFetcher.class);
        });
    }

    @Test
    @DisplayName("V3-04 사용자가 검증기·JWKS 받기를 올리면 그것을 쓴다")
    void userValidatorWins() {
        KeycloakAccessTokenValidator custom = token -> AccessTokenValidationResult.invalid("custom");
        JwkSetFetcher fetcher = () -> "{\"keys\":[]}";

        runner.withBean(KeycloakAccessTokenValidator.class, () -> custom)
            .withBean(JwkSetFetcher.class, () -> fetcher)
            .run(context -> {
                assertThat(context.getBean(KeycloakAccessTokenValidator.class)).isSameAs(custom);
                assertThat(context.getBean(JwkSetFetcher.class)).isSameAs(fetcher);
            });
    }

    @Test
    @DisplayName("cookie.app-name·token.required-audience를 주면 client id 대신 그것을 쓴다")
    void explicitAppNameAndAudience() {
        runner.withPropertyValues("keycloak.security.cookie.app-name=portal", "keycloak.security.token.required-audience=portal-api")
            .run(context -> {
                KeycloakSecuritySettings settings = context.getBean(KeycloakSecuritySettings.class);
                assertThat(settings.cookieAppName()).isEqualTo("portal");
                assertThat(settings.requiredAudience()).isEqualTo("portal-api");
            });
    }

    @Test
    @DisplayName("지연 초기화를 켜도 설정 검사 빈은 기동 때 만든다")
    void settingsAreExcludedFromLazyInitialization() {
        runner.run(context -> {
            LazyInitializationExcludeFilter filter = context.getBean(LazyInitializationExcludeFilter.class);
            assertThat(filter.isExcluded("keycloakSecuritySettings",
                context.getBeanFactory().getBeanDefinition("keycloakSecuritySettings"), KeycloakSecuritySettings.class)).isTrue();
        });
    }

    @Test
    @DisplayName("keycloak.security.enabled=false면 아무 빈도 올리지 않는다")
    void disabled() {
        runner.withPropertyValues("keycloak.security.enabled=false", "keycloak.security.frontend.base-url=")
            .run(context -> {
                assertThat(context).hasNotFailed();
                assertThat(context).doesNotHaveBean(KeycloakSecuritySettings.class);
            });
    }

    @Test
    @DisplayName("사용자가 같은 빈(설정, keycloakSecurityClock)을 올리면 그것을 쓴다")
    void userBeansWin() {
        runner.withUserConfiguration(UserBeans.class).withPropertyValues("keycloak.security.frontend.base-url=").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(KeycloakSecuritySettings.class).cookieAppName()).isEqualTo("custom");
            assertThat(context.getBean("keycloakSecurityClock", Clock.class).instant()).isEqualTo(Instant.EPOCH);
        });
    }

    @Configuration(proxyBeanMethods = false)
    static class UserBeans {

        @Bean
        KeycloakSecuritySettings mySettings() {
            return KeycloakSecuritySettings.builder()
                .frontendBaseUrl("https://custom.example.com")
                .cookieAppName("custom")
                .requiredAudience("custom")
                .activeKeyId("k1")
                .keys(Map.of("k1", KEY))
                .build();
        }

        @Bean
        Clock keycloakSecurityClock() {
            return Clock.fixed(Instant.EPOCH, ZoneOffset.UTC);
        }
    }
}
