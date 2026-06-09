package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import reactor.test.StepVerifier;

/**
 * reactive용 {@link ServerOAuth2AuthorizationRequestResolver} 커스터마이즈 단위 테스트.
 *
 * <p>{@link KeycloakWebFluxAutoConfiguration.KeycloakOAuth2ClientConfiguration}의
 * {@code keycloakServerAuthorizationRequestResolver} 빈 메서드가 등록하는 customizer를
 * 직접 구성하여 StepVerifier로 검증합니다.</p>
 */
class KeycloakServerAuthorizationRequestResolverTest {

  private static final String REGISTRATION_ID = "keycloak";

  /**
   * 테스트용 ClientRegistration 을 가진 InMemoryReactiveClientRegistrationRepository를 생성합니다.
   */
  private InMemoryReactiveClientRegistrationRepository buildClientRegistrationRepository() {
    ClientRegistration registration = ClientRegistration
        .withRegistrationId(REGISTRATION_ID)
        .clientId("test-client")
        .clientSecret("test-secret")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("http://localhost:8080/login/oauth2/code/keycloak")
        .authorizationUri("http://localhost:8180/auth/realms/test/protocol/openid-connect/auth")
        .tokenUri("http://localhost:8180/auth/realms/test/protocol/openid-connect/token")
        .scope("openid")
        .build();
    return new InMemoryReactiveClientRegistrationRepository(registration);
  }

  /**
   * 프로덕션 customizer({@link KeycloakWebFluxAutoConfiguration.KeycloakOAuth2ClientConfiguration#buildAuthorizationRequestCustomizer})를
   * 직접 호출하여 resolver를 빌드합니다.
   *
   * <p>복제 로직이 아닌 프로덕션이 실제 사용하는 코드를 검증합니다.</p>
   */
  private ServerOAuth2AuthorizationRequestResolver buildResolver(
      String acrValues, Integer maxAge, String prompt) {

    InMemoryReactiveClientRegistrationRepository repo = buildClientRegistrationRepository();

    KeycloakAuthorizationRequestProperties props = new KeycloakAuthorizationRequestProperties();
    props.setAcrValues(acrValues);
    props.setMaxAge(maxAge);
    props.setPrompt(prompt);

    DefaultServerOAuth2AuthorizationRequestResolver resolver =
        new DefaultServerOAuth2AuthorizationRequestResolver(repo);

    resolver.setAuthorizationRequestCustomizer(
        KeycloakWebFluxAutoConfiguration.KeycloakOAuth2ClientConfiguration
            .buildAuthorizationRequestCustomizer(props));

    return resolver;
  }

  private MockServerWebExchange buildExchange() {
    MockServerHttpRequest request = MockServerHttpRequest
        .method(HttpMethod.GET, URI.create("/oauth2/authorization/" + REGISTRATION_ID))
        .build();
    return MockServerWebExchange.from(request);
  }

  // ==========================================================================
  // 파라미터 포함 검증
  // ==========================================================================

  @Nested
  class 파라미터_포함_검증 {

    @Test
    void acr_values가_설정되면_additionalParameters에_포함된다() {
      ServerOAuth2AuthorizationRequestResolver resolver = buildResolver("gold", null, null);

      StepVerifier.create(resolver.resolve(buildExchange()))
          .assertNext(result -> {
            Map<String, Object> params = result.getAdditionalParameters();
            assertThat(params).containsEntry("acr_values", "gold");
          })
          .verifyComplete();
    }

    @Test
    void max_age가_설정되면_additionalParameters에_문자열로_포함된다() {
      ServerOAuth2AuthorizationRequestResolver resolver = buildResolver(null, 3600, null);

      StepVerifier.create(resolver.resolve(buildExchange()))
          .assertNext(result -> {
            Map<String, Object> params = result.getAdditionalParameters();
            assertThat(params).containsEntry("max_age", "3600");
          })
          .verifyComplete();
    }

    @Test
    void max_age_0은_유효값으로_포함된다() {
      ServerOAuth2AuthorizationRequestResolver resolver = buildResolver(null, 0, null);

      StepVerifier.create(resolver.resolve(buildExchange()))
          .assertNext(result -> {
            Map<String, Object> params = result.getAdditionalParameters();
            assertThat(params).containsEntry("max_age", "0");
          })
          .verifyComplete();
    }

    @Test
    void prompt가_설정되면_additionalParameters에_포함된다() {
      ServerOAuth2AuthorizationRequestResolver resolver = buildResolver(null, null, "login");

      StepVerifier.create(resolver.resolve(buildExchange()))
          .assertNext(result -> {
            Map<String, Object> params = result.getAdditionalParameters();
            assertThat(params).containsEntry("prompt", "login");
          })
          .verifyComplete();
    }

    @Test
    void prompt_다중값_공백구분이_그대로_포함된다() {
      ServerOAuth2AuthorizationRequestResolver resolver =
          buildResolver(null, null, "login consent");

      StepVerifier.create(resolver.resolve(buildExchange()))
          .assertNext(result -> assertThat(result.getAdditionalParameters())
              .containsEntry("prompt", "login consent"))
          .verifyComplete();
    }

    @Test
    void 세_파라미터_모두_설정하면_전부_포함된다() {
      ServerOAuth2AuthorizationRequestResolver resolver = buildResolver("gold", 3600, "login");

      StepVerifier.create(resolver.resolve(buildExchange()))
          .assertNext(result -> {
            Map<String, Object> params = result.getAdditionalParameters();
            assertThat(params)
                .containsEntry("acr_values", "gold")
                .containsEntry("max_age", "3600")
                .containsEntry("prompt", "login");
          })
          .verifyComplete();
    }
  }

  // ==========================================================================
  // 미설정 시 미포함 검증 (회귀 0)
  // ==========================================================================

  @Nested
  class 미설정_시_미포함_검증 {

    @Test
    void 세_파라미터_모두_null이면_additionalParameters에_포함되지_않는다() {
      ServerOAuth2AuthorizationRequestResolver resolver = buildResolver(null, null, null);

      StepVerifier.create(resolver.resolve(buildExchange()))
          .assertNext(result -> {
            Map<String, Object> params = result.getAdditionalParameters();
            assertThat(params).doesNotContainKey("acr_values");
            assertThat(params).doesNotContainKey("max_age");
            assertThat(params).doesNotContainKey("prompt");
          })
          .verifyComplete();
    }

    @Test
    void prompt만_null이면_해당_파라미터만_미포함이다() {
      ServerOAuth2AuthorizationRequestResolver resolver = buildResolver("gold", 0, null);

      StepVerifier.create(resolver.resolve(buildExchange()))
          .assertNext(result -> {
            Map<String, Object> params = result.getAdditionalParameters();
            assertThat(params).containsEntry("acr_values", "gold");
            assertThat(params).containsEntry("max_age", "0");
            assertThat(params).doesNotContainKey("prompt");
          })
          .verifyComplete();
    }
  }
}
