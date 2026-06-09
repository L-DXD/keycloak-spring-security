package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * servlet용 {@link OAuth2AuthorizationRequestResolver} 커스터마이즈 단위 테스트.
 *
 * <p>{@link KeycloakServletAutoConfiguration.KeycloakWebSecurityConfiguration}의
 * {@code keycloakAuthorizationRequestResolver} 빈 메서드가 등록하는 customizer를
 * 직접 구성하여 검증합니다.</p>
 */
class KeycloakAuthorizationRequestResolverTest {

  private static final String REGISTRATION_ID = "keycloak";
  private static final String BASE_URI =
      OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

  /**
   * 테스트용 ClientRegistration 을 가진 InMemoryClientRegistrationRepository를 생성합니다.
   */
  private InMemoryClientRegistrationRepository buildClientRegistrationRepository() {
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
    return new InMemoryClientRegistrationRepository(registration);
  }

  /**
   * 프로덕션 customizer({@link KeycloakServletAutoConfiguration.KeycloakWebSecurityConfiguration#buildAuthorizationRequestCustomizer})를
   * 직접 호출하여 resolver를 빌드합니다.
   *
   * <p>복제 로직이 아닌 프로덕션이 실제 사용하는 코드를 검증합니다.</p>
   */
  private OAuth2AuthorizationRequestResolver buildResolver(
      String acrValues, Integer maxAge, String prompt) {

    InMemoryClientRegistrationRepository repo = buildClientRegistrationRepository();

    KeycloakAuthorizationRequestProperties props = new KeycloakAuthorizationRequestProperties();
    props.setAcrValues(acrValues);
    props.setMaxAge(maxAge);
    props.setPrompt(prompt);

    DefaultOAuth2AuthorizationRequestResolver resolver =
        new DefaultOAuth2AuthorizationRequestResolver(repo, BASE_URI);

    resolver.setAuthorizationRequestCustomizer(
        KeycloakServletAutoConfiguration.KeycloakWebSecurityConfiguration
            .buildAuthorizationRequestCustomizer(props));

    return resolver;
  }

  private MockHttpServletRequest buildRequest() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI(BASE_URI + "/" + REGISTRATION_ID);
    return request;
  }

  // ==========================================================================
  // 파라미터 포함 검증
  // ==========================================================================

  @Nested
  class 파라미터_포함_검증 {

    @Test
    void acr_values가_설정되면_additionalParameters에_포함된다() {
      OAuth2AuthorizationRequestResolver resolver = buildResolver("gold", null, null);
      OAuth2AuthorizationRequest result = resolver.resolve(buildRequest());

      assertThat(result).isNotNull();
      Map<String, Object> params = result.getAdditionalParameters();
      assertThat(params).containsEntry("acr_values", "gold");
    }

    @Test
    void max_age가_설정되면_additionalParameters에_문자열로_포함된다() {
      OAuth2AuthorizationRequestResolver resolver = buildResolver(null, 3600, null);
      OAuth2AuthorizationRequest result = resolver.resolve(buildRequest());

      assertThat(result).isNotNull();
      Map<String, Object> params = result.getAdditionalParameters();
      assertThat(params).containsEntry("max_age", "3600");
    }

    @Test
    void max_age_0은_유효값으로_포함된다() {
      OAuth2AuthorizationRequestResolver resolver = buildResolver(null, 0, null);
      OAuth2AuthorizationRequest result = resolver.resolve(buildRequest());

      assertThat(result).isNotNull();
      Map<String, Object> params = result.getAdditionalParameters();
      assertThat(params).containsEntry("max_age", "0");
    }

    @Test
    void prompt가_설정되면_additionalParameters에_포함된다() {
      OAuth2AuthorizationRequestResolver resolver = buildResolver(null, null, "login");
      OAuth2AuthorizationRequest result = resolver.resolve(buildRequest());

      assertThat(result).isNotNull();
      Map<String, Object> params = result.getAdditionalParameters();
      assertThat(params).containsEntry("prompt", "login");
    }

    @Test
    void prompt_다중값_공백구분이_그대로_포함된다() {
      OAuth2AuthorizationRequestResolver resolver = buildResolver(null, null, "login consent");
      OAuth2AuthorizationRequest result = resolver.resolve(buildRequest());

      assertThat(result).isNotNull();
      assertThat(result.getAdditionalParameters()).containsEntry("prompt", "login consent");
    }

    @Test
    void 세_파라미터_모두_설정하면_전부_포함된다() {
      OAuth2AuthorizationRequestResolver resolver = buildResolver("gold", 3600, "login");
      OAuth2AuthorizationRequest result = resolver.resolve(buildRequest());

      assertThat(result).isNotNull();
      Map<String, Object> params = result.getAdditionalParameters();
      assertThat(params)
          .containsEntry("acr_values", "gold")
          .containsEntry("max_age", "3600")
          .containsEntry("prompt", "login");
    }
  }

  // ==========================================================================
  // 미설정 시 미포함 검증 (회귀 0)
  // ==========================================================================

  @Nested
  class 미설정_시_미포함_검증 {

    @Test
    void 세_파라미터_모두_null이면_additionalParameters에_포함되지_않는다() {
      OAuth2AuthorizationRequestResolver resolver = buildResolver(null, null, null);
      OAuth2AuthorizationRequest result = resolver.resolve(buildRequest());

      assertThat(result).isNotNull();
      Map<String, Object> params = result.getAdditionalParameters();
      assertThat(params).doesNotContainKey("acr_values");
      assertThat(params).doesNotContainKey("max_age");
      assertThat(params).doesNotContainKey("prompt");
    }

    @Test
    void acr_values만_null이면_해당_파라미터만_미포함이다() {
      OAuth2AuthorizationRequestResolver resolver = buildResolver(null, 3600, "login");
      OAuth2AuthorizationRequest result = resolver.resolve(buildRequest());

      assertThat(result).isNotNull();
      Map<String, Object> params = result.getAdditionalParameters();
      assertThat(params).doesNotContainKey("acr_values");
      assertThat(params).containsEntry("max_age", "3600");
      assertThat(params).containsEntry("prompt", "login");
    }
  }
}
