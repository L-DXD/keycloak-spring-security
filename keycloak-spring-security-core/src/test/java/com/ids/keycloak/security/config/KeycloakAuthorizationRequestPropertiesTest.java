package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * {@link KeycloakAuthorizationRequestProperties} 단위 테스트.
 *
 * <p>기본값, 개별 필드 설정, 바인딩 시뮬레이션을 검증합니다.</p>
 */
class KeycloakAuthorizationRequestPropertiesTest {

  @Nested
  class 기본값_검증 {

    @Test
    void 기본_acrValues는_null이다() {
      KeycloakAuthorizationRequestProperties props = new KeycloakAuthorizationRequestProperties();
      assertThat(props.getAcrValues()).isNull();
    }

    @Test
    void 기본_maxAge는_null이다() {
      KeycloakAuthorizationRequestProperties props = new KeycloakAuthorizationRequestProperties();
      assertThat(props.getMaxAge()).isNull();
    }

    @Test
    void 기본_prompt는_null이다() {
      KeycloakAuthorizationRequestProperties props = new KeycloakAuthorizationRequestProperties();
      assertThat(props.getPrompt()).isNull();
    }

    @Test
    void 세_필드_모두_null이면_설정_미적용_상태이다() {
      KeycloakAuthorizationRequestProperties props = new KeycloakAuthorizationRequestProperties();
      assertThat(props.getAcrValues()).isNull();
      assertThat(props.getMaxAge()).isNull();
      assertThat(props.getPrompt()).isNull();
    }
  }

  @Nested
  class Setter_및_바인딩_검증 {

    @Test
    void acrValues를_설정할_수_있다() {
      KeycloakAuthorizationRequestProperties props = new KeycloakAuthorizationRequestProperties();
      props.setAcrValues("gold");

      assertThat(props.getAcrValues()).isEqualTo("gold");
    }

    @Test
    void acrValues_다중값을_공백구분으로_설정할_수_있다() {
      KeycloakAuthorizationRequestProperties props = new KeycloakAuthorizationRequestProperties();
      props.setAcrValues("gold silver");

      assertThat(props.getAcrValues()).isEqualTo("gold silver");
    }

    @Test
    void maxAge를_설정할_수_있다() {
      KeycloakAuthorizationRequestProperties props = new KeycloakAuthorizationRequestProperties();
      props.setMaxAge(3600);

      assertThat(props.getMaxAge()).isEqualTo(3600);
    }

    @Test
    void maxAge_0은_유효한_값이다() {
      KeycloakAuthorizationRequestProperties props = new KeycloakAuthorizationRequestProperties();
      props.setMaxAge(0);

      assertThat(props.getMaxAge()).isEqualTo(0);
      assertThat(props.getMaxAge()).isNotNull();
    }

    @Test
    void prompt를_설정할_수_있다() {
      KeycloakAuthorizationRequestProperties props = new KeycloakAuthorizationRequestProperties();
      props.setPrompt("login");

      assertThat(props.getPrompt()).isEqualTo("login");
    }

    @Test
    void prompt_다중값을_공백구분으로_설정할_수_있다() {
      KeycloakAuthorizationRequestProperties props = new KeycloakAuthorizationRequestProperties();
      props.setPrompt("login consent");

      assertThat(props.getPrompt()).isEqualTo("login consent");
    }

    @Test
    void 세_필드를_모두_설정할_수_있다() {
      KeycloakAuthorizationRequestProperties props = new KeycloakAuthorizationRequestProperties();
      props.setAcrValues("gold");
      props.setMaxAge(0);
      props.setPrompt("login");

      assertThat(props.getAcrValues()).isEqualTo("gold");
      assertThat(props.getMaxAge()).isEqualTo(0);
      assertThat(props.getPrompt()).isEqualTo("login");
    }
  }

  @Nested
  class KeycloakAuthenticationProperties_중첩_바인딩_검증 {

    @Test
    void authorizationRequest_기본값은_null_아닌_인스턴스이다() {
      KeycloakAuthenticationProperties authProps = new KeycloakAuthenticationProperties();
      assertThat(authProps.getAuthorizationRequest()).isNotNull();
    }

    @Test
    void authorizationRequest_기본값은_모두_null이다() {
      KeycloakAuthenticationProperties authProps = new KeycloakAuthenticationProperties();
      KeycloakAuthorizationRequestProperties reqProps = authProps.getAuthorizationRequest();

      assertThat(reqProps.getAcrValues()).isNull();
      assertThat(reqProps.getMaxAge()).isNull();
      assertThat(reqProps.getPrompt()).isNull();
    }

    @Test
    void authorizationRequest_설정이_KeycloakAuthenticationProperties에_반영된다() {
      KeycloakAuthenticationProperties authProps = new KeycloakAuthenticationProperties();
      authProps.getAuthorizationRequest().setAcrValues("gold");
      authProps.getAuthorizationRequest().setMaxAge(3600);
      authProps.getAuthorizationRequest().setPrompt("login");

      assertThat(authProps.getAuthorizationRequest().getAcrValues()).isEqualTo("gold");
      assertThat(authProps.getAuthorizationRequest().getMaxAge()).isEqualTo(3600);
      assertThat(authProps.getAuthorizationRequest().getPrompt()).isEqualTo("login");
    }
  }
}
