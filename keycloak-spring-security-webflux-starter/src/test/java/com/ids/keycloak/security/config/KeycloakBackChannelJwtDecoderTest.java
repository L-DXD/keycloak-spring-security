package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * {@link KeycloakWebFluxAutoConfiguration.KeycloakBackChannelLogoutConfiguration#keycloakBackChannelJwtDecoder}
 * 빈 팩토리 메서드를 Spring Context 없이 직접 호출하여 검증하는 단위 테스트입니다.
 *
 * <p><b>보안 Advisory 8 대응 검증:</b>
 * <ul>
 *   <li>issuer-uri/client-id 누락·공백 시 기동(빈 생성) 자체가 실패해야 한다.</li>
 *   <li>생성된 decoder에 결합된 {@link OAuth2TokenValidator}가 실제로
 *       iss/aud/iat/exp 클레임을 강제하는지, production 코드가 조립한 validator
 *       인스턴스를 리플렉션으로 꺼내 직접 검증한다(복제 로직 아님).</li>
 * </ul>
 * </p>
 */
class KeycloakBackChannelJwtDecoderTest {

  private static final String ISSUER_URI = "http://keycloak.local/realms/test";
  private static final String CLIENT_ID = "test-client";

  private final KeycloakWebFluxAutoConfiguration.KeycloakBackChannelLogoutConfiguration configuration =
      new KeycloakWebFluxAutoConfiguration.KeycloakBackChannelLogoutConfiguration();

  // ==========================================================================
  // 보안 Advisory 8: issuer-uri/client-id 누락 시 기동 실패
  // ==========================================================================

  @Nested
  @DisplayName("issuer-uri/client-id 누락·공백 시 기동 실패")
  class 기동_실패_검증 {

    @Test
    @DisplayName("issuer-uri가 null이면 IllegalStateException")
    void issuerUri가_null이면_기동_실패() {
      assertThatThrownBy(() -> configuration.keycloakBackChannelJwtDecoder(null, CLIENT_ID))
          .isInstanceOf(IllegalStateException.class)
          .hasMessageContaining("issuer-uri");
    }

    @Test
    @DisplayName("issuer-uri가 공백 문자열이면 IllegalStateException")
    void issuerUri가_공백이면_기동_실패() {
      assertThatThrownBy(() -> configuration.keycloakBackChannelJwtDecoder("   ", CLIENT_ID))
          .isInstanceOf(IllegalStateException.class)
          .hasMessageContaining("issuer-uri");
    }

    @Test
    @DisplayName("client-id가 null이면 IllegalStateException([Advisory 8])")
    void clientId가_null이면_기동_실패() {
      assertThatThrownBy(() -> configuration.keycloakBackChannelJwtDecoder(ISSUER_URI, null))
          .isInstanceOf(IllegalStateException.class)
          .hasMessageContaining("client-id")
          .hasMessageContaining("Advisory 8");
    }

    @Test
    @DisplayName("client-id가 공백 문자열이면 IllegalStateException([Advisory 8])")
    void clientId가_공백이면_기동_실패() {
      assertThatThrownBy(() -> configuration.keycloakBackChannelJwtDecoder(ISSUER_URI, "   "))
          .isInstanceOf(IllegalStateException.class)
          .hasMessageContaining("client-id")
          .hasMessageContaining("Advisory 8");
    }

    @Test
    @DisplayName("issuer-uri/client-id가 모두 유효하면 예외 없이 decoder가 생성된다")
    void 정상_설정시_decoder_생성_성공() {
      ReactiveJwtDecoder decoder = configuration.keycloakBackChannelJwtDecoder(ISSUER_URI, CLIENT_ID);
      assertThat(decoder).isNotNull();
    }
  }

  // ==========================================================================
  // 보안 Advisory 8: iss/aud/iat/exp 필수 검증 — production validator 직접 실행
  // ==========================================================================

  @Nested
  @DisplayName("생성된 decoder에 결합된 validator가 iss/aud/iat/exp를 강제한다")
  class 필수_클레임_검증 {

    /**
     * production {@code keycloakBackChannelJwtDecoder} 빈 메서드가 실제로 조립한
     * {@link OAuth2TokenValidator}를 리플렉션으로 꺼냅니다. (복제 로직이 아닌 프로덕션 코드 자체를 검증)
     *
     * <p>{@code NimbusReactiveJwtDecoder}는 JWKS를 최초 {@code decode()} 호출 시점에만 지연 조회하므로,
     * 이 메서드 호출 자체는 네트워크 접근 없이 완료된다.</p>
     */
    private OAuth2TokenValidator<Jwt> extractValidator() {
      ReactiveJwtDecoder decoder = configuration.keycloakBackChannelJwtDecoder(ISSUER_URI, CLIENT_ID);
      @SuppressWarnings("unchecked")
      OAuth2TokenValidator<Jwt> validator =
          (OAuth2TokenValidator<Jwt>) ReflectionTestUtils.getField(decoder, "jwtValidator");
      assertThat(validator).as("keycloakBackChannelJwtDecoder의 jwtValidator 필드").isNotNull();
      return validator;
    }

    private Jwt.Builder validJwtBuilder() {
      return Jwt.withTokenValue("token-value")
          .header("alg", "RS256")
          .issuer(ISSUER_URI)
          .audience(List.of(CLIENT_ID))
          .subject("user-1")
          .issuedAt(Instant.now().minusSeconds(10))
          .expiresAt(Instant.now().plusSeconds(300));
    }

    @Test
    @DisplayName("iss/aud/iat/exp 모두 유효하면 검증 통과")
    void 모든_필수_클레임이_유효하면_검증_통과() {
      Jwt jwt = validJwtBuilder().build();

      OAuth2TokenValidatorResult result = extractValidator().validate(jwt);

      assertThat(result.hasErrors()).isFalse();
    }

    @Test
    @DisplayName("iat(issuedAt) 클레임이 없으면 검증 실패")
    void iat가_없으면_검증_실패() {
      Jwt jwt = Jwt.withTokenValue("token-value")
          .header("alg", "RS256")
          .issuer(ISSUER_URI)
          .audience(List.of(CLIENT_ID))
          .subject("user-1")
          .expiresAt(Instant.now().plusSeconds(300))
          .build();

      OAuth2TokenValidatorResult result = extractValidator().validate(jwt);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.getErrors())
          .anyMatch(error -> error.getDescription() != null && error.getDescription().contains("iat"));
    }

    @Test
    @DisplayName("exp(expiresAt) 클레임이 없으면 검증 실패")
    void exp가_없으면_검증_실패() {
      Jwt jwt = Jwt.withTokenValue("token-value")
          .header("alg", "RS256")
          .issuer(ISSUER_URI)
          .audience(List.of(CLIENT_ID))
          .subject("user-1")
          .issuedAt(Instant.now().minusSeconds(10))
          .build();

      OAuth2TokenValidatorResult result = extractValidator().validate(jwt);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.getErrors())
          .anyMatch(error -> error.getDescription() != null && error.getDescription().contains("exp"));
    }

    @Test
    @DisplayName("aud에 client-id가 없으면 검증 실패")
    void aud에_clientId가_없으면_검증_실패() {
      Jwt jwt = Jwt.withTokenValue("token-value")
          .header("alg", "RS256")
          .issuer(ISSUER_URI)
          .audience(List.of("other-client"))
          .subject("user-1")
          .issuedAt(Instant.now().minusSeconds(10))
          .expiresAt(Instant.now().plusSeconds(300))
          .build();

      OAuth2TokenValidatorResult result = extractValidator().validate(jwt);

      assertThat(result.hasErrors()).isTrue();
    }

    @Test
    @DisplayName("aud 클레임 자체가 없으면 검증 실패")
    void aud가_없으면_검증_실패() {
      Jwt jwt = Jwt.withTokenValue("token-value")
          .header("alg", "RS256")
          .issuer(ISSUER_URI)
          .subject("user-1")
          .issuedAt(Instant.now().minusSeconds(10))
          .expiresAt(Instant.now().plusSeconds(300))
          .build();

      OAuth2TokenValidatorResult result = extractValidator().validate(jwt);

      assertThat(result.hasErrors()).isTrue();
    }

    @Test
    @DisplayName("iss가 다르면 검증 실패")
    void iss가_다르면_검증_실패() {
      Jwt jwt = Jwt.withTokenValue("token-value")
          .header("alg", "RS256")
          .issuer("http://attacker.example/realms/evil")
          .audience(List.of(CLIENT_ID))
          .subject("user-1")
          .issuedAt(Instant.now().minusSeconds(10))
          .expiresAt(Instant.now().plusSeconds(300))
          .build();

      OAuth2TokenValidatorResult result = extractValidator().validate(jwt);

      assertThat(result.hasErrors()).isTrue();
    }
  }
}
