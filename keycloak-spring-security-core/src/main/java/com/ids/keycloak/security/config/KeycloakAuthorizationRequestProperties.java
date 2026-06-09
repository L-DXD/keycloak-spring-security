package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;

/**
 * OIDC authorize 요청에 추가할 파라미터 설정입니다.
 *
 * <p>이 설정은 OAuth2/OIDC 인가(authorization) 엔드포인트로 리다이렉트할 때
 * 쿼리 스트링에 포함할 추가 파라미터를 제어합니다.
 * 인가(authorization) 서버의 접근 제어 정책과는 무관합니다.</p>
 *
 * <p>application.yaml 예시:
 * <pre>
 * keycloak:
 *   security:
 *     authentication:
 *       authorization-request:
 *         acr-values: "gold"
 *         max-age: 3600
 *         prompt: "login"
 * </pre>
 * </p>
 *
 * <p>모든 필드의 기본값은 {@code null}이며, {@code null}인 필드는 authorize 요청에 포함되지 않습니다.
 * 세 값이 모두 {@code null}이면 기존 authorize 요청과 완전히 동일하게 동작합니다(회귀 0).</p>
 */
@Getter
@Setter
public class KeycloakAuthorizationRequestProperties {

  /**
   * OIDC {@code acr_values} 파라미터.
   *
   * <p>요청할 인증 컨텍스트 클래스 레퍼런스(Authentication Context Class Reference)를 지정합니다.
   * 공백으로 구분된 복수 값을 허용합니다(예: {@code "gold silver"}).
   * {@code null}이면 요청에 포함되지 않습니다.</p>
   */
  private String acrValues;

  /**
   * OIDC {@code max_age} 파라미터 (초 단위).
   *
   * <p>인증 경과 시간의 허용 최대값을 지정합니다. {@code 0}은 항상 재인증을 요구합니다.
   * {@code null}이면 요청에 포함되지 않습니다.</p>
   */
  private Integer maxAge;

  /**
   * OIDC {@code prompt} 파라미터.
   *
   * <p>인증 서버가 사용자에게 재인증이나 동의를 요청하는 방식을 제어합니다.
   * 허용값: {@code "none"}, {@code "login"}, {@code "consent"}, {@code "select_account"}.
   * 공백으로 구분된 복수 값도 허용합니다(예: {@code "login consent"}).
   * {@code null}이면 요청에 포함되지 않습니다.</p>
   */
  private String prompt;
}
