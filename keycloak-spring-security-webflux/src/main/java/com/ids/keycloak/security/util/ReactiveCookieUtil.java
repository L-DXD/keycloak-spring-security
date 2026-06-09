package com.ids.keycloak.security.util;

import com.ids.keycloak.security.config.KeycloakCookieProperties;
import java.time.Instant;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.StringUtils;

/**
 * WebFlux 환경에서 쿠키를 조작하는 유틸리티 클래스입니다.
 *
 * <p>servlet 모듈의 {@code CookieUtil}을 Reactive {@link ServerHttpRequest}/{@link ServerHttpResponse}로 포팅합니다.
 * Reactive에서는 {@link ResponseCookie}를 사용하며, servlet의 {@code Cookie}와 달리
 * SameSite 속성을 직접 지원합니다.</p>
 */
@Slf4j
public final class ReactiveCookieUtil {

  public static final String ID_TOKEN_NAME = "id_token";
  public static final String ACCESS_TOKEN_NAME = "access_token";

  private ReactiveCookieUtil() {
  }

  /**
   * 설정 기반으로 {@link ResponseCookie}를 생성합니다.
   *
   * @param name       쿠키 이름
   * @param value      쿠키 값
   * @param maxAge     쿠키 만료 시간(초), 0이면 즉시 삭제
   * @param properties 쿠키 설정 프로퍼티
   * @return 생성된 ResponseCookie
   */
  public static ResponseCookie createCookie(
      String name, String value, int maxAge, KeycloakCookieProperties properties) {

    ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from(name, value != null ? value : "")
        .httpOnly(properties.isHttpOnly())
        .secure(properties.isSecure())
        .path(properties.getPath())
        .maxAge(maxAge);

    if (StringUtils.hasText(properties.getDomain())) {
      builder.domain(properties.getDomain());
    }
    if (StringUtils.hasText(properties.getSameSite())) {
      builder.sameSite(properties.getSameSite());
    }

    if (log.isTraceEnabled()) {
      log.trace("쿠키 생성: name={}, path={}, maxAge={}, secure={}, httpOnly={}",
          name, properties.getPath(), maxAge, properties.isSecure(), properties.isHttpOnly());
    }
    return builder.build();
  }

  /**
   * Access Token과 ID Token 쿠키를 응답에 추가합니다.
   *
   * @param response     ServerHttpResponse
   * @param accessToken  Access Token 값
   * @param accessMaxAge Access Token 만료 시간(초)
   * @param idToken      ID Token 값
   * @param idMaxAge     ID Token 만료 시간(초)
   * @param properties   쿠키 설정
   */
  public static void addTokenCookies(
      ServerHttpResponse response,
      String accessToken, int accessMaxAge,
      String idToken, int idMaxAge,
      KeycloakCookieProperties properties) {

    log.debug("[ReactiveCookieUtil] Access Token / ID Token 쿠키 추가.");
    response.addCookie(createCookie(ACCESS_TOKEN_NAME, accessToken, accessMaxAge, properties));
    response.addCookie(createCookie(ID_TOKEN_NAME, idToken, idMaxAge, properties));
  }

  /**
   * 모든 토큰 쿠키를 삭제합니다(maxAge=0으로 덮어씀).
   *
   * @param response   ServerHttpResponse
   * @param properties 쿠키 설정
   */
  public static void deleteAllTokenCookies(
      ServerHttpResponse response, KeycloakCookieProperties properties) {

    log.debug("[ReactiveCookieUtil] 모든 토큰 쿠키 삭제 요청.");
    response.addCookie(createCookie(ACCESS_TOKEN_NAME, null, 0, properties));
    response.addCookie(createCookie(ID_TOKEN_NAME, null, 0, properties));
  }

  /**
   * 요청에서 특정 이름의 쿠키 값을 조회합니다.
   *
   * @param request 요청 객체
   * @param name    쿠키 이름
   * @return 쿠키 값 (Optional)
   */
  public static Optional<String> getCookieValue(ServerHttpRequest request, String name) {
    HttpCookie cookie = request.getCookies().getFirst(name);
    if (cookie != null && StringUtils.hasText(cookie.getValue())) {
      return Optional.of(cookie.getValue());
    }
    return Optional.empty();
  }

  /**
   * 만료 시각(Epoch Second)을 기준으로 남은 수명을 계산합니다.
   *
   * @param expireTimeEpochSecond 만료 시각 (Epoch Second)
   * @return 남은 시간 (초), 0 이상
   */
  public static int calculateRestMaxAge(long expireTimeEpochSecond) {
    long now = Instant.now().getEpochSecond();
    long diff = expireTimeEpochSecond - now;
    return diff > 0 ? (int) diff : 0;
  }

  /**
   * Instant 기준으로 남은 수명을 계산합니다.
   *
   * @param expiresAt 만료 시각 (null이면 -1 반환 — 세션 쿠키)
   * @return 남은 시간 (초)
   */
  public static int calculateRestMaxAge(Instant expiresAt) {
    if (expiresAt == null) {
      return -1;
    }
    return calculateRestMaxAge(expiresAt.getEpochSecond());
  }
}
