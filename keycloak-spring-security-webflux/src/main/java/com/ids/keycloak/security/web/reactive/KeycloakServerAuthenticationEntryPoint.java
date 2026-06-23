package com.ids.keycloak.security.web.reactive;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.config.KeycloakErrorProperties;
import com.ids.keycloak.security.exception.ErrorCode;
import com.ids.keycloak.security.exception.KeycloakSecurityException;
import java.net.URI;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Reactive 환경에서 인증(Authentication) 실패 시 호출되는 핸들러입니다.
 *
 * <p>servlet 모듈의 {@code KeycloakAuthenticationEntryPoint}를 WebFlux로 포팅합니다.
 * 요청 유형에 따라 다음 분기를 수행합니다:
 * <ol>
 *   <li>Bearer Token 요청 ({@code Authorization: Bearer}) → WWW-Authenticate: Bearer 헤더 + 401</li>
 *   <li>Basic Auth 요청 ({@code Authorization: Basic}, basicAuthEnabled=true) → WWW-Authenticate: Basic realm 헤더</li>
 *   <li>redirect-enabled=true + AJAX 요청 + ajaxReturnsJson=true → 401 JSON</li>
 *   <li>redirect-enabled=true (비-AJAX) → 로그인/세션만료 URL로 리다이렉트</li>
 *   <li>그 외 (API 모드) → 401 JSON</li>
 * </ol>
 * </p>
 */
@Slf4j
public class KeycloakServerAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

  private static final String BEARER_PREFIX = "Bearer ";
  private static final String BASIC_PREFIX = "Basic ";
  private static final String AJAX_HEADER = "X-Requested-With";
  private static final String AJAX_HEADER_VALUE = "XMLHttpRequest";

  private final ObjectMapper objectMapper;
  private final KeycloakErrorProperties errorProperties;
  private final boolean basicAuthEnabled;
  private final String realmName;

  /**
   * API 모드(redirect 없음) 기본 생성자.
   */
  public KeycloakServerAuthenticationEntryPoint(ObjectMapper objectMapper) {
    this(objectMapper, new KeycloakErrorProperties(), false, null);
  }

  /**
   * 전체 분기 지원 생성자.
   *
   * @param objectMapper      JSON 직렬화
   * @param errorProperties   redirect/ajaxReturnsJson/URL 설정
   * @param basicAuthEnabled  Basic Auth 요청 분기 활성 여부
   * @param realmName         WWW-Authenticate: Basic realm 이름
   */
  public KeycloakServerAuthenticationEntryPoint(
      ObjectMapper objectMapper,
      KeycloakErrorProperties errorProperties,
      boolean basicAuthEnabled,
      String realmName) {
    this.objectMapper = objectMapper;
    this.errorProperties = errorProperties;
    this.basicAuthEnabled = basicAuthEnabled;
    this.realmName = realmName;
  }

  @Override
  public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
    return Mono.defer(() -> {
      ServerHttpResponse response = exchange.getResponse();
      String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

      // 1. Bearer Token 요청 → WWW-Authenticate: Bearer 위임
      if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
        log.debug("[EntryPoint] Bearer Token 요청 감지 — WWW-Authenticate: Bearer 응답");
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().set(HttpHeaders.WWW_AUTHENTICATE,
            "Bearer realm=\"" + getRealmName() + "\", error=\"invalid_token\"");
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        return writeJsonError(response, resolveErrorCode(ex), ex.getMessage());
      }

      // 2. Basic Auth 요청 (basicAuthEnabled=true) → WWW-Authenticate: Basic
      if (basicAuthEnabled && authHeader != null && authHeader.startsWith(BASIC_PREFIX)) {
        log.debug("[EntryPoint] Basic Auth 요청 감지 — WWW-Authenticate: Basic 응답");
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().set(HttpHeaders.WWW_AUTHENTICATE,
            "Basic realm=\"" + getRealmName() + "\"");
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        return writeJsonError(response, resolveErrorCode(ex), ex.getMessage());
      }

      // 3. redirect-enabled 모드
      if (errorProperties.isRedirectEnabled()) {
        // AJAX 요청이고 ajaxReturnsJson=true면 JSON 응답
        if (errorProperties.isAjaxReturnsJson() && isAjaxRequest(exchange)) {
          log.debug("[EntryPoint] AJAX 요청 — JSON 401 응답");
          response.setStatusCode(HttpStatus.UNAUTHORIZED);
          response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
          return writeJsonError(response, ErrorCode.AUTHENTICATION_FAILED, ex.getMessage());
        }

        // 브라우저 리다이렉트
        String redirectUrl = determineRedirectUrl(exchange);
        log.debug("[EntryPoint] 인증 실패 — 리다이렉트: {}", redirectUrl);
        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().setLocation(URI.create(redirectUrl));
        return response.setComplete();
      }

      // 4. API 모드 기본: 401 JSON
      log.debug("[EntryPoint] 인증 실패 — 401 JSON 응답");
      response.setStatusCode(HttpStatus.UNAUTHORIZED);
      response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
      return writeJsonError(response, resolveErrorCode(ex), ex.getMessage());
    });
  }

  /**
   * 세션 만료/인증 실패에 따라 리다이렉트 URL을 결정합니다.
   */
  private String determineRedirectUrl(ServerWebExchange exchange) {
    // WebFlux에서는 HttpSession 직접 접근 불가, 쿠키 기반 세션 ID 확인으로 대체
    // 세션 쿠키가 있으면 세션 만료로 간주
    boolean hasSessionCookie = exchange.getRequest().getCookies().containsKey("SESSION");
    if (hasSessionCookie) {
      return errorProperties.getEffectiveSessionExpiredRedirectUrl();
    }
    return errorProperties.getAuthenticationFailedRedirectUrl();
  }

  /**
   * AJAX 요청 여부를 판단합니다.
   *
   * <p>판정 기준:
   * <ol>
   *   <li>{@code X-Requested-With: XMLHttpRequest} 헤더가 있으면 AJAX</li>
   *   <li>Accept 헤더에 {@code text/html}이 포함되어 있으면 브라우저 네비게이션 → non-AJAX</li>
   *   <li>Accept 헤더에 명시적 JSON(subtype이 "json" 또는 "+json"으로 끝나는 타입) 타입이 있고
   *       text/html이 없으면 AJAX</li>
   *   <li>{@code Accept: *&#47;*} 단독이나 Accept 헤더 없음 → non-AJAX</li>
   * </ol>
   * 브라우저는 보통 {@code text/html,...,*&#47;*;q=0.8} 형태로 Accept를 보내므로
   * {@code *&#47;*} 와일드카드 매칭({@link MediaType#includes})을 사용하면
   * application/json과 compatible로 판정되어 오분류가 발생한다. 이를 방지하기 위해
   * subtype을 직접 비교한다.
   */
  private boolean isAjaxRequest(ServerWebExchange exchange) {
    HttpHeaders headers = exchange.getRequest().getHeaders();
    if (AJAX_HEADER_VALUE.equalsIgnoreCase(headers.getFirst(AJAX_HEADER))) {
      return true;
    }
    List<MediaType> accepts = headers.getAccept();
    boolean acceptsHtml = accepts.stream().anyMatch(MediaType.TEXT_HTML::isCompatibleWith);
    boolean explicitJson = accepts.stream()
        .anyMatch(mt -> "json".equals(mt.getSubtype()) || mt.getSubtype().endsWith("+json"));
    return explicitJson && !acceptsHtml;
  }

  /**
   * 예외 원인에서 ErrorCode를 추출합니다.
   */
  private ErrorCode resolveErrorCode(AuthenticationException ex) {
    if (ex.getCause() instanceof KeycloakSecurityException cause) {
      return cause.getErrorCode();
    }
    return ErrorCode.AUTHENTICATION_FAILED;
  }

  private String getRealmName() {
    return (realmName != null && !realmName.isBlank()) ? realmName : "keycloak";
  }

  /**
   * JSON 에러 응답을 응답 스트림에 씁니다.
   */
  private Mono<Void> writeJsonError(
      ServerHttpResponse response, ErrorCode errorCode, String fallbackMessage) {
    String message = (fallbackMessage != null) ? fallbackMessage : errorCode.getDefaultMessage();
    try {
      byte[] bytes = objectMapper.writeValueAsBytes(
          new ErrorResponse(errorCode.getCode(), message));
      DataBuffer buffer = response.bufferFactory().wrap(bytes);
      return response.writeWith(Mono.just(buffer));
    } catch (JsonProcessingException e) {
      response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
      byte[] bytes = getFallbackBytes(errorCode);
      DataBuffer buffer = response.bufferFactory().wrap(bytes);
      return response.writeWith(Mono.just(buffer));
    }
  }

  private byte[] getFallbackBytes(ErrorCode errorCode) {
    try {
      return objectMapper.writeValueAsBytes(
          new ErrorResponse(errorCode.getCode(), errorCode.getDefaultMessage()));
    } catch (JsonProcessingException e) {
      return String.format("{\"code\":\"%s\",\"message\":\"%s\"}",
          errorCode.getCode(), errorCode.getDefaultMessage()).getBytes();
    }
  }

  /** JSON 에러 응답 레코드 */
  private record ErrorResponse(String code, String message) {
  }
}
