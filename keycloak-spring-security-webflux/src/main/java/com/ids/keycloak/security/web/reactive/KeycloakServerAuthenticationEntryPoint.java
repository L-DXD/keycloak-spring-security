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
 *   <li>redirect-enabled=false(기본) + oauth2LoginRedirectEnabled=true(기본) + oauth2Login 등록됨(C-B) +
 *       Basic Auth 아님 + OAuth2 authorization/callback 경로 아님(C-B) + 비-AJAX(HTML) → OAuth2 로그인
 *       authorization endpoint로 리다이렉트 (C-1)</li>
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

  /** OAuth2 로그인 authorize 엔드포인트 경로 prefix (C-B 자기참조 가드). */
  private static final String OAUTH2_AUTHORIZATION_PREFIX = "/oauth2/authorization/";
  /** OAuth2 로그인 콜백(redirect_uri) 경로 prefix (C-B 자기참조 가드). */
  private static final String OAUTH2_CALLBACK_PREFIX = "/login/oauth2/code/";

  private final ObjectMapper objectMapper;
  private final KeycloakErrorProperties errorProperties;
  private final boolean basicAuthEnabled;
  private final String realmName;
  private final boolean oauth2LoginAvailable;

  /**
   * API 모드(redirect 없음) 기본 생성자.
   */
  public KeycloakServerAuthenticationEntryPoint(ObjectMapper objectMapper) {
    this(objectMapper, new KeycloakErrorProperties(), false, null);
  }

  /**
   * 전체 분기 지원 생성자.
   *
   * <p>{@code oauth2LoginAvailable}은 {@code true}로 간주한다(하위 호환) — 실제로 oauth2Login이
   * 등록되지 않은 애플리케이션에서 C-B 회귀(리다이렉트 대상 필터가 없어 무한 302)를 피하려면
   * {@link #KeycloakServerAuthenticationEntryPoint(ObjectMapper, KeycloakErrorProperties, boolean,
   * String, boolean)} 생성자로 실제 등록 여부를 전달해야 한다. Auto-Configuration 경로는 이미 그
   * 생성자를 사용한다.</p>
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
    this(objectMapper, errorProperties, basicAuthEnabled, realmName, true);
  }

  /**
   * oauth2Login 등록 여부까지 지정하는 생성자 (C-B).
   *
   * @param oauth2LoginAvailable {@code ReactiveClientRegistrationRepository}/
   *     {@code ReactiveOAuth2AuthorizedClientService}가 모두 존재해 {@code oauth2Login}이 실제로
   *     체인에 등록되었는지 여부. {@code false}면 {@code /oauth2/authorization/{registrationId}}를
   *     처리할 필터가 아예 없으므로, {@code oauth2LoginRedirectEnabled=true}여도 리다이렉트를
   *     보내지 않고 401 JSON을 반환한다(그 경로 자체도 미인증으로 막혀 영구 302 루프가 되는 것을
   *     방지).
   */
  public KeycloakServerAuthenticationEntryPoint(
      ObjectMapper objectMapper,
      KeycloakErrorProperties errorProperties,
      boolean basicAuthEnabled,
      String realmName,
      boolean oauth2LoginAvailable) {
    this.objectMapper = objectMapper;
    this.errorProperties = errorProperties;
    this.basicAuthEnabled = basicAuthEnabled;
    this.realmName = realmName;
    this.oauth2LoginAvailable = oauth2LoginAvailable;
  }

  @Override
  public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
    return Mono.defer(() -> {
      ServerHttpResponse response = exchange.getResponse();
      String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

      // 항목 6: servlet 모듈(KeycloakAuthenticationEntryPoint)과 동일하게, 이 EntryPoint는 인증
      // 실패의 최종 처리 지점이므로 사유를 운영 기본 로그 레벨(INFO)에서 추적 가능해야 한다.
      // 401 자체는 정상적인 보호 동작이므로 WARN까지는 올리지 않는다.
      log.info("[EntryPoint] 인증 실패 - path={}, errorCode={}",
          exchange.getRequest().getPath(), resolveErrorCode(ex).getCode());

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

      // C-1: servlet 모듈(KeycloakAuthenticationEntryPoint)과 동일하게, redirect-enabled=false
      // (API 모드, 기본값) 상태에서도 Authorization: Basic 헤더를 실은 요청(basicAuthEnabled=false로
      // 꺼져 있어도 마찬가지 — Authorization 헤더 보유 자체가 "프로그래밍적 클라이언트"의 근거)이 아니고
      // AJAX/명시적 JSON 요청이 아닌(즉 브라우저의 HTML 네비게이션으로 보이는) 요청은 기본적으로 OAuth2
      // 로그인 authorization endpoint로 리다이렉트한다. oauth2LoginRedirectEnabled=false로 끄면 항상
      // 401 JSON을 반환한다.
      // C-B: oauth2Login이 실제로 등록되지 않았다면(oauth2LoginAvailable=false) 이 리다이렉트 대상
      // 자체를 처리할 필터가 없어 그 경로도 미인증으로 남아 EntryPoint가 다시 호출되는 무한 302
      // 루프가 된다 — 이 경우 리다이렉트 대신 401 JSON을 반환한다. 또한 실패한 요청이 이미
      // authorization/callback 경로 자신이면(자기참조) 리다이렉트하지 않는다(무한 루프 가드).
      boolean basicAuthHeaderPresent = authHeader != null && authHeader.startsWith(BASIC_PREFIX);
      if (errorProperties.isOauth2LoginRedirectEnabled()
          && oauth2LoginAvailable
          && !basicAuthHeaderPresent
          && !isOAuth2FlowPath(exchange)
          && !isAjaxRequest(exchange)) {
        String authorizationUrl = buildOAuth2AuthorizationUrl(exchange);
        log.debug("[EntryPoint] 인증 실패 — OAuth2 로그인으로 리다이렉트: {}", authorizationUrl);
        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().setLocation(URI.create(authorizationUrl));
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
   * OAuth2 로그인 authorization endpoint URL을 생성합니다 (C-1, H-A).
   * <p>
   * Spring Security {@code oauth2Login}의 기본 authorization endpoint 규약
   * ({@code /oauth2/authorization/{registrationId}})을 그대로 따른다.
   * </p>
   * <p>
   * <b>H-A (context-path 배포 404):</b> {@code /}로 시작하는 경로로 리다이렉트하면 컨테이너
   * 루트(서버 도메인) 기준으로 해석된다. {@code /myapp} 같은 context-path로 배포된 애플리케이션에서
   * context-path를 붙이지 않으면 404가 된다. servlet 모듈의
   * {@code HttpServletRequest#getContextPath()}에 대응하는
   * {@code exchange.getRequest().getPath().contextPath().value()}를 prefix로 붙인다(context-path가
   * 없는 환경에서는 빈 문자열이므로 회귀가 없다).
   * </p>
   */
  private String buildOAuth2AuthorizationUrl(ServerWebExchange exchange) {
    String contextPath = exchange.getRequest().getPath().contextPath().value();
    return contextPath + OAUTH2_AUTHORIZATION_PREFIX + errorProperties.getOauth2LoginRegistrationId();
  }

  /**
   * 실패한 요청 자체가 OAuth2 authorization/callback 경로인지 확인합니다 (C-B 자기참조 가드).
   * <p>
   * 정상 구성이라면 이 경로들은 Spring Security의 OAuth2 관련 필터가 이 EntryPoint보다 먼저
   * 처리하지만, oauth2Login 미등록 등 예외적인 구성에서 이 경로 자체가 미인증으로 EntryPoint까지
   * 도달하면, 여기서 다시 같은 authorization endpoint로 리다이렉트해 무한 루프가 될 수 있다. 이를
   * 방지하기 위해 이 경로들은 리다이렉트 대상에서 제외하고 401 JSON으로 처리한다.
   * </p>
   */
  private boolean isOAuth2FlowPath(ServerWebExchange exchange) {
    String path = exchange.getRequest().getPath().pathWithinApplication().value();
    return path.startsWith(OAUTH2_AUTHORIZATION_PREFIX) || path.startsWith(OAUTH2_CALLBACK_PREFIX);
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
