package com.ids.keycloak.security.controller;

import com.ids.keycloak.security.dto.ReactiveLogoutRequest;
import com.ids.keycloak.security.dto.ReactiveRefreshRequest;
import com.ids.keycloak.security.dto.ReactiveTokenRequest;
import com.ids.keycloak.security.ratelimit.AuthenticationEventLogger;
import com.ids.keycloak.security.util.ClientIpResolver;
import com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import jakarta.validation.Valid;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.support.WebExchangeBindException;
import reactor.core.publisher.Mono;

/**
 * Bearer Token 발급/갱신/로그아웃 REST 컨트롤러의 Reactive 버전입니다.
 *
 * <p>servlet 모듈의 {@code KeycloakTokenController}를 Reactive(Mono 반환)로 포팅합니다.
 * RestTemplate 대신 {@code authAsync()}를 사용하여 Non-blocking으로 동작합니다.
 * {@code .block()} 호출 없이 완전히 Reactive 체이닝으로 처리합니다.</p>
 *
 * <p><b>보안:</b> 토큰 발급/갱신 응답에 {@code Cache-Control: no-store}를 설정합니다.</p>
 */
@RestController
@Slf4j
public class KeycloakReactiveTokenController {

  private final KeycloakClient keycloakClient;
  private final String prefix;
  private final int trustedProxyCount;

  public KeycloakReactiveTokenController(KeycloakClient keycloakClient, String prefix) {
    this(keycloakClient, prefix, 0);
  }

  public KeycloakReactiveTokenController(
      KeycloakClient keycloakClient, String prefix, int trustedProxyCount) {
    this.keycloakClient = keycloakClient;
    this.prefix = prefix;
    this.trustedProxyCount = trustedProxyCount;
  }

  /**
   * 토큰 발급: username/password로 Keycloak에 토큰을 요청합니다.
   * Resource Owner Password Credentials Grant.
   */
  @PostMapping("${keycloak.security.bearer-token.token-endpoint.prefix:/auth}/token")
  public Mono<ResponseEntity<Object>> issueToken(
      @RequestBody @Valid ReactiveTokenRequest request,
      ServerHttpRequest httpRequest) {

    String username = request.username();
    String clientIp = getClientIp(httpRequest);

    log.debug("[TokenAPI] 토큰 발급 요청: username={}", username);

    return keycloakClient.authAsync().basicAuth(username, request.password())
        .map(response -> {
          int status = response.getStatus();

          if (status == 200) {
            KeycloakTokenInfo tokenInfo = response.getBody().orElse(null);
            if (tokenInfo == null) {
              AuthenticationEventLogger.logFailure(
                  AuthenticationEventLogger.METHOD_TOKEN_API, clientIp, username, "empty_response");
              return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                  .<Object>body(errorBody("server_error", "Empty response from authentication server"));
            }
            AuthenticationEventLogger.logSuccess(
                AuthenticationEventLogger.METHOD_TOKEN_API, clientIp, username);
            log.debug("[TokenAPI] 토큰 발급 성공.");
            return (ResponseEntity<Object>) ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .<Object>body(buildTokenResponse(tokenInfo));
          }

          if (status == 401) {
            AuthenticationEventLogger.logFailure(
                AuthenticationEventLogger.METHOD_TOKEN_API, clientIp, username, "invalid_credentials");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .<Object>body(errorBody("invalid_grant", "Invalid user credentials"));
          }

          AuthenticationEventLogger.logFailure(
              AuthenticationEventLogger.METHOD_TOKEN_API, clientIp, username, "status_" + status);
          log.warn("[TokenAPI] 토큰 발급 실패. 상태 코드: {}", status);
          return ResponseEntity.status(status)
              .<Object>body(errorBody("server_error", "Authentication server error"));
        })
        .onErrorResume(e -> {
          log.error("[TokenAPI] Keycloak 통신 오류: {}", e.getMessage());
          return Mono.<ResponseEntity<Object>>just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
              .<Object>body(errorBody("server_error", "Failed to communicate with authentication server")));
        });
  }

  /**
   * 토큰 갱신: refreshToken으로 새 access_token을 발급받습니다.
   * grant_type=refresh_token
   */
  @PostMapping("${keycloak.security.bearer-token.token-endpoint.prefix:/auth}/refresh")
  public Mono<ResponseEntity<Object>> refreshToken(
      @RequestBody @Valid ReactiveRefreshRequest request) {

    log.debug("[TokenAPI] 토큰 갱신 요청.");

    return keycloakClient.authAsync().reissueToken(request.refreshToken())
        .map(response -> {
          int status = response.getStatus();

          if (status == 200) {
            KeycloakTokenInfo tokenInfo = response.getBody().orElse(null);
            if (tokenInfo == null) {
              return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                  .<Object>body(errorBody("server_error", "Empty response from authentication server"));
            }
            log.debug("[TokenAPI] 토큰 갱신 성공.");
            return (ResponseEntity<Object>) ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .<Object>body(buildTokenResponse(tokenInfo));
          }

          if (status == 401) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .<Object>body(errorBody("invalid_grant", "Refresh token is expired or invalid"));
          }

          log.warn("[TokenAPI] 토큰 갱신 실패. 상태 코드: {}", status);
          return ResponseEntity.status(status)
              .<Object>body(errorBody("server_error", "Authentication server error"));
        })
        .onErrorResume(e -> {
          log.error("[TokenAPI] Keycloak 통신 오류: {}", e.getMessage());
          return Mono.<ResponseEntity<Object>>just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
              .<Object>body(errorBody("server_error", "Failed to communicate with authentication server")));
        });
  }

  /**
   * 로그아웃: refreshToken을 Keycloak에서 폐기합니다.
   */
  @PostMapping("${keycloak.security.bearer-token.token-endpoint.prefix:/auth}/logout")
  public Mono<ResponseEntity<Object>> logout(
      @RequestBody @Valid ReactiveLogoutRequest request) {

    log.debug("[TokenAPI] 로그아웃 요청.");

    return keycloakClient.authAsync().logout(request.refreshToken())
        .map(response -> {
          int status = response.getStatus();

          if (status == 200 || status == 204) {
            log.debug("[TokenAPI] 로그아웃 성공.");
            return ResponseEntity.<Object>noContent().build();
          }

          if (status == 400 || status == 401) {
            return ResponseEntity.status(status)
                .<Object>body(errorBody("invalid_grant", "Token is not active"));
          }

          log.warn("[TokenAPI] 로그아웃 실패. 상태 코드: {}", status);
          return ResponseEntity.status(status)
              .<Object>body(errorBody("server_error", "Failed to logout"));
        })
        .onErrorResume(e -> {
          log.error("[TokenAPI] Keycloak 통신 오류: {}", e.getMessage());
          return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
              .<Object>body(errorBody("server_error", "Failed to communicate with authentication server")));
        });
  }

  /**
   * KeycloakTokenInfo를 Map 응답으로 변환합니다.
   */
  private Map<String, Object> buildTokenResponse(KeycloakTokenInfo tokenInfo) {
    return Map.of(
        "access_token", tokenInfo.getAccessToken() != null ? tokenInfo.getAccessToken() : "",
        "refresh_token", tokenInfo.getRefreshToken() != null ? tokenInfo.getRefreshToken() : "",
        "id_token", tokenInfo.getIdToken() != null ? tokenInfo.getIdToken() : "",
        "token_type", "Bearer",
        "expires_in", tokenInfo.getExpireTime()
    );
  }

  /**
   * M-N1: @Valid @NotBlank 위반 시 OAuth2 표준 에러 포맷({@code error/error_description}) + 400 응답.
   *
   * <p>Spring 기본 {@code timestamp/status/error/path} 포맷 대신 정상 경로 에러와 동일한
   * {@code {"error":"invalid_request","error_description":"..."}} 포맷을 반환합니다.</p>
   */
  @ExceptionHandler(WebExchangeBindException.class)
  public ResponseEntity<Map<String, String>> handleValidationException(
      WebExchangeBindException ex) {
    String description = ex.getBindingResult().getFieldErrors().stream()
        .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
        .collect(Collectors.joining(", "));
    log.debug("[TokenAPI] 요청 파라미터 검증 실패: {}", description);
    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
        .body(errorBody("invalid_request", description));
  }

  private Map<String, String> errorBody(String error, String description) {
    return Map.of("error", error, "error_description", description);
  }

  private String getClientIp(ServerHttpRequest request) {
    String remoteAddr = request.getRemoteAddress() != null
        ? request.getRemoteAddress().getAddress().getHostAddress()
        : "unknown";
    return ClientIpResolver.resolve(
        request.getHeaders().getFirst("X-Forwarded-For"),
        remoteAddr,
        trustedProxyCount
    );
  }
}
