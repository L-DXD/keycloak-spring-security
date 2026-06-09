package com.ids.keycloak.security.filter;

import com.ids.keycloak.security.authentication.BasicAuthenticationToken;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.ratelimit.AuthenticationEventLogger;
import com.ids.keycloak.security.util.JwtUtil;
import com.ids.keycloak.security.util.KeycloakAuthorityExtractor;
import com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo;
import com.sd.KeycloakClient.dto.user.KeycloakUserInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * {@code Authorization: Basic} 헤더를 파싱하여 Keycloak Direct Access Grants 인증을 시도하는 WebFilter입니다.
 *
 * <p>servlet 모듈의 {@code BasicAuthenticationFilter}를 Reactive WebFilter로 포팅합니다.
 * Basic 헤더가 없으면 다음 필터로 위임하고,
 * Basic 헤더가 있으면 {@code authAsync().basicAuth(username, password)}를 Non-blocking으로 호출합니다.</p>
 *
 * <p>Basic Auth는 Stateless로 동작합니다. 매 요청마다 인증하며 세션을 생성하지 않습니다.</p>
 */
@Slf4j
@RequiredArgsConstructor
public class ReactiveBasicAuthenticationFilter implements WebFilter, Ordered {

  private static final String AUTHORIZATION_HEADER = "Authorization";
  private static final String BASIC_PREFIX = "Basic ";
  private static final String X_FORWARDED_FOR_HEADER = "X-Forwarded-For";

  private final KeycloakClient keycloakClient;
  private final String clientId;

  @Override
  public int getOrder() {
    // 인증 필터 이전에 위치 (SecurityWebFiltersOrder.AUTHENTICATION 앞)
    return Ordered.HIGHEST_PRECEDENCE + 100;
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    String authHeader = exchange.getRequest().getHeaders().getFirst(AUTHORIZATION_HEADER);

    // Basic 헤더가 없으면 다음 필터로 위임 (OIDC 쿠키 흐름)
    if (authHeader == null || !authHeader.startsWith(BASIC_PREFIX)) {
      return chain.filter(exchange);
    }

    log.debug("[BasicAuthFilter] Authorization: Basic 헤더 감지. 인증 시도.");

    String clientIp = getClientIp(exchange);
    String[] credentials = decodeBasicAuth(authHeader);

    if (credentials == null) {
      log.warn("[BasicAuthFilter] Base64 디코딩 실패 또는 잘못된 형식.");
      return chain.filter(exchange);
    }

    String username = credentials[0];
    String password = credentials[1];

    return keycloakClient.authAsync().basicAuth(username, password)
        .flatMap(response -> {
          int status = response.getStatus();

          if (status == 200) {
            KeycloakTokenInfo tokenInfo = response.getBody().orElse(null);
            if (tokenInfo == null) {
              log.warn("[BasicAuthFilter] Basic Auth 성공하였으나 응답 본문이 없습니다.");
              AuthenticationEventLogger.logFailure(
                  AuthenticationEventLogger.METHOD_BASIC, clientIp, username, "empty_response");
              return chain.filter(exchange);
            }

            // userAsync().getUserInfo(accessToken)으로 상세 권한까지 조회하여 Principal 구성
            return buildAuthenticationWithUserInfo(username, tokenInfo)
                .flatMap(auth -> {
                  log.debug("[BasicAuthFilter] Basic Auth 인증 성공: {}", username);
                  AuthenticationEventLogger.logSuccess(
                      AuthenticationEventLogger.METHOD_BASIC, clientIp, username);

                  SecurityContext securityContext = new SecurityContextImpl(auth);
                  return chain.filter(exchange)
                      .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                          Mono.just(securityContext)));
                });
          }

          if (status == 401) {
            log.warn("[BasicAuthFilter] Basic Auth 인증 실패 (401): username={}", username);
            AuthenticationEventLogger.logFailure(
                AuthenticationEventLogger.METHOD_BASIC, clientIp, username, "invalid_credentials");
            return chain.filter(exchange);
          }

          log.warn("[BasicAuthFilter] Basic Auth 예상치 못한 응답: {}", status);
          AuthenticationEventLogger.logFailure(
              AuthenticationEventLogger.METHOD_BASIC, clientIp, username, "status_" + status);
          return chain.filter(exchange);
        })
        .onErrorResume(e -> {
          log.warn("[BasicAuthFilter] Basic Auth 인증 중 오류: {}", e.getMessage());
          AuthenticationEventLogger.logFailure(
              AuthenticationEventLogger.METHOD_BASIC, clientIp, username, e.getMessage());
          return chain.filter(exchange);
        });
  }

  /**
   * Basic Auth 헤더를 Base64 디코딩하여 [username, password] 배열을 반환합니다.
   * 실패 시 null을 반환합니다.
   */
  private String[] decodeBasicAuth(String authHeader) {
    try {
      String base64Credentials = authHeader.substring(BASIC_PREFIX.length()).trim();
      String credentials = new String(
          Base64.getDecoder().decode(base64Credentials), StandardCharsets.UTF_8);
      int colonIndex = credentials.indexOf(':');
      if (colonIndex < 0) {
        return null;
      }
      return new String[]{
          credentials.substring(0, colonIndex),
          credentials.substring(colonIndex + 1)
      };
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  /**
   * Keycloak 토큰 정보로 인증된 {@link Authentication} 객체를 Reactive하게 생성합니다.
   *
   * <p>처리 흐름:
   * <ol>
   *   <li>ID Token 클레임 파싱으로 subject 추출</li>
   *   <li>{@code userAsync().getUserInfo(accessToken)}으로 UserInfo 조회 (상세 권한 포함)</li>
   *   <li>UserInfo 조회 성공 시 UserInfo 클레임 기반 권한 추출, 실패 시 ID Token 클레임 폴백</li>
   *   <li>{@link KeycloakPrincipal} 생성 후 {@link BasicAuthenticationToken} 반환</li>
   * </ol>
   * </p>
   *
   * @param username  사용자명 (subject 파싱 실패 시 폴백)
   * @param tokenInfo Keycloak 토큰 응답
   * @return 인증된 {@link Authentication}을 담은 {@link Mono}
   */
  private Mono<Authentication> buildAuthenticationWithUserInfo(
      String username, KeycloakTokenInfo tokenInfo) {

    String idToken = tokenInfo.getIdToken();
    String accessToken = tokenInfo.getAccessToken();

    String subject = JwtUtil.parseSubjectWithoutValidation(idToken);
    if (subject == null || subject.isBlank()) {
      subject = username;
    }
    final String finalSubject = subject;

    Map<String, Object> idTokenClaims = JwtUtil.parseClaimsWithoutValidation(idToken);

    return keycloakClient.userAsync().getUserInfo(accessToken)
        .flatMap(userInfoResponse -> {
          int status = userInfoResponse.getStatus();
          if (status == 200) {
            KeycloakUserInfo keycloakUserInfo = userInfoResponse.getBody().orElse(null);
            if (keycloakUserInfo != null) {
              log.debug("[BasicAuthFilter] UserInfo 조회 성공: subject={}", finalSubject);
              OidcUserInfo oidcUserInfo = convertToOidcUserInfo(keycloakUserInfo);
              // UserInfo 클레임 기반 권한 추출 (상세 권한 포함)
              Map<String, Object> userInfoClaims = oidcUserInfo.getClaims();
              // resource_access 등의 권한 클레임은 ID Token에 있으므로 병합
              Map<String, Object> mergedClaims = new HashMap<>(idTokenClaims);
              mergedClaims.putAll(userInfoClaims);
              Collection<GrantedAuthority> authorities =
                  KeycloakAuthorityExtractor.extract(mergedClaims, clientId);
              KeycloakPrincipal principal =
                  new KeycloakPrincipal(finalSubject, authorities, null, oidcUserInfo);
              return Mono.<Authentication>just(
                  new BasicAuthenticationToken(principal, idToken, accessToken));
            }
          }
          log.warn("[BasicAuthFilter] UserInfo 조회 실패 (status={}), ID Token 클레임으로 폴백", status);
          return Mono.just(buildAuthenticationFromIdToken(finalSubject, idToken, accessToken, idTokenClaims));
        })
        .onErrorResume(e -> {
          log.warn("[BasicAuthFilter] UserInfo 조회 중 오류, ID Token 클레임으로 폴백: {}", e.getMessage());
          return Mono.just(buildAuthenticationFromIdToken(finalSubject, idToken, accessToken, idTokenClaims));
        });
  }

  /**
   * UserInfo 조회 실패 시 ID Token 클레임만으로 인증 객체를 생성하는 폴백 메서드입니다.
   */
  private Authentication buildAuthenticationFromIdToken(
      String subject, String idToken, String accessToken, Map<String, Object> claims) {
    Collection<GrantedAuthority> authorities = KeycloakAuthorityExtractor.extract(claims, clientId);
    KeycloakPrincipal principal = new KeycloakPrincipal(subject, authorities, null, null);
    return new BasicAuthenticationToken(principal, idToken, accessToken);
  }

  /**
   * KeycloakUserInfo를 OidcUserInfo로 변환합니다.
   */
  private OidcUserInfo convertToOidcUserInfo(KeycloakUserInfo keycloakUserInfo) {
    Map<String, Object> claims = new HashMap<>();
    if (keycloakUserInfo.getSubject() != null) {
      claims.put("sub", keycloakUserInfo.getSubject());
    }
    if (keycloakUserInfo.getPreferredUsername() != null) {
      claims.put("preferred_username", keycloakUserInfo.getPreferredUsername());
    }
    if (keycloakUserInfo.getEmail() != null) {
      claims.put("email", keycloakUserInfo.getEmail());
    }
    if (keycloakUserInfo.getName() != null) {
      claims.put("name", keycloakUserInfo.getName());
    }
    claims.putAll(keycloakUserInfo.getOtherInfo());
    return new OidcUserInfo(claims);
  }

  private String getClientIp(ServerWebExchange exchange) {
    String xff = exchange.getRequest().getHeaders().getFirst(X_FORWARDED_FOR_HEADER);
    if (xff != null && !xff.isBlank()) {
      return xff.split(",")[0].trim();
    }
    return exchange.getRequest().getRemoteAddress() != null
        ? exchange.getRequest().getRemoteAddress().getAddress().getHostAddress()
        : "unknown";
  }
}
