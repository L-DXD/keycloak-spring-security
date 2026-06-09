package com.ids.keycloak.security.authentication;

import com.ids.keycloak.security.config.KeycloakCookieProperties;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.session.ReactiveSessionManager;
import com.ids.keycloak.security.util.ReactiveCookieUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import reactor.core.publisher.Mono;

/**
 * OIDC 로그인 성공 후 Access/ID Token을 쿠키에 저장하고 Refresh Token/sid를 세션에 저장하는
 * Reactive 성공 핸들러입니다.
 *
 * <p>servlet 모듈의 {@code OidcLoginSuccessHandler}를 Reactive(WebFlux)로 포팅합니다.
 * 저장 내용은 servlet과 완전히 동일합니다:
 * <ul>
 *   <li>Access Token → {@code access_token} 쿠키 (만료 시각 기반 maxAge)</li>
 *   <li>ID Token → {@code id_token} 쿠키 (만료 시각 기반 maxAge)</li>
 *   <li>Refresh Token → WebSession {@code KEYCLOAK_REFRESH_TOKEN}</li>
 *   <li>Keycloak SID (sid 클레임) → WebSession {@code KEYCLOAK_SESSION_ID}</li>
 *   <li>Principal Name → WebSession {@code SPRING_SECURITY_CONTEXT} (FindByIndexNameSessionRepository 호환)</li>
 * </ul>
 * </p>
 *
 * <p>처리 흐름:
 * <ol>
 *   <li>{@link OAuth2AuthenticationToken} 타입 확인 → 아니면 기본 리다이렉트만 수행</li>
 *   <li>Principal이 {@link OidcUser}인지 확인 → 아니면 기본 리다이렉트</li>
 *   <li>{@link ReactiveOAuth2AuthorizedClientService}에서 {@link OAuth2AuthorizedClient} 조회</li>
 *   <li>Access Token 쿠키, ID Token 쿠키 발급</li>
 *   <li>Refresh Token / sid / principalName 세션 저장</li>
 *   <li>SecurityContext를 {@link KeycloakPrincipal} 기반으로 교체</li>
 *   <li>defaultSuccessUrl로 리다이렉트</li>
 * </ol>
 * </p>
 */
@Slf4j
public class OidcReactiveLoginSuccessHandler implements ServerAuthenticationSuccessHandler {

  private final ReactiveOAuth2AuthorizedClientService authorizedClientService;
  private final ReactiveSessionManager sessionManager;
  private final KeycloakCookieProperties cookieProperties;
  private final RedirectServerAuthenticationSuccessHandler redirectHandler;

  public OidcReactiveLoginSuccessHandler(
      ReactiveOAuth2AuthorizedClientService authorizedClientService,
      ReactiveSessionManager sessionManager,
      KeycloakCookieProperties cookieProperties,
      String defaultSuccessUrl) {
    this.authorizedClientService = authorizedClientService;
    this.sessionManager = sessionManager;
    this.cookieProperties = cookieProperties;
    this.redirectHandler = new RedirectServerAuthenticationSuccessHandler(defaultSuccessUrl);
  }

  @Override
  public Mono<Void> onAuthenticationSuccess(
      WebFilterExchange webFilterExchange, Authentication authentication) {

    if (!(authentication instanceof OAuth2AuthenticationToken oauthToken)) {
      log.warn("[OidcSuccessHandler] OAuth2AuthenticationToken 타입이 아닙니다. type={}",
          authentication.getClass().getName());
      return redirectHandler.onAuthenticationSuccess(webFilterExchange, authentication);
    }

    if (!(oauthToken.getPrincipal() instanceof OidcUser oidcUser)) {
      log.warn("[OidcSuccessHandler] OidcUser 타입이 아닙니다.");
      return redirectHandler.onAuthenticationSuccess(webFilterExchange, authentication);
    }

    log.debug("[OidcSuccessHandler] OIDC 로그인 성공. principal={}", authentication.getName());

    // 1. AuthorizedClient에서 Access Token / Refresh Token 조회
    return authorizedClientService
        .loadAuthorizedClient(
            oauthToken.getAuthorizedClientRegistrationId(),
            authentication.getName())
        .flatMap(authorizedClient ->
            issueTokenCookiesAndSaveSession(
                webFilterExchange, authentication, oidcUser, authorizedClient))
        .switchIfEmpty(
            Mono.defer(() -> {
              log.warn("[OidcSuccessHandler] AuthorizedClient를 찾을 수 없음. 쿠키 없이 진행합니다.");
              return issueIdTokenCookieOnly(webFilterExchange, authentication, oidcUser);
            }));
  }

  /**
   * AuthorizedClient가 존재할 때: Access Token 쿠키 + ID Token 쿠키 + 세션 저장 + 리다이렉트.
   */
  private Mono<Void> issueTokenCookiesAndSaveSession(
      WebFilterExchange webFilterExchange,
      Authentication authentication,
      OidcUser oidcUser,
      OAuth2AuthorizedClient authorizedClient) {

    var exchange = webFilterExchange.getExchange();

    if (authorizedClient.getAccessToken() != null) {
      String accessTokenValue = authorizedClient.getAccessToken().getTokenValue();
      int accessMaxAge = ReactiveCookieUtil.calculateRestMaxAge(
          authorizedClient.getAccessToken().getExpiresAt());
      exchange.getResponse().addCookie(
          ReactiveCookieUtil.createCookie(
              ReactiveCookieUtil.ACCESS_TOKEN_NAME, accessTokenValue, accessMaxAge, cookieProperties));
      log.debug("[OidcSuccessHandler] access_token 쿠키 발급 완료.");
    } else {
      log.warn("[OidcSuccessHandler] AccessToken이 null입니다.");
    }

    // ID Token 쿠키
    String idTokenValue = oidcUser.getIdToken().getTokenValue();
    int idMaxAge = ReactiveCookieUtil.calculateRestMaxAge(oidcUser.getIdToken().getExpiresAt());
    exchange.getResponse().addCookie(
        ReactiveCookieUtil.createCookie(
            ReactiveCookieUtil.ID_TOKEN_NAME, idTokenValue, idMaxAge, cookieProperties));
    log.debug("[OidcSuccessHandler] id_token 쿠키 발급 완료.");

    // KeycloakPrincipal 생성
    KeycloakPrincipal keycloakPrincipal = toKeycloakPrincipal(oidcUser);
    OAuth2AuthenticationToken newToken = new OAuth2AuthenticationToken(
        keycloakPrincipal,
        keycloakPrincipal.getAuthorities(),
        ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId());

    // 세션에 Refresh Token / sid / principalName 저장
    return exchange.getSession()
        .flatMap(session -> {
          // Refresh Token 저장
          if (authorizedClient.getRefreshToken() != null) {
            sessionManager.saveRefreshToken(session, authorizedClient.getRefreshToken().getTokenValue());
            log.debug("[OidcSuccessHandler] Refresh Token 세션 저장 완료.");
          }

          // Principal Name 저장 (FindByIndexNameSessionRepository 호환 — Back-Channel 로그아웃 인덱스)
          sessionManager.savePrincipalName(session, keycloakPrincipal.getName());

          // Keycloak Session ID (sid 클레임) 저장
          String keycloakSid = oidcUser.getIdToken().getClaimAsString("sid");
          if (keycloakSid != null) {
            sessionManager.saveKeycloakSessionId(session, keycloakSid);
            log.debug("[OidcSuccessHandler] Keycloak SID 세션 저장 완료: {}", keycloakSid);
          }

          return session.save();
        })
        .then(redirectHandler.onAuthenticationSuccess(webFilterExchange, newToken));
  }

  /**
   * AuthorizedClient가 없을 때: ID Token 쿠키만 발급 후 리다이렉트.
   */
  private Mono<Void> issueIdTokenCookieOnly(
      WebFilterExchange webFilterExchange,
      Authentication authentication,
      OidcUser oidcUser) {

    var exchange = webFilterExchange.getExchange();
    String idTokenValue = oidcUser.getIdToken().getTokenValue();
    int idMaxAge = ReactiveCookieUtil.calculateRestMaxAge(oidcUser.getIdToken().getExpiresAt());
    exchange.getResponse().addCookie(
        ReactiveCookieUtil.createCookie(
            ReactiveCookieUtil.ID_TOKEN_NAME, idTokenValue, idMaxAge, cookieProperties));

    KeycloakPrincipal keycloakPrincipal = toKeycloakPrincipal(oidcUser);
    OAuth2AuthenticationToken newToken = new OAuth2AuthenticationToken(
        keycloakPrincipal,
        keycloakPrincipal.getAuthorities(),
        ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId());

    return exchange.getSession()
        .flatMap(session -> {
          sessionManager.savePrincipalName(session, keycloakPrincipal.getName());
          String keycloakSid = oidcUser.getIdToken().getClaimAsString("sid");
          if (keycloakSid != null) {
            sessionManager.saveKeycloakSessionId(session, keycloakSid);
          }
          return session.save();
        })
        .then(redirectHandler.onAuthenticationSuccess(webFilterExchange, newToken));
  }

  /**
   * OidcUser → KeycloakPrincipal 변환 (servlet OidcLoginSuccessHandler#createKeycloakPrincipal과 동일).
   */
  private KeycloakPrincipal toKeycloakPrincipal(OidcUser oidcUser) {
    return new KeycloakPrincipal(
        oidcUser.getName(),
        oidcUser.getAuthorities(),
        oidcUser.getIdToken(),
        oidcUser.getUserInfo());
  }
}
