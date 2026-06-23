# WebFlux 수동 배선(Manual Wiring) 가이드 — auto-filter-chain 없이 도입하기

> zero-config(`auto-filter-chain: true`, yaml-only)가 맞지 않는 경우 — **커스텀 인가 룰, 커스텀 엔드포인트 경로, 커스텀 로깅 필터 유지, 또는 자체 보안 체인과의 공존**이 필요할 때 — 라이브러리의 Keycloak 컴포넌트를 **직접 조립**하는 패턴과, 그 과정에서 흔히 만나는 함정·해결책을 정리합니다.
>
> 수동 배선이라도 인증/세션/Bearer/로그아웃/백채널 등 **핵심 mechanics는 전부 라이브러리 컴포넌트를 재사용**합니다. 사용자가 쓰는 건 "조립(SecurityConfig)"뿐입니다.

---

## 1. zero-config vs 수동 배선

| 상황 | 권장 |
|------|------|
| 표준 OIDC 로그인/세션/Bearer/로그아웃만 | **zero-config** (`auto-filter-chain: true` + yaml) |
| 커스텀 `ReactiveAuthorizationManager`, 커스텀 엔드포인트 경로, 커스텀 로깅 WebFilter 유지, 자체 `SecurityWebFilterChain` 공존 | **수동 배선** (본 문서) |

---

## 2. 수동 배선 레시피 (WebFlux)

`KeycloakWebFluxAutoConfiguration`을 제외하고, `@EnableConfigurationProperties(KeycloakSecurityProperties.class)`로 프로퍼티만 바인딩한 뒤 라이브러리 컴포넌트를 직접 조립합니다.

```yaml
spring:
  autoconfigure:
    exclude: com.ids.keycloak.security.config.KeycloakWebFluxAutoConfiguration
```

```java
@Configuration
@EnableWebFluxSecurity
@EnableConfigurationProperties(KeycloakSecurityProperties.class)
public class SecurityConfig {

  @Value("${spring.security.oauth2.client.registration.keycloak.client-id}") String clientId;
  @Value("${keycloak.realm-name}") String realmName;

  @Bean ReactiveSessionManager reactiveSessionManager() { return new ReactiveSessionManager(); }

  @Bean ReactiveOAuth2AuthorizedClientService acs(ReactiveClientRegistrationRepository crr) {
    return new InMemoryReactiveOAuth2AuthorizedClientService(crr); // 프로덕션은 Redis 기반 구현 권장
  }

  // 함정 4: 수동 배선 시 이 빈을 직접 등록해야 oauth2Login 저장 ↔ 성공 핸들러 조회가 동일 service를 공유
  @Bean ServerOAuth2AuthorizedClientRepository authorizedClientRepository(ReactiveOAuth2AuthorizedClientService s) {
    return new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(s);
  }

  @Bean
  SecurityWebFilterChain chain(ServerHttpSecurity http, KeycloakClient kc,
      KeycloakSecurityProperties props, ReactiveSessionManager sm,
      ReactiveClientRegistrationRepository crr, ReactiveOAuth2AuthorizedClientService acs, ObjectMapper om) {

    var authManager = new KeycloakReactiveAuthenticationManager(kc, clientId);
    var converter   = new KeycloakServerAuthenticationConverter(authManager, kc, sm, props.getCookie());
    var authFilter  = new AuthenticationWebFilter(authManager);
    authFilter.setServerAuthenticationConverter(converter);

    http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
        .exceptionHandling(e -> e
            .authenticationEntryPoint(new KeycloakServerAuthenticationEntryPoint(
                om, props.getError(), props.getBasicAuth().isEnabled(), realmName))
            .accessDeniedHandler(new KeycloakServerAccessDeniedHandler(om)))
        .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
        .addFilterAt(authFilter, SecurityWebFiltersOrder.AUTHENTICATION)
        .authorizeExchange(a -> a
            .pathMatchers(props.getAuthentication().getPermitAllPaths().toArray(new String[0])).permitAll()
            // 표준이면 .anyExchange().access(new KeycloakReactiveAuthorizationManager(kc))
            // 커스텀 룰이 필요하면 직접 작성한 ReactiveAuthorizationManager 주입 (함정 6)
            .anyExchange().access(yourAuthorizationManager))
        .oauth2Login(l -> l.authenticationSuccessHandler(new OidcReactiveLoginSuccessHandler(
            acs, sm, props.getCookie(), props.getAuthentication().getDefaultSuccessUrl())))
        .oauth2ResourceServer(rs -> rs.opaqueToken(o -> o.introspector(
            new KeycloakReactiveOpaqueTokenIntrospector(kc, clientId))))   // Bearer
        .logout(l -> l.logoutUrl(KeycloakWebFluxConstants.LOGOUT_URL)
            .logoutHandler(new KeycloakReactiveLogoutHandler(kc, sm, props.getCookie()))
            .logoutSuccessHandler(new OidcClientInitiatedServerLogoutSuccessHandler(crr)));

    // 커스텀 로깅 WebFilter를 유지한다면 라이브러리 ReactiveLoggingFilter는 배선하지 않는다 (함정 1)
    return http.build();
  }
}
```

> Spring Session Reactive(Redis)를 쓰면 백채널 로그아웃을 위해 `ReactiveFindByIndexNameSessionRepository` 빈 존재 시 `ReactiveBackChannelLogoutEndpointFilter`를 `SecurityWebFiltersOrder.FIRST`로 추가하세요.

---

## 3. 함정 & 해결 (수동 배선에서 흔함)

### 함정 1 — 로깅 필터 자동 등록과 커스텀 로깅 충돌
`ReactiveLoggingFilter`/`ReactiveAuthLoggingFilter`가 `@Bean`(WebFilter)으로 등록되어 앱의 커스텀 로깅 WebFilter와 함께 동작(예: 응답 헤더 중복 설정)할 수 있습니다.
- **해결**: 커스텀 로깅을 유지하려면 autoconfig를 제외하고 수동 배선(라이브러리 로깅 필터 미배선).
- **개선 제안**: 로깅 필터를 `@ConditionalOnProperty`로 게이팅(기본 on 유지 + opt-out).

### 함정 2 — 권한(authorities)이 비어 역할 기반 인가가 실패  ★자주 헤맴
인증 매니저/introspector는 권한을 **UserInfo 클레임에서만** 추출합니다(`KeycloakAuthorityExtractor.extract(userInfoClaims, clientId)`). 그런데 Keycloak 역할(`realm_access`/`resource_access`)은 보통 **access token에만** 있고 UserInfo 엔드포인트 응답엔 포함되지 않습니다 → `authorities`가 빈 채로 인증만 성공 → 역할 기반 인가가 거부됩니다.
- **해결 A**: Keycloak 클라이언트의 realm/client roles 매퍼에서 **"Add to userinfo" 활성화**.
- **해결 B**: 커스텀 인가에서 **access token(JWT)을 직접 파싱**해 역할 추출(`AccessTokenHolder`/`BearerTokenAuthentication`에서 토큰 획득).
- **개선 제안**: 권한 소스를 UserInfo 외에 access token / ID token 클레임도 선택할 수 있게 옵션화.

### 함정 3 — SameSite 소문자 → 응답 500
`KeycloakCookieProperties.sameSite` 값이 그대로 `ResponseCookie.sameSite(...)`에 전달되어, 소문자(`lax`)면 Netty `SameSite.valueOf`가 **`No enum constant ...SameSite.lax`** 예외 → 응답이 깨집니다.
- **해결**: `keycloak.security.cookie.same-site: Lax` (첫 글자 대문자: `Lax`/`Strict`/`None`).
- **개선 제안**: 라이브러리가 sameSite 값을 대문자로 정규화하여 소문자 설정도 허용.

### 함정 4 — `AuthorizedClient를 찾을 수 없음` (수동 배선 시)
autoconfig 제외 + `oauth2Login` 직접 구성 시, `ServerOAuth2AuthorizedClientRepository` 빈을 등록하지 않으면 로그인 필터의 저장소와 `OidcReactiveLoginSuccessHandler`의 조회 대상(`ReactiveOAuth2AuthorizedClientService`)이 달라 client를 못 찾습니다.
- **해결**: §2처럼 `AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(service)` 빈을 등록(저장·조회가 동일 service 공유).

### 함정 5 — 미인증인데 401 JSON만, 로그인 리다이렉트 안 함
`KeycloakServerAuthenticationEntryPoint`는 `error.redirect-enabled` 기본 false → 브라우저 미인증에도 401 JSON. OIDC 브라우저 로그인 흐름을 원하면:
```yaml
keycloak.security.error:
  redirect-enabled: true
  authentication-failed-redirect-url: /oauth2/authorization/keycloak
  # ajax-returns-json: true   # XHR/JSON 요청은 리다이렉트 대신 401
```
Bearer 요청은 entry point가 자동으로 401 처리합니다.

### 함정 6 — Configurer가 인가까지 포함해 닫혀 커스텀 인가 주입 불가
`KeycloakWebFluxSecurityConfigurer.configure()`는 `authorizeExchange`까지 포함해 `http.build()`로 체인을 닫습니다 → 커스텀 `ReactiveAuthorizationManager`를 끼울 seam이 없습니다.
- **해결**: Configurer를 쓰지 않고 §2처럼 컴포넌트를 직접 조립 + `authorizeExchange`를 직접 구성.
- **개선 제안**: Configurer에 `authorizeExchange` Customizer 파라미터 추가, 또는 인가 매니저를 `@ConditionalOnMissingBean`으로 주입 가능하게.

---

## 4. 개선 제안 요약 (백로그 후보)
1. 로깅 필터 `@ConditionalOnProperty` 게이팅 (함정 1)
2. 권한 소스 옵션화: UserInfo / access token / ID token (함정 2)
3. SameSite 값 대문자 정규화 (함정 3)
4. 수동 배선 시 AuthorizedClient repository 등록 문서화/헬퍼 (함정 4)
5. Configurer에 authz 주입 seam (함정 6)

> 1~3은 기본 동작 유지하며 회귀 없이 추가 가능, 4~5는 수동 배선 사용성 개선.
