# keycloak-spring-security 사용 가이드

Keycloak을 Spring Security에 통합하는 라이브러리입니다. 의존성 하나와 최소 설정으로 OIDC 로그인·세션·로그아웃·인가가 자동 구성됩니다.

- **지원**: JDK 17+, Spring Boot 3.5.x, Spring Security 6.5.x
- **현재 버전**: `1.10.0`
- **스택**: Servlet(Spring MVC) / **Reactive(WebFlux) — v1.8.0부터 servlet과 기능 동등** ([8. Reactive](#8-reactivewebflux))
- 이 문서는 **도입 개발자용 사용 가이드**입니다. 아키텍처/기여 규칙은 [README](../README.md) 참고.

---

## 목차
1. [빠른 시작](#1-빠른-시작)
2. [동작 방식](#2-동작-방식)
3. [설정 레퍼런스](#3-설정-레퍼런스)
4. [기능별 가이드](#4-기능별-가이드)
5. [확장점](#5-확장점)
6. [버전 노트 / 마이그레이션](#6-버전-노트--마이그레이션)
7. [트러블슈팅](#7-트러블슈팅)
8. [Reactive(WebFlux)](#8-reactivewebflux)

---

## 1. 빠른 시작

### 1.1 의존성

```gradle
// Servlet (Spring MVC)
implementation("io.github.l-dxd:keycloak-spring-security-web-starter:1.8.0")

// 또는 Reactive (WebFlux)
implementation("io.github.l-dxd:keycloak-spring-security-webflux-starter:1.8.0")
```
> Redis 세션을 쓸 경우에만 추가:
> ```gradle
> implementation("org.springframework.boot:spring-boot-starter-data-redis")
> implementation("org.springframework.session:spring-session-data-redis")
> ```

### 1.2 필수 설정

Keycloak 연결 정보와 OIDC 클라이언트 등록은 **필수**입니다.

```yaml
keycloak:
  realm-name: my-realm
  base-url: https://keycloak.example.com
  relative-path: ""                 # Keycloak 컨텍스트 경로 (보통 "" 또는 "/auth")
  response:
    type: code
  logout:
    redirect:
      uri: https://app.example.com/

spring:
  security:
    oauth2:
      client:
        registration:
          keycloak:
            client-id: my-client
            client-secret: ${KEYCLOAK_CLIENT_SECRET}
            redirect-uri: "{baseUrl}/login/oauth2/code/keycloak"
```

### 1.3 끝

별도 `SecurityConfig` 없이 기동하면 기본 `SecurityFilterChain`이 자동 등록됩니다.
- 모든 요청은 인증 필요 (`permit-all-paths` 제외)
- 미인증 시 Keycloak 로그인으로 리다이렉트 (OIDC Authorization Code)
- 로그인 성공 시 세션 생성, 이후 쿠키 기반 인증

```yaml
keycloak:
  security:
    authentication:
      permit-all-paths:
        - /public/**
        - /health
```

---

## 2. 동작 방식

### 인증 모델
기본은 **OIDC Authorization Code + 서버 세션(쿠키)** 입니다. 매 요청마다 `KeycloakAuthenticationFilter`가 세션의 인증을 확인합니다. 추가로 옵션에 따라 **Bearer Token**(API), **Basic Auth**(머신 클라이언트)를 병렬 지원합니다.

### 필터 체인 (요약)
```
MdcRequestFilter (traceId 등 MDC)
  → RateLimitFilter (옵션)
  → BasicAuthenticationFilter (옵션)
  → KeycloakAuthenticationFilter (세션 인증)
  → MdcAuthenticationFilter (userId 등 MDC)
  → AuthorizationFilter (인가)
```

### SecurityFilterChain 공존 (v1.5.0+)
라이브러리 체인은 `securityMatcher`(기본 `/**`) + `@Order(LOWEST_PRECEDENCE)`로 등록되어, **사용자가 자체 `SecurityFilterChain`(예: `/actuator` 전용)을 추가해도 공존**합니다. ([4.8](#48-securityfilterchain-공존) 참고)

---

## 3. 설정 레퍼런스

모든 설정은 `keycloak.security.*` 네임스페이스입니다.

### 3.1 인증 (`authentication`)
| 키 | 기본값 | 설명 |
|----|--------|------|
| `authentication.permit-all-paths` | `[]` | 인증 없이 허용할 경로 (Ant) |
| `authentication.default-success-url` | `/` | 로그인 성공 후 리다이렉트 |
| `authentication.login-paths` | `[/api/keycloak/login]` | body 기반 로그인으로 분류할 경로 |
| `authentication.authorization-request.acr-values` | (없음) | OIDC authorize 요청의 `acr_values` (LoA step-up). 예: `loa2` |
| `authentication.authorization-request.max-age` | (없음) | `max_age`(초). 마지막 인증 후 경과 시 재인증. 예: `1800` |
| `authentication.authorization-request.prompt` | (없음) | `prompt`. `login`(강제 재인증)/`consent`/`none`/`select_account` |

### 3.2 인가 (`authorization`)
| 키 | 기본값 | 설명 |
|----|--------|------|
| `authorization.enabled` | `false` | Keycloak Authorization Services로 모든 요청 인가 검증 |

### 3.3 세션 (`session`)
| 키 | 기본값 | 설명 |
|----|--------|------|
| `session.store-type` | `MEMORY` | `MEMORY` 또는 `REDIS` |
| `session.timeout` | `30m` | 세션 만료 시간 |

### 3.4 쿠키 (`cookie`)
| 키 | 기본값 | 설명 |
|----|--------|------|
| `cookie.http-only` | `true` | |
| `cookie.secure` | `true` | (v1.10.0부터 기본 true) HTTP 개발환경은 `false`로 해제 |
| `cookie.domain` | (없음) | |
| `cookie.path` | `/` | |
| `cookie.same-site` | (없음) | `Lax`/`Strict`/`None` |

### 3.5 에러 처리 (`error`)
| 키 | 기본값 | 설명 |
|----|--------|------|
| `error.redirect-enabled` | `false` | 인증 실패 시 리다이렉트 사용 |
| `error.ajax-returns-json` | `false` | AJAX 요청은 JSON 응답 |
| `error.authentication-failed-redirect-url` | `/login` | |
| `error.session-expired-redirect-url` | (auth 실패 URL 따름) | |
| `error.access-denied-redirect-url` | `/error/403` | |

### 3.6 Basic Auth (`basic-auth`)
| 키 | 기본값 | 설명 |
|----|--------|------|
| `basic-auth.enabled` | `false` | Direct Access Grants 기반 Basic 인증 |

### 3.7 Bearer Token (`bearer-token`)
| 키 | 기본값 | 설명 |
|----|--------|------|
| `bearer-token.enabled` | `false` | Resource Server(Introspect) + 토큰 발급 API |
| `bearer-token.token-endpoint.prefix` | `/auth` | 토큰 발급 엔드포인트 prefix (`/auth/token` 등) |

### 3.8 CSRF (`csrf`)
| 키 | 기본값 | 설명 |
|----|--------|------|
| `csrf.enabled` | `true` | |
| `csrf.ignore-paths` | `[]` | 추가 면제 경로 |

### 3.9 Rate Limiting (`rate-limit`)
| 키 | 기본값 | 설명 |
|----|--------|------|
| `rate-limit.enabled` | `false` | |
| `rate-limit.max-requests` | `5` | 윈도우 내 최대 요청 |
| `rate-limit.window-seconds` | `60` | 윈도우(초) |
| `rate-limit.block-duration-seconds` | `300` | 차단 지속(초) |
| `rate-limit.key-strategy` | `IP_AND_USERNAME` | `IP`/`USERNAME`/`IP_AND_USERNAME` |
| `rate-limit.include-basic-auth` | `true` | Basic Auth에도 적용 |

### 3.10 로깅/MDC (`logging`) — v1.6.0/1.7.0
| 키 | 기본값 | 설명 |
|----|--------|------|
| `logging.include-trace-id` | `true` | traceId MDC |
| `logging.include-http-method` | `true` | |
| `logging.include-request-uri` | `true` | |
| `logging.include-query-string` | `false` | 쿼리스트링(디코딩+길이제한+마스킹) |
| `logging.include-client-ip` | `true` | |
| `logging.include-user-agent` | `true` | userAgent(마스킹+256) |
| `logging.include-user-id` / `-username` / `-session-id` | `true` | 인증 후 사용자 정보 |
| `logging.max-query-length` | `512` | |
| `logging.max-user-agent-length` | `256` | |
| `logging.return-trace-id-header` | `true` | 응답 `X-Request-Id` 회신 |
| `logging.include-response-metrics` | `false` | status/durationMs + 종료 로그 |
| `logging.exclude-patterns` | `[/actuator/**]` | MDC 필터 제외 경로 |

### 3.11 SecurityFilterChain (`matcher`, `auto-filter-chain`) — v1.5.0
| 키 | 기본값 | 설명 |
|----|--------|------|
| `auto-filter-chain` | `true` | Keycloak 기본 체인 자동 등록 (false=직접 구성) |
| `matcher.include` | `[/**]` | Keycloak 체인 담당 경로 |
| `matcher.exclude` | `[]` | 제외 경로(다른 체인이 담당) |

---

## 4. 기능별 가이드

### 4.1 OIDC 로그인 (기본)
설정만으로 동작. 미인증 요청은 Keycloak으로 리다이렉트, 로그인 후 세션 쿠키 발급. 로그아웃은 `POST /logout`(Front-Channel) + Back-Channel(`/logout/connect/back-channel/keycloak`) 자동.

### 4.2 세션 저장소 (Memory / Redis)
```yaml
keycloak:
  security:
    session:
      store-type: redis      # 기본 memory. redis 시 위 의존성 추가 필요
      timeout: 30m
```
`memory`는 단일 인스턴스 전제. 다중 인스턴스(HA)는 `redis` 권장.

### 4.3 Bearer Token (API)
```yaml
keycloak:
  security:
    bearer-token:
      enabled: true
      token-endpoint:
        prefix: /auth
```
- Introspect(RFC 7662) 기반 온라인 검증
- 토큰 발급/갱신/로그아웃: `POST {prefix}/token`, `/refresh`, `/logout` (미인증 허용)

### 4.4 Basic Auth (머신 클라이언트)
```yaml
keycloak:
  security:
    basic-auth:
      enabled: true
```
`Authorization: Basic` 요청은 Keycloak Direct Access Grants로 인증되고 CSRF 자동 면제.

### 4.5 인가 (Authorization Services)
```yaml
keycloak:
  security:
    authorization:
      enabled: true
```
켜면 모든 요청을 Keycloak Authorization Services로 인가 검증. OIDC/Bearer/Basic 모든 인증 타입 지원(v1.4.0+). 메서드 보안은 `@EnableMethodSecurity`가 기본 활성이라 `@PreAuthorize` 등 사용 가능.

### 4.6 CSRF
기본 활성. 로그아웃·Bearer 토큰 엔드포인트·Basic Auth 요청은 자동 면제. 추가 면제는 `csrf.ignore-paths`.

### 4.7 MDC 로깅 + PII 마스킹 (v1.6.0/1.7.0)
모든 요청에 `traceId` 등이 MDC로 자동 주입되고 응답 `X-Request-Id`로 회신됩니다. query/userAgent는 **PII 마스킹**(이메일/폰/주민/카드/Bearer)이 기본 적용됩니다. 마스킹 교체/해제는 [5. 확장점](#5-확장점) 참고. 자세한 내용은 [13](13-MDC-로깅-사내표준-위임.md)/[14](14-MDC-로깅-응답메트릭-제외경로.md).

### 4.8 SecurityFilterChain 공존
`/actuator` 등 별도 체인을 추가해도 Keycloak 체인이 함께 동작합니다. 경로를 나누려면:
```yaml
keycloak:
  security:
    matcher:
      exclude: [/actuator/**]    # 이 경로는 사용자 체인이 담당
```
```java
@Bean
@Order(0)                         // Keycloak(LOWEST_PRECEDENCE)보다 앞
SecurityFilterChain actuatorChain(HttpSecurity http) throws Exception {
    http.securityMatcher("/actuator/**").authorizeHttpRequests(a -> a.anyRequest().permitAll());
    return http.build();
}
```
Keycloak 기본 체인을 끄고 직접 구성하려면 `auto-filter-chain: false`. 자세히는 [12](12-SecurityFilterChain-FailOpen-수정.md).

### 4.9 재인증 / Step-up (acr_values · max_age · prompt) (v1.9.0+)
Keycloak LoA step-up·재인증을 쓰려면 OIDC authorize 요청에 `acr_values`/`max_age`/`prompt`를 실어야 합니다. 라이브러리가 `oauth2Login`에 resolver를 연결하므로, **두 가지 방법**으로 주입할 수 있습니다.

**(1) 전역 — 프로퍼티 (모든 로그인에 동일 적용)**
```yaml
keycloak:
  security:
    authentication:
      authorization-request:
        max-age: 1800       # 마지막 인증 후 30분 경과 시 재인증
        # acr-values: loa2  # LoA step-up
        # prompt: login     # 강제 재인증
```

**(2) 경로별 Step-up — 커스텀 resolver 빈 (특정 경로에서만 강한 인증)**
`OAuth2AuthorizationRequestResolver`(servlet)/`ServerOAuth2AuthorizationRequestResolver`(reactive) 빈을 등록하면 라이브러리 기본 빈을 대체합니다(`@ConditionalOnMissingBean`). 요청 경로를 보고 동적으로 `acr_values`를 결정:
```java
@Bean
OAuth2AuthorizationRequestResolver authorizationRequestResolver(ClientRegistrationRepository repo) {
    var resolver = new DefaultOAuth2AuthorizationRequestResolver(repo, "/oauth2/authorization"); // baseUri 유지
    resolver.setAuthorizationRequestCustomizer(builder ->
        builder.additionalParameters(p -> p.put("acr_values", "loa2")));  // 조건 분기 가능
    return resolver;
}
```
> ⚠️ 커스텀 빈을 등록할 때 baseUri는 `/oauth2/authorization`을 유지해야 로그인 진입 경로가 깨지지 않습니다.
> ⚠️ `prompt=none` + `max_age`를 함께 쓰고 재인증이 필요하면 Keycloak이 `login_required` 에러를 반환합니다(정상 동작).

---

## 5. 확장점

라이브러리의 모든 빈은 `@ConditionalOnMissingBean`이라 **같은 타입 빈을 등록하면 교체**됩니다.

| 확장 | 방법 |
|------|------|
| 보안 설정 일부만 추가 | 자체 `SecurityFilterChain`에서 `http.with(KeycloakHttpConfigurer.keycloak(), Customizer.withDefaults())` |
| PII 마스킹 교체/해제 | `LoggingValueSanitizer` 빈 등록 (`NoOpLoggingValueSanitizer`로 해제) |
| Rate Limiter 구현 교체 | `RateLimiter` 빈 등록 (예: 분산 Redis 기반) |
| 로깅 컨텍스트 접근자 | `LoggingContextAccessor` 빈 등록 |

```java
// 예: PII 마스킹 끄기
@Bean
LoggingValueSanitizer loggingValueSanitizer() {
    return new NoOpLoggingValueSanitizer();
}
```

---

## 6. 버전 노트 / 마이그레이션

| 버전 | 변경 | 주의 |
|------|------|------|
| **1.10.0** ⚠️ | **보안 강화** (보안검토 13건) — reactive 백채널 JWKS 서명+aud 검증, 쿠키 secure 기본 true, XFF 신뢰 프록시, servlet SameSite/토큰 no-store, PII 마스킹 확장(JWT/OAuth2), 인가 캐시·require-user-info 토글, Redis JSON 직렬화 | **Breaking 3건** — 아래 [마이그레이션](#마이그레이션-v190--v1100-breaking) |
| **1.9.0** | OIDC authorize 파라미터(`acr_values`/`max_age`/`prompt`) 커스터마이즈 — LoA step-up·재인증 | 미설정 시 무동작(회귀 0). 경로별 step-up은 resolver 빈 재정의([4.9](#49-재인증--step-up-acr_values--max_age--prompt-v190)) |
| **1.8.0** | **Reactive(WebFlux) 스택 추가** — servlet과 기능 동등 (OIDC 로그인·세션·인가·Bearer·Basic·RateLimit·CSRF·로그아웃·MDC 로깅) | `keycloak-spring-security-webflux-starter` 신규. servlet 사용자는 영향 없음 |
| **1.7.0** | 응답 메트릭(status/durationMs, 기본 off) + exclude-patterns(/actuator) | — |
| **1.6.0** | MDC PII 마스킹 **기본 on** + userAgent/query 정제 + X-Request-Id 회신 | 로그 PII가 마스킹됨. 해제는 `NoOpLoggingValueSanitizer` |
| **1.5.0** | SecurityFilterChain Fail-Open 수정 (Bean 이름 조건 + securityMatcher) | actuator 등 자체 체인 쓰던 앱은 Keycloak 체인이 함께 켜짐 → `matcher.exclude` 또는 `auto-filter-chain: false` |
| **1.4.x** | Bearer/Basic 인가 지원, stateless 세션 분리 | — |

상세: `docs/12`, `docs/13`, `docs/14`

### 마이그레이션 (v1.9.0 → v1.10.0) (breaking)
보안 강화로 **기본 동작 3가지가 변경**됩니다. 기존 배포는 업그레이드 시 아래를 확인하세요.

| # | 변경 | 영향 | 해제/대응 |
|---|------|------|-----------|
| 1 | `cookie.secure` 기본 `false`→`true` | HTTP(비TLS) 환경에서 토큰 쿠키가 브라우저에 설정 안 됨 | 로컬/HTTP 개발환경: `keycloak.security.cookie.secure=false` |
| 2 | `X-Forwarded-For` 신뢰 변경 — `trusted-proxy-count` 기본 `0`(=`remoteAddr` 사용, XFF 무시) | XFF로 클라이언트 IP를 로깅/rate-limit하던 환경에서 IP가 프록시 IP로 바뀜 | 프록시 N개 환경: `keycloak.security.trusted-proxy-count=N` / 기존 동작 강제: `=-1`(비권장) |
| 3 | `/logout` CSRF 면제가 `bearer-token.enabled=true`일 때만 | 쿠키 OIDC만 쓰며 `/logout` CSRF 면제에 의존하던 경우 403 | CSRF 토큰을 정상 전송하거나 Bearer 모드 사용 |

그 외(회귀 없음): reactive 백채널 JWKS 검증 강화, 토큰 응답 no-store, PII 마스킹 확장은 **추가 보안일 뿐 설정 변경 불필요**. 인가 캐시(`authorization.cache.enabled`)·UserInfo 필수화(`authentication.require-user-info`)는 **기본 off라 미설정 시 영향 없음**.

---

## 7. 트러블슈팅

| 증상 | 원인 / 조치 |
|------|-------------|
| 로그인 무한 리다이렉트 | `redirect-uri`/Keycloak 클라이언트 Valid Redirect URIs 불일치 확인 |
| actuator가 갑자기 401/403 (1.5.0 업그레이드 후) | Keycloak 체인이 함께 켜진 것 → `matcher.exclude: [/actuator/**]` |
| 로그에 이메일/전화가 `***`로 (1.6.0 후) | PII 마스킹 기본 on (정상). 해제는 `NoOpLoggingValueSanitizer` |
| Redis 세션인데 `NoClassDefFoundError` | `spring-boot-starter-data-redis` + `spring-session-data-redis` 의존성 누락 |
| 다중 인스턴스에서 로그아웃이 일부만 전파 | `session.store-type: redis`로 전환 |
| 토큰 발급 API 404 | `bearer-token.enabled: true` 확인, prefix(`/auth`) 경로 확인 |

---

## 8. Reactive(WebFlux)

v1.8.0부터 **WebFlux 스택을 servlet과 동등하게 지원**합니다. 의존성만 `webflux-starter`로 바꾸면 됩니다.

```gradle
implementation("io.github.l-dxd:keycloak-spring-security-webflux-starter:1.8.0")
```

- **설정은 servlet과 100% 공유**합니다 — `keycloak.*`, `keycloak.security.*` 프로퍼티(§1.2, §3)가 그대로 적용됩니다. (core 모듈의 Properties를 양쪽이 공유)
- **기능 동등**: OIDC 로그인(`oauth2Login` + 쿠키/세션) · Bearer · Basic · 인가(Authorization Services) · Rate Limiting · CSRF · Front/Back-Channel 로그아웃 · MDC 로깅 · SecurityFilterChain 공존(Fail-Open 방지).

### servlet과의 차이 (아키텍처 특성상)

| 항목 | 차이 |
|------|------|
| 보안 체인 | `SecurityWebFilterChain`(reactive). 사용자 커스텀 체인 공존 시 `auto-filter-chain`/`matcher` 동일하게 동작 |
| 세션 | reactive `WebSession`. 다중 인스턴스는 Spring Session Reactive(Redis) 권장 |
| OAuth2 AuthorizedClient | 기본 `InMemoryReactiveOAuth2AuthorizedClientService` — **프로덕션은 Redis 기반 구현으로 교체 권장**(재시작 시 인메모리 소실) |
| MDC 로깅 | Reactor Context ↔ MDC 자동 전파는 **기본 비활성**. 활성화하려면 `keycloak.security.logging.mdc-propagation-enabled=true` (전역 Reactor `Hooks` 사용) |

### 확장점
servlet과 동일하게 `@ConditionalOnMissingBean`으로 교체 가능: `ReactiveAuthenticationManager`, `LoggingValueSanitizer`, `RateLimiter`, `SecurityWebFilterChain`(이름 `keycloakSecurityWebFilterChain`) 등.
