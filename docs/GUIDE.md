# keycloak-spring-security 사용 가이드

Keycloak을 Spring Security에 통합하는 라이브러리입니다. 의존성 하나와 최소 설정으로 OIDC 로그인·세션·로그아웃·인가가 자동 구성됩니다.

- **지원**: JDK 17+, Spring Boot 3.5.x, Spring Security 6.5.x
- **현재 버전**: `2.0.2`
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
implementation("io.github.l-dxd:keycloak-spring-security-web-starter:2.0.2")

// 또는 Reactive (WebFlux)
implementation("io.github.l-dxd:keycloak-spring-security-webflux-starter:2.0.2")
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
| `authentication.issuer-uri` | (없음) | OIDC ID/Access Token 서명 검증용 issuer(`iss`) 명시 지정. 미설정 시 표준 Spring Boot `spring.security.oauth2.resourceserver.jwt.issuer-uri`/`...client.provider.keycloak.issuer-uri` → `base-url` 파생 순으로 해석(보안 Advisory 1) |

### 3.2 인가 (`authorization`)
| 키 | 기본값 | 설명 |
|----|--------|------|
| `authorization.enabled` | `false` | Keycloak Authorization Services로 모든 요청 인가 검증 |

### 3.3 세션 (`session`)
| 키 | 기본값 | 설명 |
|----|--------|------|
| `session.store-type` | `MEMORY` | `MEMORY` 또는 `REDIS` |
| `session.timeout` | `30m` | 세션 만료 시간 |
| `session.max-sessions` | `10000` | (`MEMORY` 전용) 동시 보유 가능한 최대 세션 수. 상한 도달 시 신규 세션은 fail-closed(생성 거부), 기존 세션은 영향 없음(보안 Advisory 6) |
| `session.cleanup-interval` | `5m` | (`MEMORY` 전용) 만료 세션을 스캔해 제거하는 정리 스케줄 주기(전용 데몬 스레드) |

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
| `rate-limit.max-tracked-keys` | `100000` | 인메모리 rate limiter가 동시에 추적할 최대 키(IP/username) 수. 상한 도달 시 신규 키는 fail-closed(즉시 차단)로 메모리 상한 보장(보안 Advisory 2) |

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

### 3.12 Role 매핑 (`role-mapping`) — 보안 Advisory 7
Keycloak Realm/Client 역할을 Spring `GrantedAuthority`로 매핑하는 방식입니다.

| 키 | 기본값 | 설명 |
|----|--------|------|
| `role-mapping.mode` | `SEPARATE_NAMESPACE` | `REALM_ONLY` / `CLIENT_ONLY` / `SEPARATE_NAMESPACE` / `LEGACY_MERGED` |
| `role-mapping.realm-role-prefix` | `ROLE_REALM_` | `SEPARATE_NAMESPACE`일 때 Realm 역할 접두사 |
| `role-mapping.client-role-prefix` | `ROLE_CLIENT_` | `SEPARATE_NAMESPACE`일 때 Client 역할 접두사. 실제 권한은 `<접두사><정규화된 clientId>_<역할명>` |

`SEPARATE_NAMESPACE`(기본값)에서 `realm-role-prefix`/`client-role-prefix`가 공백이거나 서로 같으면 기동이 실패합니다(Advisory 7 재현 방지 가드). 자세한 마이그레이션은 [4.10](#410-role-매핑-realmclient-역할-네임스페이스-분리)을 참고하세요.

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
      max-sessions: 10000       # memory 전용, 보안 Advisory 6
      cleanup-interval: 5m      # memory 전용, 보안 Advisory 6
```
`memory`는 단일 인스턴스 전제. 다중 인스턴스(HA)는 `redis` 권장. `memory` 저장소는 `max-sessions` 상한과 `cleanup-interval` 만료 정리 스케줄로 무한정 세션 누적(메모리 고갈)을 방지합니다(보안 Advisory 6) — 인터넷에 노출되는 운영 환경에서는 `redis` 전환 + OIDC 로그인 개시 엔드포인트 rate limit을 함께 권장합니다.

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
`Authorization: Basic` 요청은 Keycloak Direct Access Grants로 인증됩니다. **CSRF는 자동 면제되지 않습니다** — Basic 자격증명은 브라우저가 캐시해 cross-origin 폼 제출에도 자동 재전송될 수 있어(CWE-352), 헤더 보유만으로 비-브라우저 요청을 단정할 수 없기 때문입니다. 머신 전용 API는 `csrf.ignore-paths`에 명시적으로 등록하세요.

### 4.5 인가 (Authorization Services)
```yaml
keycloak:
  security:
    authorization:
      enabled: true
```
켜면 모든 요청을 Keycloak Authorization Services로 인가 검증. OIDC/Bearer/Basic 모든 인증 타입 지원(v1.4.0+). 메서드 보안은 `@EnableMethodSecurity`가 기본 활성이라 `@PreAuthorize` 등 사용 가능.

### 4.6 CSRF
기본 활성. 로그아웃·Bearer 토큰 엔드포인트는 자동 면제. **Basic Auth 요청은 더 이상 자동 면제되지 않습니다**(보안 Advisory 3, CWE-352 — Authorization: Basic 헤더 보유를 "비-브라우저 요청" 증거로 사용하지 않음). 면제가 필요한 경로는 `csrf.ignore-paths`에 명시적으로 등록하세요.

### 4.7 MDC 로깅 + PII 마스킹 (v1.6.0/1.7.0)
모든 요청에 `traceId` 등이 MDC로 자동 주입되고 응답 `X-Request-Id`로 회신됩니다. query/userAgent는 **PII 마스킹**(이메일/폰/주민/카드/Bearer)이 기본 적용됩니다. 마스킹 교체/해제는 [5. 확장점](#5-확장점) 참고. 자세한 내용은 [13](13-MDC-로깅-사내표준-위임.md)/[14](14-MDC-로깅-응답메트릭-제외경로.md).

Back-Channel 로그아웃 처리 로그는 `logout_token` 원문을 기록하지 않으며 `sub`/`sid`/`jti` 등 식별자는 모든 로그 레벨에서 마스킹됩니다(보안 Advisory 5). 처리 실패 시 HTTP 응답에도 상세 예외 대신 고정 메시지만 반환되고, 상세는 로그로만 확인할 수 있습니다.

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

### 4.10 Role 매핑 (Realm/Client 역할 네임스페이스 분리)

**보안 Advisory 7(CWE-863) — breaking change.** 과거에는 `realm_access.roles`와 `resource_access.{clientId}.roles`가 모두 동일한 `ROLE_<역할명>`으로 변환되어, 동명의 realm 역할과 client 역할을 구분할 수 없었습니다(realm 역할 보유자가 client 전용 `hasRole(...)` 검사를 의도치 않게 통과할 수 있었음). 기본값이 아래처럼 네임스페이스를 분리하는 `SEPARATE_NAMESPACE`로 바뀌었습니다.

```yaml
# 예: client-id = target-client
# realm_access.roles: ["ADMIN"]                   -> ROLE_REALM_ADMIN
# resource_access.target-client.roles: ["ADMIN"]  -> ROLE_CLIENT_TARGET_CLIENT_ADMIN
```

**마이그레이션 체크리스트:**
1. 코드에서 `hasRole("ADMIN")` / `hasAuthority("ROLE_ADMIN")` 등 역할 문자열을 참조하는 모든 지점을 찾는다(`@PreAuthorize`, `SecurityFilterChain`의 `authorizeHttpRequests`/`authorizeExchange`, `ReactiveAuthorizationManager` 구현 등).
2. 그 역할이 **realm 역할**이면 `ROLE_REALM_ADMIN`으로, **client 역할**이면 `ROLE_CLIENT_<정규화된 CLIENT-ID>_ADMIN`으로 참조를 갱신한다(clientId는 영숫자가 아닌 문자가 `_`로 치환된 뒤 대문자화됨. 예: `target-client` → `TARGET_CLIENT`).
3. 즉시 갱신이 어려우면 과도기적으로 아래처럼 과거 동작을 명시 적용할 수 있습니다(비권장, 마이그레이션 기간 한정 — CWE-863에 다시 노출됨):
   ```yaml
   keycloak:
     security:
       role-mapping:
         mode: LEGACY_MERGED   # realm/client 역할 모두 ROLE_<역할명>으로 병합 (구분 불가)
   ```
4. `mode: SEPARATE_NAMESPACE`(기본값)를 유지하면서 접두사만 바꾸고 싶다면 `role-mapping.realm-role-prefix`/`client-role-prefix`를 설정합니다. 단, 두 값은 공백이거나 서로 같을 수 없습니다(기동 시 검증 실패).
5. 단일 소스만 쓰는 경우 `REALM_ONLY`/`CLIENT_ONLY`로 전환하면 접두사 없이 기존 `ROLE_<역할명>` 형태를 그대로 유지할 수 있습니다(이름 충돌 자체가 없는 경우에만 안전).

자세한 설정 항목은 [3.12](#312-role-매핑-role-mapping--보안-advisory-7) 참고.

---

## 5. 확장점

라이브러리의 모든 빈은 `@ConditionalOnMissingBean`이라 **같은 타입 빈을 등록하면 교체**됩니다.

| 확장 | 방법 |
|------|------|
| 보안 설정 일부만 추가 | 자체 `SecurityFilterChain`에서 `http.with(KeycloakHttpConfigurer.keycloak(), Customizer.withDefaults())` |
| PII 마스킹 교체/해제 | `LoggingValueSanitizer` 빈 등록 (`NoOpLoggingValueSanitizer`로 해제) |
| Rate Limiter 구현 교체 | `RateLimiter` 빈 등록 (예: 분산 Redis 기반) |
| 로깅 컨텍스트 접근자 | `LoggingContextAccessor` 빈 등록 |
| 전체 수동 배선(auto-filter-chain 미사용) | 커스텀 인가 매니저·엔드포인트·로깅 유지가 필요하면 autoconfig 제외 후 컴포넌트 직접 조립 → **[WebFlux 수동 배선 가이드](15-WebFlux-수동배선-가이드.md)** |

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
| **2.0.2** | (버그픽스) `session.store-type: redis` 사용 시 세션의 `SecurityContext` 역직렬화가 실패해 인증 요청이 500이 되던 회귀 수정(mixin 필드 기반 introspection 전환, claims의 `Instant` 복원 누락 수정) | breaking 없음. 세션 직렬화 포맷 변경 없음, 앱 코드 변경 불필요 |
| **2.0.1** ⚠️ | **외부 보안 검토 4건 대응** — OIDC Access Token subject를 ID Token subject와 직접 비교(High #1), WebFlux CSRF 안전 메서드 예외 누락 수정(Medium #3), 브라우저 Front-Channel `/logout` CSRF 우회 차단(Medium #4), Bearer prefix 검증·검증 순서 정렬·로그 정리·subject 마스킹(Low #1~#4) | **Breaking 1건** — 아래 [마이그레이션](#마이그레이션-201--외부-보안-검토-4건-breaking) |
| **2.0.0** ⚠️ | **보안 강화 8건** — OIDC ID/Access Token 결합 검증(Advisory 1), 로그인 세션 고정 방지(Advisory 2), Rate Limit IP 판정 일원화(Advisory 2), Basic Auth CSRF 전면 면제 제거(Advisory 3), 백채널 로그아웃 로그 마스킹(Advisory 5), 인메모리 세션 저장소 용량 상한(Advisory 6), Realm/Client Role 네임스페이스 분리(Advisory 7), WebFlux 백채널 decoder 검증 강화(Advisory 8) | **Breaking 3건** — 아래 [마이그레이션](#마이그레이션-200--보안-강화-8건-breaking) |
| **1.10.2** | (버그픽스 #54) webflux 토큰 무효화(백채널 로그아웃 등) 후 보호 경로 접근 시 refresh 재발급 실패가 500 나던 문제 → 미인증 처리로 EntryPoint(로그인 리다이렉트/401) 경유 | breaking 없음 |
| **1.10.1** | (버그픽스 #52) webflux/servlet AJAX 판정 통일 — 브라우저 `Accept: */*`를 JSON으로 오판하던 문제 수정(`ajax-returns-json=true` 시 브라우저 리다이렉트 정상화) | breaking 없음 |
| **1.10.0** ⚠️ | **보안 강화** (보안검토 13건) — reactive 백채널 JWKS 서명+aud 검증, 쿠키 secure 기본 true, XFF 신뢰 프록시, servlet SameSite/토큰 no-store, PII 마스킹 확장(JWT/OAuth2), 인가 캐시·require-user-info 토글, Redis JSON 직렬화 | **Breaking 3건** — 아래 [마이그레이션](#마이그레이션-v190--v1100-breaking) |
| **1.9.0** | OIDC authorize 파라미터(`acr_values`/`max_age`/`prompt`) 커스터마이즈 — LoA step-up·재인증 | 미설정 시 무동작(회귀 0). 경로별 step-up은 resolver 빈 재정의([4.9](#49-재인증--step-up-acr_values--max_age--prompt-v190)) |
| **1.8.0** | **Reactive(WebFlux) 스택 추가** — servlet과 기능 동등 (OIDC 로그인·세션·인가·Bearer·Basic·RateLimit·CSRF·로그아웃·MDC 로깅) | `keycloak-spring-security-webflux-starter` 신규. servlet 사용자는 영향 없음 |
| **1.7.0** | 응답 메트릭(status/durationMs, 기본 off) + exclude-patterns(/actuator) | — |
| **1.6.0** | MDC PII 마스킹 **기본 on** + userAgent/query 정제 + X-Request-Id 회신 | 로그 PII가 마스킹됨. 해제는 `NoOpLoggingValueSanitizer` |
| **1.5.0** | SecurityFilterChain Fail-Open 수정 (Bean 이름 조건 + securityMatcher) | actuator 등 자체 체인 쓰던 앱은 Keycloak 체인이 함께 켜짐 → `matcher.exclude` 또는 `auto-filter-chain: false` |
| **1.4.x** | Bearer/Basic 인가 지원, stateless 세션 분리 | — |

상세: `docs/12`, `docs/13`, `docs/14`

### 마이그레이션 (2.0.1 — 외부 보안 검토 4건, breaking)
외부 보안 검토(High #1/Medium #3/Medium #4/Low #1~#4) 반영으로 **API 변경 1건**이 있습니다. 나머지는 회귀 없는 보안 강화입니다.

| # | 변경 | 영향 | 해제/대응 |
|---|------|------|-----------|
| 1 | Servlet OIDC 인증용 `JwtDecoder` 빈의 `@ConditionalOnMissingBean` 조건이 타입(`JwtDecoder.class`) 기반에서 빈 이름(`keycloakOidcJwtDecoder`) 기반으로 변경(webflux `keycloakOidcReactiveJwtDecoder`와 동일 패턴 정렬) | 이 decoder를 커스텀 빈으로 재정의(override)하던 코드가 빈 이름 불일치로 더 이상 대체되지 않음(라이브러리 기본 decoder와 사용자 decoder가 동시에 등록되어 `NoUniqueBeanDefinitionException`으로 기동 실패 가능) | 재정의 빈 이름을 `keycloakOidcJwtDecoder`로 맞출 것. 별도 resource-server용 JWT decoder가 필요하면 다른 이름을 쓰고 소비 지점에서 `@Qualifier`로 명시 구분 |

**주의 (breaking은 아니지만 확인 필요) — Opaque Access Token + `require-user-info`**: 이번 버전은 Access Token이 구조적으로 JWT인 경우에 한해 `sub`를 ID Token과 직접 비교합니다(외부 검토 High #1). **Opaque(불투명) Access Token은 로컬에서 `sub`를 파싱할 수 없어 이 직접 비교의 보호를 받지 못하며**, 여전히 UserInfo 엔드포인트 조회 성공 시의 `sub` 일치 검증에만 의존합니다. Opaque Access Token을 발급하는 Keycloak 클라이언트를 쓴다면 다음을 반드시 켜세요.
```yaml
keycloak:
  security:
    authentication:
      require-user-info: true   # UserInfo 조회 실패를 인증 실패로 승격(기본 false)
```
`require-user-info=false`(기본값)이면서 Opaque Access Token을 쓰는 환경은, UserInfo 조회가 실패(장애·타임아웃)했을 때 서로 다른 사용자의 Access Token과 ID Token이 조합되어도 인증이 성립할 수 있는 잔여 위험이 남습니다.

그 외(회귀 없음): WebFlux CSRF 매처 안전 메서드(GET/HEAD/OPTIONS/TRACE) 예외 처리 정상화(Medium #3, 과거 CSRF 활성화 시 안전 메서드까지 403이 나던 문제 수정이라 오히려 허용 범위가 넓어짐), 브라우저 Front-Channel `/logout` CSRF 보호 강화(Medium #4 — Bearer 활성 시에만 `/logout`이 CSRF 면제되던 것을 제거, 정상적인 CSRF 토큰을 포함한 로그아웃 요청은 영향 없음), Bearer prefix 기동 시 검증(Low #1, 공백/`"/"` prefix를 쓰던 비정상 설정만 영향), webflux 토큰 결합 검증 순서 정렬·로그 정리·예외 메시지 마스킹(Low #2~#4).

### 마이그레이션 (2.0.0 — 보안 강화 8건, breaking)
보안 검토(Advisory 1/2/3/5/6/7/8) 반영으로 **기본 동작 2가지가 변경**되고, **수동 배선(auto-filter-chain 미사용) 사용자에 한해** API 변경이 하나 있습니다.

| # | 변경 | 영향 | 해제/대응 |
|---|------|------|-----------|
| 1 | Basic Auth `Authorization: Basic` 헤더 보유만으로 CSRF가 자동 면제되던 로직 제거 (Advisory 3, CWE-352) | `basic-auth.enabled=true` 상태에서 CSRF 면제에 의존하던 상태 변경 요청(POST/PUT/PATCH/DELETE)이 `403` | 해당 경로를 `keycloak.security.csrf.ignore-paths`에 명시 등록. 자세히는 [4.6](#46-csrf) |
| 2 | Realm/Client Role 매핑 기본값이 `SEPARATE_NAMESPACE`로 변경 (Advisory 7, CWE-863) | `hasRole(...)`/`hasAuthority(...)`로 realm/client 역할을 구분 없이 검사하던 코드가 전부 거부됨(권한 문자열이 `ROLE_REALM_*`/`ROLE_CLIENT_<CLIENT>_*`로 분리) | 참조 갱신, 또는 과도기적으로 `keycloak.security.role-mapping.mode=LEGACY_MERGED`(비권장). 자세히는 [4.10](#410-role-매핑-realmclient-역할-네임스페이스-분리) |
| 3 (수동 배선만 해당) | `KeycloakAuthenticationProvider`(servlet)/`KeycloakReactiveAuthenticationManager`(webflux) 생성자에 `JwtDecoder`/`ReactiveJwtDecoder` 파라미터 추가, reactive `createAuthenticatedToken` 반환 타입이 `Authentication`→`Mono<Authentication>`으로 변경 (Advisory 1) | `auto-filter-chain: false`로 컴포넌트를 직접 조립하던 코드가 컴파일 실패 | JwtDecoder 빈을 직접 구성해 생성자에 전달 → [WebFlux 수동 배선 가이드](15-WebFlux-수동배선-가이드.md) §2 예시 갱신본 참고. **Starter 자동 구성만 쓰는 경우 영향 없음** |

그 외(회귀 없음, 기본값 변경 없이 강화됨): 로그인 세션 고정 방지(Advisory 2), Rate Limit IP 판정 `ClientIpResolver` 일원화 + `max-tracked-keys` 상한(Advisory 2), 백채널 로그아웃 로그 마스킹(Advisory 5), 인메모리 세션 저장소 `max-sessions`/`cleanup-interval` 상한(Advisory 6, 기본값 자체가 새로 생겼으나 충분히 크게 잡혀 있어 일반적인 트래픽에서는 영향 없음), WebFlux 백채널 decoder aud/iat/exp 검증 강화(Advisory 8).

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
| 쿠키 설정 후 응답 500 (`No enum constant ...SameSite.lax`) | `cookie.same-site` 값을 대문자로 — `Lax`/`Strict`/`None` |
| 인증은 성공하는데 역할 기반 인가가 전부 거부 | 권한이 **UserInfo**에서 추출됨 — Keycloak 역할(`realm_access`/`resource_access`)은 access token에만 있을 수 있음. role 매퍼 "Add to userinfo" 활성화 또는 access token 직접 파싱 → [수동 배선 가이드 함정 2](15-WebFlux-수동배선-가이드.md) |
| (수동 배선) 로그인 성공 후 `AuthorizedClient를 찾을 수 없음` | `AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository` 빈 등록 → [수동 배선 가이드 함정 4](15-WebFlux-수동배선-가이드.md) |
| 업그레이드 후 `hasRole(...)`/`hasAuthority(...)` 인가가 갑자기 전부 거부 | Role 매핑 기본값이 `SEPARATE_NAMESPACE`로 변경(Advisory 7) — 권한이 `ROLE_REALM_*`/`ROLE_CLIENT_<CLIENT>_*`로 분리됨 → [4.10 마이그레이션](#410-role-매핑-realmclient-역할-네임스페이스-분리) |
| (수동 배선) `new KeycloakReactiveAuthenticationManager(client, clientId)` 컴파일 에러 | 생성자에 `ReactiveJwtDecoder` 파라미터 추가(Advisory 1) → [수동 배선 가이드 §2](15-WebFlux-수동배선-가이드.md) |

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
