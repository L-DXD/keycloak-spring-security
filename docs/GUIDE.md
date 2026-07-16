# keycloak-spring-security User Guide

**English** | [한국어](GUIDE.ko.md)

A library that integrates Keycloak with Spring Security. With a single dependency and minimal configuration, OIDC login, session, logout, and authorization are auto-configured.

- **Support**: JDK 17+, Spring Boot 3.5.x, Spring Security 6.5.x
- **Current version**: `2.0.2`
- **Stacks**: Servlet (Spring MVC) / **Reactive (WebFlux) — feature-equivalent to servlet since v1.8.0** ([8. Reactive](#8-reactivewebflux))
- This document is the **user guide for adopting developers**. For architecture/contribution rules, see the [README](../README.md).

---

## Table of Contents
1. [Quick Start](#1-quick-start)
2. [How It Works](#2-how-it-works)
3. [Configuration Reference](#3-configuration-reference)
4. [Feature Guide](#4-feature-guide)
5. [Extension Points](#5-extension-points)
6. [Version Notes / Migration](#6-version-notes--migration)
7. [Troubleshooting](#7-troubleshooting)
8. [Reactive (WebFlux)](#8-reactivewebflux)

---

## 1. Quick Start

### 1.1 Dependency

```gradle
// Servlet (Spring MVC)
implementation("io.github.l-dxd:keycloak-spring-security-web-starter:2.0.2")

// or Reactive (WebFlux)
implementation("io.github.l-dxd:keycloak-spring-security-webflux-starter:2.0.2")
```
> Add only if you use Redis sessions:
> ```gradle
> implementation("org.springframework.boot:spring-boot-starter-data-redis")
> implementation("org.springframework.session:spring-session-data-redis")
> ```

### 1.2 Required Configuration

Keycloak connection info and OIDC client registration are **required**.

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

### 1.3 Done

If you start the application without a separate `SecurityConfig`, a default `SecurityFilterChain` is auto-registered.
- All requests require authentication (except `permit-all-paths`)
- When unauthenticated, redirect to Keycloak login (OIDC Authorization Code)
- On successful login, a session is created and subsequent authentication is cookie-based

```yaml
keycloak:
  security:
    authentication:
      permit-all-paths:
        - /public/**
        - /health
```

---

## 2. How It Works

### Authentication Model
The default is **OIDC Authorization Code + server session (cookie)**. On every request, `KeycloakAuthenticationFilter` checks the session's authentication. Additionally, depending on options, **Bearer Token** (API) and **Basic Auth** (machine clients) are supported in parallel.

### Filter Chain (summary)
```
MdcRequestFilter (traceId 등 MDC)
  → RateLimitFilter (옵션)
  → BasicAuthenticationFilter (옵션)
  → KeycloakAuthenticationFilter (세션 인증)
  → MdcAuthenticationFilter (userId 등 MDC)
  → AuthorizationFilter (인가)
```

### SecurityFilterChain Coexistence (v1.5.0+)
The library chain is registered with `securityMatcher` (default `/**`) + `@Order(LOWEST_PRECEDENCE)`, so it **coexists even when the user adds their own `SecurityFilterChain` (e.g. dedicated to `/actuator`)**. (See [4.8](#48-securityfilterchain-coexistence))

---

## 3. Configuration Reference

All settings live under the `keycloak.security.*` namespace.

### 3.1 Authentication (`authentication`)
| Key | Default | Description |
|----|--------|------|
| `authentication.permit-all-paths` | `[]` | Paths allowed without authentication (Ant) |
| `authentication.default-success-url` | `/` | Redirect after successful login |
| `authentication.login-paths` | `[/api/keycloak/login]` | Paths classified as body-based login |
| `authentication.authorization-request.acr-values` | (none) | `acr_values` for the OIDC authorize request (LoA step-up). e.g. `loa2` |
| `authentication.authorization-request.max-age` | (none) | `max_age` (seconds). Re-authenticate when this much time has passed since the last authentication. e.g. `1800` |
| `authentication.authorization-request.prompt` | (none) | `prompt`. `login` (forced re-authentication) / `consent` / `none` / `select_account` |
| `authentication.issuer-uri` | (none) | Explicitly sets the issuer (`iss`) used for OIDC ID/Access Token signature validation. If unset, resolved in the order of the standard Spring Boot `spring.security.oauth2.resourceserver.jwt.issuer-uri` / `...client.provider.keycloak.issuer-uri` → derivation from `base-url` (Security Advisory 1) |

### 3.2 Authorization (`authorization`)
| Key | Default | Description |
|----|--------|------|
| `authorization.enabled` | `false` | Validate authorization for all requests via Keycloak Authorization Services |

### 3.3 Session (`session`)
| Key | Default | Description |
|----|--------|------|
| `session.store-type` | `MEMORY` | `MEMORY` or `REDIS` |
| `session.timeout` | `30m` | Session expiration time |
| `session.max-sessions` | `10000` | (`MEMORY` only) Maximum number of sessions held concurrently. When the cap is reached, new sessions fail closed (creation refused); existing sessions are unaffected (Security Advisory 6) |
| `session.cleanup-interval` | `5m` | (`MEMORY` only) Interval of the cleanup schedule that scans and removes expired sessions (dedicated daemon thread) |

### 3.4 Cookie (`cookie`)
| Key | Default | Description |
|----|--------|------|
| `cookie.http-only` | `true` | |
| `cookie.secure` | `true` | (default true since v1.10.0) In HTTP development environments, disable with `false` |
| `cookie.domain` | (none) | |
| `cookie.path` | `/` | |
| `cookie.same-site` | (none) | `Lax`/`Strict`/`None` |

### 3.5 Error Handling (`error`)
| Key | Default | Description |
|----|--------|------|
| `error.redirect-enabled` | `false` | Use a redirect on authentication failure |
| `error.ajax-returns-json` | `false` | AJAX requests get a JSON response |
| `error.authentication-failed-redirect-url` | `/login` | |
| `error.session-expired-redirect-url` | (follows the auth-failure URL) | |
| `error.access-denied-redirect-url` | `/error/403` | |

### 3.6 Basic Auth (`basic-auth`)
| Key | Default | Description |
|----|--------|------|
| `basic-auth.enabled` | `false` | Basic authentication based on Direct Access Grants |

### 3.7 Bearer Token (`bearer-token`)
| Key | Default | Description |
|----|--------|------|
| `bearer-token.enabled` | `false` | Resource Server (Introspect) + token issuance API |
| `bearer-token.token-endpoint.prefix` | `/auth` | Token issuance endpoint prefix (`/auth/token`, etc.) |

### 3.8 CSRF (`csrf`)
| Key | Default | Description |
|----|--------|------|
| `csrf.enabled` | `true` | |
| `csrf.ignore-paths` | `[]` | Additional exempt paths |

### 3.9 Rate Limiting (`rate-limit`)
| Key | Default | Description |
|----|--------|------|
| `rate-limit.enabled` | `false` | |
| `rate-limit.max-requests` | `5` | Maximum requests within the window |
| `rate-limit.window-seconds` | `60` | Window (seconds) |
| `rate-limit.block-duration-seconds` | `300` | Block duration (seconds) |
| `rate-limit.key-strategy` | `IP_AND_USERNAME` | `IP`/`USERNAME`/`IP_AND_USERNAME` |
| `rate-limit.include-basic-auth` | `true` | Also apply to Basic Auth |
| `rate-limit.max-tracked-keys` | `100000` | Maximum number of keys (IP/username) the in-memory rate limiter tracks concurrently. When the cap is reached, new keys fail closed (blocked immediately), guaranteeing a memory bound (Security Advisory 2) |

### 3.10 Logging/MDC (`logging`) — v1.6.0/1.7.0
| Key | Default | Description |
|----|--------|------|
| `logging.include-trace-id` | `true` | traceId MDC |
| `logging.include-http-method` | `true` | |
| `logging.include-request-uri` | `true` | |
| `logging.include-query-string` | `false` | Query string (decoding + length limit + masking) |
| `logging.include-client-ip` | `true` | |
| `logging.include-user-agent` | `true` | userAgent (masking + 256) |
| `logging.include-user-id` / `-username` / `-session-id` | `true` | User info after authentication |
| `logging.max-query-length` | `512` | |
| `logging.max-user-agent-length` | `256` | |
| `logging.return-trace-id-header` | `true` | Return `X-Request-Id` in the response |
| `logging.include-response-metrics` | `false` | status/durationMs + termination log |
| `logging.exclude-patterns` | `[/actuator/**]` | Paths excluded from the MDC filter |

### 3.11 SecurityFilterChain (`matcher`, `auto-filter-chain`) — v1.5.0
| Key | Default | Description |
|----|--------|------|
| `auto-filter-chain` | `true` | Auto-register the Keycloak default chain (false = configure manually) |
| `matcher.include` | `[/**]` | Paths handled by the Keycloak chain |
| `matcher.exclude` | `[]` | Excluded paths (handled by another chain) |

### 3.12 Role Mapping (`role-mapping`) — Security Advisory 7
How Keycloak Realm/Client roles are mapped to Spring `GrantedAuthority`.

| Key | Default | Description |
|----|--------|------|
| `role-mapping.mode` | `SEPARATE_NAMESPACE` | `REALM_ONLY` / `CLIENT_ONLY` / `SEPARATE_NAMESPACE` / `LEGACY_MERGED` |
| `role-mapping.realm-role-prefix` | `ROLE_REALM_` | Realm role prefix when `SEPARATE_NAMESPACE` |
| `role-mapping.client-role-prefix` | `ROLE_CLIENT_` | Client role prefix when `SEPARATE_NAMESPACE`. The actual authority is `<prefix><normalized clientId>_<role name>` |

When `SEPARATE_NAMESPACE` (default), startup fails if `realm-role-prefix`/`client-role-prefix` are blank or equal to each other (guard preventing reproduction of Advisory 7). For detailed migration, see [4.10](#410-role-mapping-realmclient-role-namespace-separation).

---

## 4. Feature Guide

### 4.1 OIDC Login (default)
Works with configuration alone. Unauthenticated requests are redirected to Keycloak, and a session cookie is issued after login. Logout is automatic via `POST /logout` (Front-Channel) + Back-Channel (`/logout/connect/back-channel/keycloak`).

### 4.2 Session Store (Memory / Redis)
```yaml
keycloak:
  security:
    session:
      store-type: redis      # 기본 memory. redis 시 위 의존성 추가 필요
      timeout: 30m
      max-sessions: 10000       # memory 전용, 보안 Advisory 6
      cleanup-interval: 5m      # memory 전용, 보안 Advisory 6
```
`memory` assumes a single instance. For multiple instances (HA), `redis` is recommended. The `memory` store prevents unbounded session accumulation (memory exhaustion) via the `max-sessions` cap and the `cleanup-interval` expiration-cleanup schedule (Security Advisory 6) — in production environments exposed to the internet, switching to `redis` plus rate limiting the OIDC login-initiation endpoint is recommended together.

### 4.3 Bearer Token (API)
```yaml
keycloak:
  security:
    bearer-token:
      enabled: true
      token-endpoint:
        prefix: /auth
```
- Online validation based on Introspect (RFC 7662)
- Token issuance/refresh/logout: `POST {prefix}/token`, `/refresh`, `/logout` (unauthenticated allowed)

### 4.4 Basic Auth (machine clients)
```yaml
keycloak:
  security:
    basic-auth:
      enabled: true
```
`Authorization: Basic` requests are authenticated via Keycloak Direct Access Grants. **CSRF is not automatically exempted** — Basic credentials can be cached by the browser and automatically re-sent even on cross-origin form submissions (CWE-352), so possessing the header alone cannot be taken as proof of a non-browser request. Register machine-only APIs explicitly under `csrf.ignore-paths`.

### 4.5 Authorization (Authorization Services)
```yaml
keycloak:
  security:
    authorization:
      enabled: true
```
When enabled, all requests are authorized via Keycloak Authorization Services. All authentication types — OIDC/Bearer/Basic — are supported (v1.4.0+). Method security is enabled by default via `@EnableMethodSecurity`, so `@PreAuthorize` and the like can be used.

### 4.6 CSRF
Enabled by default. Logout and Bearer token endpoints are automatically exempted. **Basic Auth requests are no longer automatically exempted** (Security Advisory 3, CWE-352 — possession of the `Authorization: Basic` header is not used as evidence of a "non-browser request"). Register paths that need exemption explicitly under `csrf.ignore-paths`.

### 4.7 MDC Logging + PII Masking (v1.6.0/1.7.0)
On every request, `traceId` and the like are automatically injected into the MDC and returned in the response `X-Request-Id`. **PII masking** (email/phone/national ID/card/Bearer) is applied by default to query/userAgent. To replace or disable masking, see [5. Extension Points](#5-extension-points). For details, see [13](13-MDC-로깅-사내표준-위임.md)/[14](14-MDC-로깅-응답메트릭-제외경로.md).

Back-Channel logout processing logs do not record the raw `logout_token`, and identifiers such as `sub`/`sid`/`jti` are masked at all log levels (Security Advisory 5). On processing failure, the HTTP response returns only a fixed message instead of a detailed exception, and the details are available only through the logs.

### 4.8 SecurityFilterChain Coexistence
Even if you add a separate chain for `/actuator` and so on, the Keycloak chain runs alongside it. To split paths:
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
To turn off the Keycloak default chain and configure it yourself, use `auto-filter-chain: false`. For details, see [12](12-SecurityFilterChain-FailOpen-수정.md).

### 4.9 Re-authentication / Step-up (acr_values · max_age · prompt) (v1.9.0+)
To use Keycloak LoA step-up / re-authentication, you must carry `acr_values`/`max_age`/`prompt` in the OIDC authorize request. Since the library wires a resolver into `oauth2Login`, you can inject them in **two ways**.

**(1) Global — properties (applied identically to all logins)**
```yaml
keycloak:
  security:
    authentication:
      authorization-request:
        max-age: 1800       # 마지막 인증 후 30분 경과 시 재인증
        # acr-values: loa2  # LoA step-up
        # prompt: login     # 강제 재인증
```

**(2) Per-path Step-up — custom resolver bean (strong authentication on specific paths only)**
Registering an `OAuth2AuthorizationRequestResolver` (servlet) / `ServerOAuth2AuthorizationRequestResolver` (reactive) bean replaces the library's default bean (`@ConditionalOnMissingBean`). Determine `acr_values` dynamically based on the request path:
```java
@Bean
OAuth2AuthorizationRequestResolver authorizationRequestResolver(ClientRegistrationRepository repo) {
    var resolver = new DefaultOAuth2AuthorizationRequestResolver(repo, "/oauth2/authorization"); // baseUri 유지
    resolver.setAuthorizationRequestCustomizer(builder ->
        builder.additionalParameters(p -> p.put("acr_values", "loa2")));  // 조건 분기 가능
    return resolver;
}
```
> Note: When registering a custom bean, you must keep the baseUri as `/oauth2/authorization` so the login entry path does not break.
> Note: If you use `prompt=none` together with `max_age` and re-authentication is required, Keycloak returns a `login_required` error (expected behavior).

### 4.10 Role Mapping (Realm/Client Role Namespace Separation)

**Security Advisory 7 (CWE-863) — breaking change.** In the past, both `realm_access.roles` and `resource_access.{clientId}.roles` were converted to the same `ROLE_<role name>`, so realm roles and client roles with the same name could not be distinguished (a realm-role holder could unintentionally pass a client-only `hasRole(...)` check). The default has changed to `SEPARATE_NAMESPACE`, which separates namespaces as shown below.

```yaml
# 예: client-id = target-client
# realm_access.roles: ["ADMIN"]                   -> ROLE_REALM_ADMIN
# resource_access.target-client.roles: ["ADMIN"]  -> ROLE_CLIENT_TARGET_CLIENT_ADMIN
```

**Migration checklist:**
1. Find every point in the code that references role strings, such as `hasRole("ADMIN")` / `hasAuthority("ROLE_ADMIN")` (`@PreAuthorize`, `authorizeHttpRequests`/`authorizeExchange` in `SecurityFilterChain`, `ReactiveAuthorizationManager` implementations, etc.).
2. If that role is a **realm role**, update the reference to `ROLE_REALM_ADMIN`; if it is a **client role**, update it to `ROLE_CLIENT_<normalized CLIENT-ID>_ADMIN` (in clientId, non-alphanumeric characters are replaced with `_` and then uppercased. e.g. `target-client` → `TARGET_CLIENT`).
3. If immediate update is difficult, you can explicitly apply the old behavior as a transitional measure as shown below (not recommended, limited to the migration period — exposed again to CWE-863):
   ```yaml
   keycloak:
     security:
       role-mapping:
         mode: LEGACY_MERGED   # realm/client 역할 모두 ROLE_<역할명>으로 병합 (구분 불가)
   ```
4. If you want to keep `mode: SEPARATE_NAMESPACE` (default) but change only the prefixes, set `role-mapping.realm-role-prefix`/`client-role-prefix`. Note that the two values cannot be blank or equal to each other (validation fails at startup).
5. If you use only a single source, switching to `REALM_ONLY`/`CLIENT_ONLY` lets you keep the existing `ROLE_<role name>` form without a prefix (safe only when there is no name collision to begin with).

For detailed configuration items, see [3.12](#312-role-mapping-role-mapping--security-advisory-7).

---

## 5. Extension Points

Every bean in the library is `@ConditionalOnMissingBean`, so **registering a bean of the same type replaces it**.

| Extension | How |
|------|------|
| Add only part of the security configuration | In your own `SecurityFilterChain`, use `http.with(KeycloakHttpConfigurer.keycloak(), Customizer.withDefaults())` |
| Replace/disable PII masking | Register a `LoggingValueSanitizer` bean (disable with `NoOpLoggingValueSanitizer`) |
| Replace the Rate Limiter implementation | Register a `RateLimiter` bean (e.g. distributed Redis-based) |
| Logging context accessor | Register a `LoggingContextAccessor` bean |
| Full manual wiring (not using auto-filter-chain) | If you need to keep a custom authorization manager, endpoints, or logging, exclude the autoconfig and assemble the components yourself → **[WebFlux Manual Wiring Guide](15-WebFlux-수동배선-가이드.md)** |

```java
// 예: PII 마스킹 끄기
@Bean
LoggingValueSanitizer loggingValueSanitizer() {
    return new NoOpLoggingValueSanitizer();
}
```

---

## 6. Version Notes / Migration

| Version | Change | Notes |
|------|------|------|
| **2.0.2** | (bugfix) Fixed a regression where, when using `session.store-type: redis`, deserialization of the session's `SecurityContext` failed and authenticated requests returned 500 (switched to mixin field-based introspection, fixed the missing `Instant` restoration in claims) | No breaking changes. No change to the session serialization format; no application code changes needed |
| **2.0.1** (caution) | **Response to 4 external security review items** — directly compare the OIDC Access Token subject with the ID Token subject (High #1), fix the missing WebFlux CSRF safe-method exception (Medium #3), block browser Front-Channel `/logout` CSRF bypass (Medium #4), Bearer prefix validation, aligned validation order, log cleanup, subject masking (Low #1–#4) | **1 breaking change** — see [Migration](#migration-201--external-security-review-4-items-breaking) below |
| **2.0.0** (caution) | **8 security hardening items** — OIDC ID/Access Token combined validation (Advisory 1), login session fixation prevention (Advisory 2), unified Rate Limit IP determination (Advisory 2), removal of blanket Basic Auth CSRF exemption (Advisory 3), back-channel logout log masking (Advisory 5), in-memory session store capacity cap (Advisory 6), Realm/Client Role namespace separation (Advisory 7), stronger WebFlux back-channel decoder validation (Advisory 8) | **3 breaking changes** — see [Migration](#migration-200--security-hardening-8-items-breaking) below |
| **1.10.2** | (bugfix #54) Fixed an issue where, after webflux token invalidation (back-channel logout, etc.), refresh re-issuance failure on accessing a protected path returned 500 → now treated as unauthenticated, routed through the EntryPoint (login redirect/401) | No breaking changes |
| **1.10.1** | (bugfix #52) Unified AJAX determination across webflux/servlet — fixed an issue where the browser `Accept: */*` was misjudged as JSON (normalizes browser redirect when `ajax-returns-json=true`) | No breaking changes |
| **1.10.0** (caution) | **Security hardening** (13 security review items) — reactive back-channel JWKS signature + aud validation, cookie secure default true, XFF trusted proxy, servlet SameSite / token no-store, extended PII masking (JWT/OAuth2), authorization cache and require-user-info toggles, Redis JSON serialization | **3 breaking changes** — see [Migration](#migration-v190--v1100-breaking) below |
| **1.9.0** | Customize OIDC authorize parameters (`acr_values`/`max_age`/`prompt`) — LoA step-up / re-authentication | No-op when unset (zero regression). Per-path step-up via resolver bean override ([4.9](#49-re-authentication--step-up-acr_values--max_age--prompt-v190)) |
| **1.8.0** | **Added the Reactive (WebFlux) stack** — feature-equivalent to servlet (OIDC login, session, authorization, Bearer, Basic, RateLimit, CSRF, logout, MDC logging) | New `keycloak-spring-security-webflux-starter`. No impact on servlet users |
| **1.7.0** | Response metrics (status/durationMs, off by default) + exclude-patterns (/actuator) | — |
| **1.6.0** | MDC PII masking **on by default** + userAgent/query sanitization + X-Request-Id return | Log PII is masked. Disable with `NoOpLoggingValueSanitizer` |
| **1.5.0** | SecurityFilterChain Fail-Open fix (bean-name condition + securityMatcher) | Apps that used their own chain (e.g. actuator) will have the Keycloak chain turned on alongside → `matcher.exclude` or `auto-filter-chain: false` |
| **1.4.x** | Bearer/Basic authorization support, stateless session separation | — |

Details: `docs/12`, `docs/13`, `docs/14`

### Migration (2.0.1 — External Security Review, 4 items, breaking)
Reflecting the external security review (High #1 / Medium #3 / Medium #4 / Low #1–#4), there is **1 API change**. The rest are regression-free security hardening.

| # | Change | Impact | Disable/Response |
|---|------|------|-----------|
| 1 | The `@ConditionalOnMissingBean` condition of the `JwtDecoder` bean for Servlet OIDC authentication changed from type-based (`JwtDecoder.class`) to bean-name-based (`keycloakOidcJwtDecoder`) (aligned with the same pattern as the webflux `keycloakOidcReactiveJwtDecoder`) | Code that overrode this decoder with a custom bean is no longer replaced due to the bean-name mismatch (the library's default decoder and the user's decoder are registered together, potentially failing startup with `NoUniqueBeanDefinitionException`) | Match the override bean name to `keycloakOidcJwtDecoder`. If you need a separate resource-server JWT decoder, use a different name and disambiguate explicitly with `@Qualifier` at the consumption point |

**Note (not breaking, but needs checking) — Opaque Access Token + `require-user-info`**: This version compares `sub` directly with the ID Token only when the Access Token is structurally a JWT (external review High #1). **Opaque Access Tokens cannot be parsed locally for `sub`, so they do not receive the protection of this direct comparison** and still rely only on the `sub` match validation upon a successful UserInfo endpoint lookup. If you use a Keycloak client that issues Opaque Access Tokens, you must enable the following.
```yaml
keycloak:
  security:
    authentication:
      require-user-info: true   # UserInfo 조회 실패를 인증 실패로 승격(기본 false)
```
An environment with `require-user-info=false` (default) that uses Opaque Access Tokens retains a residual risk: when the UserInfo lookup fails (failure/timeout), authentication may succeed even if an Access Token and ID Token from different users are combined.

Others (no regression): normalized WebFlux CSRF matcher safe-method (GET/HEAD/OPTIONS/TRACE) exception handling (Medium #3 — a fix for an issue where even safe methods returned 403 when CSRF was enabled, so the allowed range actually widened), stronger browser Front-Channel `/logout` CSRF protection (Medium #4 — removed the case where `/logout` was CSRF-exempt only when Bearer was enabled; logout requests that include a valid CSRF token are unaffected), Bearer prefix validation at startup (Low #1, affecting only abnormal configurations that used a blank/`"/"` prefix), aligned webflux token-combination validation order, log cleanup, and exception-message masking (Low #2–#4).

### Migration (2.0.0 — Security Hardening, 8 items, breaking)
Reflecting the security review (Advisory 1/2/3/5/6/7/8), **two default behaviors change**, and there is one API change **only for manual-wiring users (not using auto-filter-chain)**.

| # | Change | Impact | Disable/Response |
|---|------|------|-----------|
| 1 | Removed the logic that automatically exempted CSRF merely because the `Authorization: Basic` header was present in Basic Auth (Advisory 3, CWE-352) | With `basic-auth.enabled=true`, state-changing requests (POST/PUT/PATCH/DELETE) that relied on the CSRF exemption now return `403` | Register those paths explicitly under `keycloak.security.csrf.ignore-paths`. For details, see [4.6](#46-csrf) |
| 2 | The Realm/Client Role mapping default changed to `SEPARATE_NAMESPACE` (Advisory 7, CWE-863) | Code that checked realm/client roles without distinction via `hasRole(...)`/`hasAuthority(...)` is all rejected (authority strings are split into `ROLE_REALM_*`/`ROLE_CLIENT_<CLIENT>_*`) | Update references, or transitionally use `keycloak.security.role-mapping.mode=LEGACY_MERGED` (not recommended). For details, see [4.10](#410-role-mapping-realmclient-role-namespace-separation) |
| 3 (manual wiring only) | Added `JwtDecoder`/`ReactiveJwtDecoder` parameters to the `KeycloakAuthenticationProvider` (servlet) / `KeycloakReactiveAuthenticationManager` (webflux) constructor, and changed the reactive `createAuthenticatedToken` return type from `Authentication` → `Mono<Authentication>` (Advisory 1) | Code that assembled components directly with `auto-filter-chain: false` fails to compile | Configure the JwtDecoder bean yourself and pass it to the constructor → see the updated §2 example in the [WebFlux Manual Wiring Guide](15-WebFlux-수동배선-가이드.md). **No impact if you use only the Starter auto-configuration** |

Others (no regression, hardened without default changes): login session fixation prevention (Advisory 2), unified Rate Limit IP determination via `ClientIpResolver` + `max-tracked-keys` cap (Advisory 2), back-channel logout log masking (Advisory 5), in-memory session store `max-sessions`/`cleanup-interval` caps (Advisory 6 — the defaults themselves are newly introduced but set large enough to have no impact under typical traffic), stronger WebFlux back-channel decoder aud/iat/exp validation (Advisory 8).

### Migration (v1.9.0 → v1.10.0) (breaking)
Security hardening changes **three default behaviors**. Existing deployments should check the following when upgrading.

| # | Change | Impact | Disable/Response |
|---|------|------|-----------|
| 1 | `cookie.secure` default `false`→`true` | In HTTP (non-TLS) environments, token cookies are not set in the browser | Local/HTTP dev environments: `keycloak.security.cookie.secure=false` |
| 2 | Changed `X-Forwarded-For` trust — `trusted-proxy-count` default `0` (= use `remoteAddr`, ignore XFF) | In environments that logged/rate-limited client IP via XFF, the IP changes to the proxy IP | With N proxies: `keycloak.security.trusted-proxy-count=N` / force old behavior: `=-1` (not recommended) |
| 3 | `/logout` CSRF exemption only when `bearer-token.enabled=true` | If you use cookie OIDC only and relied on the `/logout` CSRF exemption, 403 | Send the CSRF token properly, or use Bearer mode |

Others (no regression): stronger reactive back-channel JWKS validation, token-response no-store, and extended PII masking are **additional security only, requiring no configuration change**. The authorization cache (`authorization.cache.enabled`) and mandatory UserInfo (`authentication.require-user-info`) are **off by default, so there is no impact when unset**.

---

## 7. Troubleshooting

| Symptom | Cause / Action |
|------|-------------|
| Infinite login redirect | Check for a mismatch between `redirect-uri` and the Keycloak client's Valid Redirect URIs |
| actuator suddenly returns 401/403 (after upgrading to 1.5.0) | The Keycloak chain was turned on alongside → `matcher.exclude: [/actuator/**]` |
| Email/phone show up as `***` in logs (after 1.6.0) | PII masking on by default (expected). Disable with `NoOpLoggingValueSanitizer` |
| `NoClassDefFoundError` with Redis sessions | Missing `spring-boot-starter-data-redis` + `spring-session-data-redis` dependencies |
| Logout propagates only partially across multiple instances | Switch to `session.store-type: redis` |
| Token issuance API 404 | Check `bearer-token.enabled: true` and the prefix (`/auth`) path |
| 500 response after setting a cookie (`No enum constant ...SameSite.lax`) | Use uppercase for the `cookie.same-site` value — `Lax`/`Strict`/`None` |
| Authentication succeeds but all role-based authorization is denied | Authorities are extracted from **UserInfo** — Keycloak roles (`realm_access`/`resource_access`) may exist only in the access token. Enable "Add to userinfo" on the role mapper or parse the access token directly → [Manual Wiring Guide, Pitfall 2](15-WebFlux-수동배선-가이드.md) |
| (manual wiring) `AuthorizedClient not found` after successful login | Register an `AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository` bean → [Manual Wiring Guide, Pitfall 4](15-WebFlux-수동배선-가이드.md) |
| After an upgrade, `hasRole(...)`/`hasAuthority(...)` authorization is suddenly all denied | The Role mapping default changed to `SEPARATE_NAMESPACE` (Advisory 7) — authorities are split into `ROLE_REALM_*`/`ROLE_CLIENT_<CLIENT>_*` → [4.10 Migration](#410-role-mapping-realmclient-role-namespace-separation) |
| (manual wiring) `new KeycloakReactiveAuthenticationManager(client, clientId)` compile error | Add a `ReactiveJwtDecoder` parameter to the constructor (Advisory 1) → [Manual Wiring Guide §2](15-WebFlux-수동배선-가이드.md) |

---

## 8. Reactive(WebFlux)

Since v1.8.0, **the WebFlux stack is supported on par with servlet**. Just switch the dependency to `webflux-starter`.

```gradle
implementation("io.github.l-dxd:keycloak-spring-security-webflux-starter:1.8.0")
```

- **Configuration is 100% shared with servlet** — the `keycloak.*`, `keycloak.security.*` properties (§1.2, §3) apply as-is. (Both share the Properties from the core module.)
- **Feature parity**: OIDC login (`oauth2Login` + cookie/session) · Bearer · Basic · authorization (Authorization Services) · Rate Limiting · CSRF · Front/Back-Channel logout · MDC logging · SecurityFilterChain coexistence (Fail-Open prevention).

### Differences from servlet (due to architecture)

| Item | Difference |
|------|------|
| Security chain | `SecurityWebFilterChain` (reactive). When coexisting with a user's custom chain, `auto-filter-chain`/`matcher` work the same way |
| Session | reactive `WebSession`. For multiple instances, Spring Session Reactive (Redis) is recommended |
| OAuth2 AuthorizedClient | Default `InMemoryReactiveOAuth2AuthorizedClientService` — **for production, replacing it with a Redis-based implementation is recommended** (in-memory is lost on restart) |
| MDC logging | Automatic Reactor Context ↔ MDC propagation is **disabled by default**. To enable it, set `keycloak.security.logging.mdc-propagation-enabled=true` (uses global Reactor `Hooks`) |

### Extension Points
Replaceable via `@ConditionalOnMissingBean` just like servlet: `ReactiveAuthenticationManager`, `LoggingValueSanitizer`, `RateLimiter`, `SecurityWebFilterChain` (named `keycloakSecurityWebFilterChain`), etc.
