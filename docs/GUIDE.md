# keycloak-spring-security User Guide (3.x)

**English** | [한국어](GUIDE.ko.md)

A library that adds Keycloak login to a Spring Boot app. One starter and a few lines of configuration give a browser front end login, request authentication, token refresh and logout.

- **Supported**: Java 17+, Spring Boot 4.1.x, Spring Security 7.1.x, Servlet (Spring MVC). WebFlux comes in 3.1.0
- **Model**: a BFF, where the app holds the tokens instead of the front end. The browser only carries cookies, the access token is validated inside the app, and the refresh token is stored encrypted in the app database
- Coming from 2.x: [Migrating from v2 to v3](MIGRATION-v3.md). 2.x docs: [docs/v2](v2/GUIDE.md)

## Contents

1. [Quick start](#1-quick-start)
2. [How it works](#2-how-it-works)
3. [Configuration](#3-configuration)
4. [Features](#4-features)
5. [Replacing parts (extension)](#5-replacing-parts-extension)
6. [Troubleshooting](#6-troubleshooting)

---

## 1. Quick start

### 1-1. Dependencies

```gradle
implementation("io.github.l-dxd:keycloak-spring-security-web-starter:3.0.0")
implementation("org.springframework.boot:spring-boot-starter-webmvc")
implementation("org.springframework.boot:spring-boot-starter-jdbc")
implementation("org.springframework.boot:spring-boot-starter-flyway")   // creates the table (any migration tool works)
runtimeOnly("org.flywaydb:flyway-database-postgresql")
runtimeOnly("org.postgresql:postgresql")
```

### 1-2. Keycloak client

| Item | Value |
|---|---|
| Client authentication | On (confidential client with a secret) |
| Authentication flow | Standard flow only |
| PKCE Method | S256 |
| Valid redirect URIs | `https://{app}/login/oauth2/code/keycloak` |
| Valid post logout redirect URIs | `{front end}/` (front end after logout) |
| Backchannel logout URL | `https://{app}/logout/connect/back-channel/keycloak` |
| Backchannel logout session required | On |
| Access token `aud` | Contains the client id (Audience mapper) |
| Client Session Idle / Max | Idle logout time / maximum login time |

The reasons are in [section 5 of the migration guide](MIGRATION-v3.md#5-keycloak-client-settings).

### 1-3. Session table

Copy `kss/schema-postgresql.sql` from the core jar into a migration (for example `src/main/resources/db/migration/V2__auth_session.sql`). Without the table the app does not start.

### 1-4. Configuration

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/myapp
  security:
    oauth2:
      client:
        registration:
          keycloak:
            client-id: myapp
            client-secret: ${KEYCLOAK_CLIENT_SECRET}
            scope: openid
        provider:
          keycloak:
            issuer-uri: https://sso.example.com/realms/my-realm

keycloak:
  security:
    frontend:
      base-url: https://app.example.com          # front-end URL; if the front end and the API share an origin, that origin
    permit-all-paths: [/api/public/**]
    crypto:
      active-key-id: k1
      keys:
        k1: ${KSS_KEY_K1}                        # openssl rand -base64 32
```

### 1-5. Check

```bash
curl -i https://api.example.com/api/me
# 401 {"code":"AUTHENTICATION_REQUIRED","message":"...","loginUrl":"/oauth2/authorization/keycloak"}
```

Open `https://api.example.com/oauth2/authorization/keycloak?return=/` in a browser: the Keycloak login page appears, and after login you land on the front-end URL. `/api/me` now returns 200.

```java
@GetMapping("/api/me")
Map<String, Object> me(@AuthenticationPrincipal KeycloakPrincipal user) {
    return Map.of("sub", user.subject(), "username", user.username());
}
```

---

## 2. How it works

### 2-1. Cookies

| Cookie | Holds | Lifetime |
|---|---|---|
| `__Host-{app}_sid` | Random value that finds the session row (the database keeps only its SHA-256) | Until the absolute timeout |
| `__Host-{app}_at` | Access token (JWT) | Until the token expires |
| `__Host-{app}_csrf` | CSRF token signed with the sid | Until the absolute timeout |
| `__Host-{app}_login` | PKCE, state and return path during login (encrypted) | 5 minutes |

All are Secure, HttpOnly, SameSite=Lax, Path=/. The ID token is not kept anywhere.

### 2-2. One request

```text
MdcRequestFilter            log values such as traceId
→ CorsFilter                one allowed front end
→ KeycloakOriginFilter      Origin check for state-changing requests
→ CsrfFilter                CSRF token signed with the sid
→ KeycloakAccessTokenFilter validates the at cookie inside the app (no Keycloak, no database)
     ├ expired or missing → locks the session row, refreshes at Keycloak → new at cookie
     └ any other failure  → deletes the row and cookies (local logout)
→ MdcAuthenticationFilter   log values such as userId
→ AuthorizationFilter       login required except permit-all-paths
```

### 2-3. When a session ends

| Reason | When | Keycloak call |
|---|---|---|
| `logout` | The user sends `POST /logout` | Keycloak logout with the refresh token |
| `backchannel_logout` | Logout in another app, or an admin deletes the session | Keycloak calls the app |
| `idle` | Keycloak Client Session Idle passed | None |
| `absolute` | `session.absolute-timeout` passed | None (optional revoke) |
| `refresh_failed` | Keycloak rejected the refresh (`invalid_grant`) | |
| `invalid_token` | Token signature, iss, aud … do not match | None (optional revoke) |
| `decryption_failed` | The refresh token cannot be decrypted (key removed) | None |
| `relogin` | The same browser logs in again | None |

---

## 3. Configuration

Everything is under `keycloak.security.*`. If a value is wrong, startup stops and lists every wrong key. Secrets never appear in errors or logs.

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | `false` turns all auto-configuration off |
| `registration-id` | `keycloak` | `spring.security.oauth2.client.registration` id |
| `frontend.base-url` | (required) | Front-end URL. https only (http only for localhost) |
| `frontend.logout-success-path` | `/` | Front-end path after logout |
| `permit-all-paths` | `[]` | Paths that need no login |
| `auto-filter-chain` | `true` | Default security chain. Turn off only when your own chains cover every path ([5-4](#5-4-splitting-security-chains)) |
| `cookie.app-name` | client id | App name in the cookie names |
| `session.store` | `jdbc` | `jdbc` or `memory` (single-server development) |
| `session.table-name` | `auth_session` | |
| `session.absolute-timeout` | `12h` | Log in again after this long since login |
| `session.refresh-reuse-window` | `10s` | How long a concurrent refresh counts as "just refreshed" |
| `session.cleanup-interval` | `10m` | How often ended rows are deleted |
| `token.clock-skew` | `30s` | Allowed clock difference (0 to 5 minutes) |
| `token.jwks-min-refetch-interval` | `5m` | Minimum time between JWKS refetches for an unknown kid (10 seconds to 1 hour). Longer means fewer Keycloak calls when requests with bogus `kid` values pile up, and a longer 503 window right after Keycloak rotates its keys |
| `token.required-audience` | client id | Value that must be in the access token `aud` |
| `request.background-header` | `X-Background` | Requests with this header never refresh |
| `csrf.endpoint` | `/api/csrf` | Where the CSRF token is served |
| `logout.revoke-refresh-token-on-local-logout` | `false` | Also revoke the Keycloak refresh token when ending with `absolute` or `invalid_token` |
| `crypto.active-key-id` | (required) | Key id for new encryption |
| `crypto.keys.{id}` | (required) | base64 key, at least 32 bytes |
| `trusted-proxy-count` | `0` | Trusted proxies for the logged clientIp. 0 ignores `X-Forwarded-For` |
| `logging.*` | | [4-8](#4-8-logging-mdc) |

---

## 4. Features

### 4-1. Login

The front end sends the browser to `{app}/oauth2/authorization/keycloak?return=/orders/1`. After login it lands on `{frontend.base-url}/orders/1`. `return` accepts only relative paths starting with `/`; anything else becomes `/`.

On failure it lands on `{frontend.base-url}/?login_error=code`.

| Code | Meaning |
|---|---|
| `invalid_state` | Login cookie missing or older than 5 minutes, or state mismatch |
| `access_denied` | Cancelled on the Keycloak page |
| `invalid_token` | The received token failed validation |
| `login_failed` | Anything else |

### 4-2. The user in a controller

```java
@GetMapping("/api/me")
Map<String, Object> me(@AuthenticationPrincipal KeycloakPrincipal user) {
    return Map.of(
        "sub", user.subject(),                 // Principal#getName() is the sub too
        "username", user.username(),           // preferred_username
        "email", user.claimAsString("email"));
}
```

There are no authorities by default. To map roles, see [5-2](#5-2-roles-to-authorities).

### 4-3. Error responses

| Status | `code` | What the front end does |
|---|---|---|
| 401 | `AUTHENTICATION_REQUIRED` | Go to `loginUrl` from the body |
| 403 | `ACCESS_DENIED` | No permission |
| 403 | `INVALID_CSRF_TOKEN` | Fetch `/api/csrf` again and retry once |
| 403 | `ORIGIN_NOT_ALLOWED` | Front end not allowed |
| 405 | `METHOD_NOT_ALLOWED` | `/logout` accepts POST only |
| 503 | `KEYCLOAK_UNAVAILABLE` | Keycloak unreachable. The session is kept; try again later |

```json
{"code":"AUTHENTICATION_REQUIRED","message":"...","loginUrl":"/oauth2/authorization/keycloak"}
```

### 4-4. Refresh

When the access token expires, the app refreshes it on the next request. The front end does not notice. Concurrent requests of one session queue on a database row lock, so Keycloak is called once.

Add `X-Background: 1` to requests the front end sends on a timer (notification polling and so on). They never refresh, so a session left alone ends with the Keycloak Client Session Idle.

### 4-5. CSRF, Origin, CORS (front-end code)

```js
const api = "https://api.example.com";

async function csrf() {
  const r = await fetch(`${api}/api/csrf`, { credentials: "include" });
  return (await r.json()).token;            // {"headerName":"X-XSRF-TOKEN","parameterName":"_csrf","token":"..."}
}

async function post(path, body) {
  const send = async (token) => fetch(`${api}${path}`, {
    method: "POST", credentials: "include",
    headers: { "Content-Type": "application/json", "X-XSRF-TOKEN": token },
    body: JSON.stringify(body),
  });
  let r = await send(await csrf());
  if (r.status === 403 && (await r.clone().json()).code === "INVALID_CSRF_TOKEN") r = await send(await csrf());
  if (r.status === 401) location.href = api + (await r.json()).loginUrl + "?return=" + encodeURIComponent(location.pathname);
  return r;
}
```

| Rule | Details |
|---|---|
| CORS | Only the `frontend.base-url` origin, with credentials. Allowed headers `Content-Type`·`Accept`·`X-Requested-With`·`X-XSRF-TOKEN`·`X-Background` |
| Origin check | Except GET·HEAD·OPTIONS·TRACE, `Origin` (or `Referer`) must be the allowed front end |
| CSRF | `X-XSRF-TOKEN` header or form field `_csrf`. The token is bound to the sid, so a planted cookie does not work |
| Exclusions | Keycloak's back-channel logout and the OIDC callback are excluded automatically. Webhooks and similar: [5-3](#5-3-configurer-customizers) |

### 4-6. Logout

The front end sends `POST {app}/logout` with the CSRF token (a form submit follows the 302). The app deletes the session row and cookies and logs out of Keycloak with the refresh token.

| Result | Response |
|---|---|
| Keycloak logout succeeded, or there was no session | 302 to `{frontend.base-url}{logout-success-path}` |
| Keycloak rejected it or was unreachable | 302 to the Keycloak logout page (after confirming, the user returns to the front end) |

`GET /logout` returns 405.

### 4-7. Back-channel logout

When the user logs out in another app or an admin deletes the Keycloak session, Keycloak calls `POST {app}/logout/connect/back-channel/keycloak`. The app deletes the session rows by the token's `sid`. The browser's at cookie keeps working until it expires (Access Token Lifespan) and gets 401 at the next refresh. If it must stop sooner, keep the Access Token Lifespan short.

### 4-8. Logging (MDC)

Each request puts these in the MDC. Names and defaults are the same as v2.

| Key | Setting (`logging.`) | Default |
|---|---|---|
| `traceId` | `include-trace-id` | On. `X-Request-Id` if it is letters, digits, `. _ : -` and at most 128 characters; otherwise a new UUID. Response `X-Request-Id` (`return-trace-id-header`) |
| `httpMethod`, `requestUri` | `include-http-method`, `include-request-uri` | On |
| `queryString` | `include-query-string`, `max-query-length` | Off, 512 |
| `clientIp` | `include-client-ip` | On. Uses `trusted-proxy-count` |
| `userAgent` | `include-user-agent`, `max-user-agent-length` | On, 256 |
| `userId`, `username`, `sessionId` | `include-user-id`, `include-username`, `include-session-id` | On. `sessionId` is the Keycloak `sid` |
| `status`, `durationMs` | `include-response-metrics` | Off |
| (excluded paths) | `exclude-patterns` | `[/actuator/**]` |

Query string, User-Agent and username go through `LoggingValueSanitizer` (default: masks JWT, Bearer, e-mail, phone, resident registration and card numbers). Token and cookie values never go into any log.

### 4-9. Session events and audit log

Login (CREATED), refresh (REFRESHED) and end (ENDED + [reason](#2-3-when-a-session-ends)) are published as events. By default they are logged to `com.ids.keycloak.security.audit` (user id shortened to 8 characters).

```java
@EventListener
void onSession(KeycloakSessionEvent event) {
    if (event.type() == KeycloakSessionEvent.Type.ENDED) {
        audit.save(event.keycloakUserId(), event.endReason(), event.occurredAt());
    }
}
```

A `KeycloakSessionEventListener` bean receives the events instead of the default audit log.

### 4-10. Rotating keys

```yaml
keycloak.security.crypto:
  active-key-id: k2          # key for new encryption
  keys:
    k1: ${KSS_KEY_K1}        # kept to read old rows
    k2: ${KSS_KEY_K2}
```

Each row stores its key id, so old rows stay readable. Remove `k1` after every row encrypted with it has ended (after the absolute timeout). Removing it earlier ends those sessions with `decryption_failed`.

---

## 5. Replacing parts (extension)

### 5-1. Beans

Every auto-configured bean is `@ConditionalOnMissingBean`. Register a bean of the same type and the library uses yours. Common ones:

| Bean | Default | Example change |
|---|---|---|
| `KeycloakPrincipalConverter` | `KeycloakPrincipal`, no authorities | Roles to authorities, lookup in the app's user table |
| `KeycloakSessionStore` | JDBC (PostgreSQL, H2) | Another database |
| `KeycloakSessionEventListener` | Audit log | Audit table |
| `KeycloakCookieWriter` | `__Host-{app}_*` | Cookie naming |
| `KeycloakErrorResponseWriter` | JSON `code`·`message` | The app's error format |
| `KeycloakTokenClient` | Spring OAuth2 Client, 2 s connect, 5 s read | Proxy, timeouts |
| `TokenCipher` | AES-256-GCM | KMS |
| `LoggingValueSanitizer`, `LoggingContextAccessor` | Masking, SLF4J MDC | In-house logging standard |
| `keycloakCorsConfigurationSource` (by name) | One front-end origin | More origins or headers |

The full list is in [design 4-3](v3/01-설계.md#4-3-확장-지점-커스텀-열어-두기) (Korean).

### 5-2. Roles to authorities

```java
@Bean
KeycloakPrincipalConverter keycloakPrincipalConverter() {
    return new DefaultKeycloakPrincipalConverter() {
        @Override
        protected Collection<? extends GrantedAuthority> authorities(Jwt token) {
            Map<String, Object> realm = token.getClaimAsMap("realm_access");
            if (realm == null || !(realm.get("roles") instanceof List<?> roles)) {
                return List.of();
            }
            return roles.stream().map(r -> new SimpleGrantedAuthority("ROLE_" + r)).toList();
        }
    };
}
```

Configure the Keycloak client so roles reach the access token (full scope or a role scope).

### 5-3. Configurer customizers

```java
@Bean
SecurityFilterChain keycloakSecurityFilterChain(HttpSecurity http, ClientRegistrationRepository clients,
                                               LogoutHandler appCacheEvictor) throws Exception {
    var resolver = new DefaultOAuth2AuthorizationRequestResolver(clients, "/oauth2/authorization");
    resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce()   // keep PKCE
        .andThen(b -> b.additionalParameters(p -> p.put("acr_values", "loa2"))));
    return http
        .authorizeHttpRequests(a -> a.requestMatchers("/api/public/**").permitAll().anyRequest().authenticated())
        .with(KeycloakHttpConfigurer.keycloak()
                .login(l -> l.authorizationEndpoint(e -> e.authorizationRequestResolver(resolver)))
                .csrf(c -> c.ignoringRequestMatchers("/api/webhooks/**"))
                .logout(l -> l.addLogoutHandler(appCacheEvictor)),
            Customizer.withDefaults())
        .build();
}
```

Customizers run after the library's settings, so your value wins. Naming the bean `keycloakSecurityFilterChain` makes it replace the default chain. In your own chain, its `authorizeHttpRequests` decides the public paths instead of `permit-all-paths`.

### 5-4. Splitting security chains

If you add a chain for some paths only, the default chain stays behind it and protects every other path.

```java
@Bean
@Order(0)
SecurityFilterChain actuator(HttpSecurity http) throws Exception {
    return http.securityMatcher("/actuator/**")
        .authorizeHttpRequests(a -> a.requestMatchers("/actuator/health").permitAll().anyRequest().denyAll())
        .build();
}
```

| Goal | How |
|---|---|
| Different rules for some paths | `securityMatcher` + `@Order` as above. The default chain stays |
| Replace the default chain | Name your bean `keycloakSecurityFilterChain` ([5-3](#5-3-configurer-customizers)) |
| Build every chain yourself | `keycloak.security.auto-filter-chain: false` + `KeycloakHttpConfigurer` on your chain |

If you add another chain that matches every request under a different name, Spring Security stops startup (one of the two chains could never be used).

---

## 6. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Startup fails on `keycloak.security.crypto.keys` | Key missing or shorter than 32 bytes. `openssl rand -base64 32` |
| Startup fails on the session table | The `auth_session` migration is missing ([1-3](#1-3-session-table)) |
| Startup fails on a public client | Turn on Client authentication in Keycloak and set the secret |
| `?login_error=invalid_state` after login | Login took over 5 minutes, or the app is not on https so the `__Host-` cookie was dropped |
| `?login_error=invalid_token` after login | The access token `aud` lacks the client id (Audience mapper), or `sid` is missing (`basic` scope). Or Keycloak just rotated its signing key and the app last tried to fetch the JWKS less than `token.jwks-min-refetch-interval` ago (log in again once that has passed) |
| 403 `ORIGIN_NOT_ALLOWED` on state-changing requests | `frontend.base-url` differs from the front-end origin |
| 403 `INVALID_CSRF_TOKEN` on state-changing requests | No `X-XSRF-TOKEN` header. Check `credentials: "include"` |
| Sudden 503 `KEYCLOAK_UNAVAILABLE` | The app cannot reach Keycloak (JWKS or token endpoint). Or Keycloak just rotated its signing key and the app last tried to fetch the JWKS less than `token.jwks-min-refetch-interval` (default 5 minutes) ago (it refetches once that has passed). Either way sessions are kept |
| Still logged in briefly after logout in another app | The at cookie works until it expires ([4-7](#4-7-back-channel-logout)) |
| Back-channel logout never arrives | Check Keycloak can reach the app, the Backchannel logout URL and "session required" |
| E-mail shows as `a***@…` in logs | Masking (expected). To turn it off, a `NoOpLoggingValueSanitizer` bean |
