# Migrating from v2 to v3

**English** | [한국어](MIGRATION-v3.ko.md)

v3 is a rewrite, not a patch on v2. The starter name, the `keycloak.security.*` prefix and the way you extend the library (replace a bean, `KeycloakHttpConfigurer`) stay the same, but the authentication model changed, so most settings, the database and the Keycloak client settings change with it. This page lists what to change, in tables. The new behaviour is in the [User Guide](GUIDE.md); the design background is in [docs/v3](v3/README.md) (Korean).

## 1. At a glance

| Item | v2 (2.0.x) | v3 (3.0.x) |
|---|---|---|
| Spring Boot · Security | 3.5 · 6.5 | 4.1 · 7.1 (upgrade the app to Boot 4.1 first) |
| Java | 17+ | 17+ |
| Stack | Servlet, WebFlux | Servlet only. WebFlux comes in 3.1.0 |
| Request authentication | Keycloak introspect + UserInfo on every request | The access token (JWT) in the `at` cookie is validated inside the app. No Keycloak or DB call per request |
| Server state | Tokens in HttpSession (memory or Redis) | No HttpSession. Only the refresh token, encrypted, in an `auth_session` row in the app database |
| Cookies | `access_token`, `id_token` | `__Host-{app}_sid`, `_at`, `_csrf`, plus `_login` during login |
| Session end | 30 minutes idle (`session.timeout`) | Idle = Keycloak Client Session Idle; hard limit = `session.absolute-timeout` (default 12 hours) |
| CSRF | Token stored in the session or a cookie | Double-submit token signed with the sid + Origin check. The front end fetches it from `GET /api/csrf` |
| Logout | Always redirects to the OIDC logout endpoint | The server logs out of Keycloak with the refresh token. Redirects to the OIDC logout endpoint only if that fails |
| Dependencies | `keycloak-client` (reactor-netty, jjwt, Jackson 2) | Spring Security OAuth2 Client and `RestClient` only |

## 2. Dependencies

```gradle
// v2
implementation("io.github.l-dxd:keycloak-spring-security-web-starter:2.0.3")

// v3 (Boot 4.1 app)
implementation("io.github.l-dxd:keycloak-spring-security-web-starter:3.0.0")
implementation("org.springframework.boot:spring-boot-starter-jdbc")   // session rows (default store)
runtimeOnly("org.postgresql:postgresql")
```

Remove the Redis and `spring-session-*` dependencies. There is no WebFlux starter in 3.0.0 (stay on v2 until 3.1.0).

## 3. Configuration keys

### 3-1. Keycloak connection

| v2 | v3 |
|---|---|
| `keycloak.base-url`, `keycloak.realm-name`, `keycloak.relative-path` | One key: `spring.security.oauth2.client.provider.keycloak.issuer-uri: https://{keycloak}/realms/{realm}` |
| `keycloak.security.authentication.issuer-uri` | The same `issuer-uri` (required). Used to check the token `iss` |
| `keycloak.response.type` | Gone (`authorization_code` only, PKCE S256) |
| `keycloak.logout.redirect.uri` | `keycloak.security.frontend.base-url` + `frontend.logout-success-path` |
| `spring.security.oauth2.client.registration.keycloak.*` | Unchanged. The client must be confidential (secret) with `scope: openid` |

### 3-2. `keycloak.security.*`

| v2 key | v3 | Alternative |
|---|---|---|
| `authentication.permit-all-paths` | `permit-all-paths` (one level up) | |
| `authentication.default-success-url` | Gone | After login the user goes to `frontend.base-url` + the `?return=` path (`/oauth2/authorization/keycloak?return=/orders`) |
| `authentication.login-paths` | Gone | Login where the app receives the password was removed |
| `authentication.authorization-request.acr-values`·`max-age`·`prompt` | Gone | Replace the resolver of `authorizationEndpoint` in the configurer's `login(...)` customizer (guide 5-3) |
| `authentication.security-context-repository` | Gone | No HttpSession |
| `authentication.require-user-info` | Gone | UserInfo is not called |
| `authorization.enabled` (Keycloak authorization) | Gone | The app authorizes (`authorizeHttpRequests`, `@PreAuthorize`) |
| `session.store-type: MEMORY \| REDIS` | `session.store: jdbc \| memory` (default `jdbc`) | Use `jdbc` for several servers. Other stores: a `KeycloakSessionStore` bean |
| `session.timeout` (30m) | Gone | Idle time is the Keycloak client's Client Session Idle. Hard limit is `session.absolute-timeout` |
| `session.max-sessions` | Gone | Rows live in the database and are removed every `session.cleanup-interval` |
| `session.cleanup-interval` (5m) | `session.cleanup-interval` (default 10m, removes database rows) | |
| `session.back-channel-logout-strict` | Gone | Back-channel logout always works, whatever the store |
| `session.cleanup-corrupted` | Gone | |
| `cookie.http-only`·`secure`·`domain`·`path`·`same-site` | Gone (fixed: `__Host-`, Secure, HttpOnly, SameSite=Lax, Path=/) | Only the app name in the cookie name: `cookie.app-name`. To change more, a `KeycloakCookieWriter` bean |
| `error.*` | Gone | 401·403·503 are JSON (`code`, `message`, and `loginUrl` on 401). To change them, `KeycloakAuthenticationEntryPoint`·`KeycloakAccessDeniedHandler`·`KeycloakErrorResponseWriter` beans |
| `basic-auth.*` | Gone | Server-to-server calls: a Keycloak service account token and a separate resource server chain in the app |
| `bearer-token.*` (introspect, `/auth/token` …) | Gone | Same as above |
| `csrf.enabled` | Gone (always on) | |
| `csrf.ignore-paths` | Gone | Configurer `csrf(c -> c.ignoringRequestMatchers(...))` |
| `csrf.token-repository` | Gone | One signed cookie repository. To change it, a `CsrfTokenRepository` bean |
| `rate-limit.*` | Gone | In the gateway or the app |
| `logging.*` | Unchanged (same names and defaults) | Only input filtering differs (guide 4-8) |
| `trusted-proxy-count` | Unchanged | |
| `auto-filter-chain` | Unchanged (default `true`) | |
| `matcher.include`·`exclude` | Gone | Put `securityMatcher` and `@Order` on your chain. The default chain stays last and takes the remaining paths |
| `role-mapping.*` | Gone (no authorities by default) | Map token claims to authorities in a `KeycloakPrincipalConverter` bean (guide 5-2) |
| `static-resources.*` | Gone | Request authentication runs inside the app, so static files no longer call Keycloak. Public paths go in `permit-all-paths` |

### 3-3. New in v3

| Key | Default | Required | Description |
|---|---|---|---|
| `frontend.base-url` | | yes | Front-end URL. CORS, Origin check, where to go after login and logout. If the front end and the API share an origin, that origin |
| `frontend.logout-success-path` | `/` | | Front-end path after logout |
| `cookie.app-name` | client id | | `__Host-{app name}_sid` |
| `session.table-name` | `auth_session` | | |
| `session.absolute-timeout` | `12h` | | Log in again after this long since login |
| `session.refresh-reuse-window` | `10s` | | How long a concurrent refresh counts as "just refreshed" |
| `token.clock-skew` | `30s` | | Allowed clock difference (0 to 5 minutes) |
| `token.required-audience` | client id | | Value that must be in the access token `aud` |
| `request.background-header` | `X-Background` | | Requests with this header never refresh the token |
| `csrf.endpoint` | `/api/csrf` | | Where the front end gets the CSRF token |
| `logout.revoke-refresh-token-on-local-logout` | `false` | | Also revoke the Keycloak refresh token on a local logout |
| `crypto.active-key-id` | | yes | Key id used for new encryption |
| `crypto.keys.{id}` | | yes | base64 key, at least 32 bytes (`openssl rand -base64 32`). From an environment variable or a secret store |
| `registration-id` | `keycloak` | | `spring.security.oauth2.client.registration` id |
| `enabled` | `true` | | `false` turns all auto-configuration off |

### 3-4. Example

```yaml
# v2
keycloak:
  realm-name: my-realm
  base-url: https://sso.example.com
  logout.redirect.uri: https://app.example.com/
  security:
    authentication:
      permit-all-paths: [/public/**]
    session:
      store-type: redis
      timeout: 30m
    cookie:
      same-site: Lax

# v3
spring.security.oauth2.client:
  registration.keycloak: { client-id: myapp, client-secret: ${KEYCLOAK_CLIENT_SECRET}, scope: openid }
  provider.keycloak.issuer-uri: https://sso.example.com/realms/my-realm
keycloak:
  security:
    frontend:
      base-url: https://app.example.com
    permit-all-paths: [/public/**]
    crypto:
      active-key-id: k1
      keys:
        k1: ${KSS_KEY_K1}
```

If a setting is wrong, startup stops and lists every wrong key.

## 4. Database schema

You need one session table. The SQL is in the core jar at `kss/schema-postgresql.sql` (`kss/schema-h2.sql` for tests); your migration tool applies it. If the table or a column is missing, the starter stops startup.

```sql
-- Flyway example: src/main/resources/db/migration/V{n}__auth_session.sql
CREATE TABLE auth_session (
  id                  UUID         PRIMARY KEY,
  sid_hash            CHAR(64)     NOT NULL UNIQUE,  -- SHA-256 of the sid cookie (never the raw value)
  keycloak_user_id    VARCHAR(64)  NOT NULL,         -- access token sub
  kc_sid              VARCHAR(64)  NOT NULL,         -- access token sid (for back-channel logout)
  refresh_token_enc   BYTEA        NOT NULL,         -- AES-256-GCM
  enc_key_id          VARCHAR(32)  NOT NULL,
  refresh_expires_at  TIMESTAMPTZ  NOT NULL,
  created_at          TIMESTAMPTZ  NOT NULL,
  absolute_expires_at TIMESTAMPTZ  NOT NULL,
  refreshed_at        TIMESTAMPTZ
);
CREATE INDEX ix_auth_session_kc_sid ON auth_session (kc_sid);
CREATE INDEX ix_auth_session_user   ON auth_session (keycloak_user_id);
CREATE INDEX ix_auth_session_abs    ON auth_session (absolute_expires_at);
```

| Item | Details |
|---|---|
| Database | PostgreSQL. H2 for tests. Other databases: implement `KeycloakSessionStore` |
| Extra columns | The app may add columns. The library reads and writes only the columns above |
| Table name | `keycloak.security.session.table-name` |
| v2 data | Not migrated. After the deploy every user logs in once more (v3 does not read v2 sessions or cookies) |
| Redis | Not used by v3. v2 session keys expire through their TTL |

## 5. Keycloak client settings

| Item | Value | Why |
|---|---|---|
| Client authentication | On (confidential client) | The server refreshes and logs out with the client secret. A public client stops startup |
| Standard flow | On | Login |
| Direct access grants, Implicit flow | Off | Not used by v3 |
| PKCE Method | S256 | The library always sends S256 |
| Valid redirect URIs | `https://{api}/login/oauth2/code/keycloak` only | |
| Valid post logout redirect URIs | `{frontend.base-url}{logout-success-path}` | Where Keycloak returns the user when the server logout failed |
| Backchannel logout URL | `https://{api}/logout/connect/back-channel/keycloak` | Must be reachable from Keycloak |
| Backchannel logout session required | On | Rows are deleted by `sid` (a token without `sid` gets 400) |
| Front channel logout | Off | |
| Audience | Client id in the access token `aud` (Audience mapper) | `token.required-audience` defaults to the client id |
| Client scopes | Keep the default `basic` | `sub` and `sid` must be in the access token |
| Client Session Idle | The app's idle limit | Refresh token expiry = idle logout |
| Client Session Max | Less than or equal to `session.absolute-timeout` | |
| Access Token Lifespan | Short (Keycloak default 5 minutes) | After a back-channel logout the at cookie still works until it expires |

## 6. Code

| v2 | v3 |
|---|---|
| `@AuthenticationPrincipal` (OIDC user) | `@AuthenticationPrincipal KeycloakPrincipal user` (`subject()`, `sessionId()`, `username()`, claims). `Principal#getName()` is the sub |
| `KeycloakLoginService` (log in with tokens) | Gone. Login only through the Keycloak page |
| Roles → `ROLE_REALM_*`·`ROLE_CLIENT_*` | No authorities by default. Use a `KeycloakPrincipalConverter` bean |
| `http.with(KeycloakHttpConfigurer.keycloak(), ...)` | Unchanged. The configurer now takes `login`·`csrf`·`cors`·`logout` `Customizer`s |
| `LoggingValueSanitizer`, `LoggingContextAccessor` beans | Unchanged |
| Manual wiring (`auto-filter-chain: false` + assembling components) | `auto-filter-chain: false` + `KeycloakHttpConfigurer` on your chain. The configurer builds the filters |

## 7. Front end

| Task | How |
|---|---|
| Login | `location.href = "{api}/oauth2/authorization/keycloak?return=/current/path"` |
| API calls | `credentials: "include"`. On 401, go to `loginUrl` from the body |
| State-changing requests | Put the `token` from `GET {api}/api/csrf` in the `X-XSRF-TOKEN` header (or form field `_csrf`). On 403 `INVALID_CSRF_TOKEN`, fetch it again and retry once |
| Polling | Add `X-Background: 1` (so the session does not live forever) |
| Logout | `POST {api}/logout` with the CSRF token. Follow the 302 |
| Login failure | Front end `/?login_error=code` (`invalid_state`, `access_denied`, `invalid_token`, `login_failed`) |

## 8. Steps

1. Upgrade the app to Spring Boot 4.1.
2. Change the dependency to 3.0.0 and remove Redis and spring-session.
3. Add the `auth_session` migration.
4. Change the settings as in section 3 and put the keys (`crypto.keys`) in your secret store.
5. Change the Keycloak client as in section 5.
6. Change the front end as in section 7.
7. Deploy. Users log in once more.
