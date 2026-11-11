# v2 → v3 옮기기

[English](MIGRATION-v3.md) | **한국어**

v3는 v2를 고친 판이 아니라 새로 짠 판입니다. 스타터 이름과 `keycloak.security.*` 접두사, 확장 방식(빈 바꿔 끼우기, `KeycloakHttpConfigurer`)은 그대로지만 인증 방식이 바뀌어서 설정 대부분과 DB, Keycloak client 설정을 같이 바꿔야 합니다. 이 문서는 바꿀 것을 표로 모았습니다. 새 동작은 [사용 가이드](GUIDE.ko.md), 설계 배경은 [docs/v3](v3/README.md)에 있습니다.

## 1. 한눈에

| 항목 | v2 (2.0.x) | v3 (3.0.x) |
|---|---|---|
| Spring Boot · Security | 3.5 · 6.5 | 4.1 · 7.1 (앱을 먼저 Boot 4.1로 올립니다) |
| Java | 17+ | 17+ |
| 스택 | Servlet, WebFlux | Servlet만. WebFlux는 3.1.0 |
| 요청 인증 | 요청마다 Keycloak introspect + UserInfo | `at` 쿠키의 액세스 토큰(JWT)을 앱 안에서 검증. 요청마다 Keycloak도 DB도 부르지 않음 |
| 서버 상태 | HttpSession(메모리·Redis)에 토큰 | HttpSession 없음. 앱 DB `auth_session` 행에 리프레시 토큰만 암호화해서 |
| 쿠키 | `access_token`, `id_token` | `__Host-{앱}_sid`, `_at`, `_csrf`, 로그인 중에만 `_login` |
| 세션 끝 | 미사용 30분(`session.timeout`) | 미사용은 Keycloak Client Session Idle, 절대 상한은 `session.absolute-timeout`(기본 12시간) |
| CSRF | 세션 또는 쿠키 저장 토큰 | sid로 서명한 double-submit 토큰 + Origin 확인. 화면은 `GET /api/csrf`로 받음 |
| 로그아웃 | 항상 OIDC 로그아웃 주소로 이동 | 서버가 리프레시 토큰으로 Keycloak 로그아웃. 실패할 때만 OIDC 로그아웃 주소로 |
| 의존성 | `keycloak-client`(reactor-netty, jjwt, Jackson 2) | Spring Security OAuth2 Client와 `RestClient`만 |

## 2. 의존성

```gradle
// v2
implementation("io.github.l-dxd:keycloak-spring-security-web-starter:2.0.3")

// v3 (Boot 4.1 앱)
implementation("io.github.l-dxd:keycloak-spring-security-web-starter:3.0.0")
implementation("org.springframework.boot:spring-boot-starter-jdbc")   // 세션 행 (기본 저장소)
runtimeOnly("org.postgresql:postgresql")
```

Redis·`spring-session-*` 의존성은 지웁니다. WebFlux 스타터는 3.0.0에 없습니다(3.1.0까지 v2를 씁니다).

## 3. 설정 키

### 3-1. Keycloak 연결

| v2 | v3 |
|---|---|
| `keycloak.base-url`, `keycloak.realm-name`, `keycloak.relative-path` | `spring.security.oauth2.client.provider.keycloak.issuer-uri: https://{keycloak}/realms/{realm}` 하나로 |
| `keycloak.security.authentication.issuer-uri` | 같은 `issuer-uri`(필수). 토큰 `iss` 검사에 씀 |
| `keycloak.response.type` | 없음 (`authorization_code` 고정, PKCE S256) |
| `keycloak.logout.redirect.uri` | `keycloak.security.frontend.base-url` + `frontend.logout-success-path` |
| `spring.security.oauth2.client.registration.keycloak.*` | 그대로. client는 비공개(secret)여야 하고 `scope: openid` |

### 3-2. `keycloak.security.*`

| v2 키 | v3 | 대안 |
|---|---|---|
| `authentication.permit-all-paths` | `permit-all-paths` (한 단계 위로) | |
| `authentication.default-success-url` | 없음 | 로그인 뒤에는 `frontend.base-url` + `?return=` 경로로 갑니다 (`/oauth2/authorization/keycloak?return=/orders`) |
| `authentication.login-paths` | 없음 | 비밀번호를 앱이 받는 로그인은 v3에서 뺐습니다 |
| `authentication.authorization-request.acr-values`·`max-age`·`prompt` | 없음 | 설정기 `login(...)` Customizer에서 `authorizationEndpoint`의 resolver를 바꿉니다 (가이드 5-3) |
| `authentication.security-context-repository` | 없음 | HttpSession을 쓰지 않습니다 |
| `authentication.require-user-info` | 없음 | UserInfo를 부르지 않습니다 |
| `authorization.enabled` (Keycloak 인가) | 없음 | 인가는 앱이 합니다 (`authorizeHttpRequests`, `@PreAuthorize`) |
| `session.store-type: MEMORY \| REDIS` | `session.store: jdbc \| memory` (기본 `jdbc`) | 여러 서버는 `jdbc`. 다른 저장소는 `KeycloakSessionStore` 빈 |
| `session.timeout` (30m) | 없음 | 미사용 시간은 Keycloak client의 Client Session Idle. 절대 상한은 `session.absolute-timeout` |
| `session.max-sessions` | 없음 | 행은 DB에 있고 `session.cleanup-interval`마다 지웁니다 |
| `session.cleanup-interval` (5m) | `session.cleanup-interval` (기본 10m, DB 행 정리) | |
| `session.back-channel-logout-strict` | 없음 | back-channel 로그아웃은 저장소와 상관없이 늘 됩니다 |
| `session.cleanup-corrupted` | 없음 | |
| `cookie.http-only`·`secure`·`domain`·`path`·`same-site` | 없음 (`__Host-`, Secure, HttpOnly, SameSite=Lax, Path=/ 고정) | 이름에 넣을 앱 이름만 `cookie.app-name`. 바꾸려면 `KeycloakCookieWriter` 빈 |
| `error.*` | 없음 | 401·403·503은 JSON(`code`, `message`, 401에는 `loginUrl`). 바꾸려면 `KeycloakAuthenticationEntryPoint`·`KeycloakAccessDeniedHandler`·`KeycloakErrorResponseWriter` 빈 |
| `basic-auth.*` | 없음 | 서버끼리 부르는 호출은 Keycloak service account 토큰 + 앱의 별도 resource server 체인 |
| `bearer-token.*` (introspect, `/auth/token` 등) | 없음 | 위와 같음 |
| `csrf.enabled` | 없음 (늘 켬) | |
| `csrf.ignore-paths` | 없음 | 설정기 `csrf(c -> c.ignoringRequestMatchers(...))` |
| `csrf.token-repository` | 없음 | 서명한 쿠키 저장소 하나. 바꾸려면 `CsrfTokenRepository` 빈 |
| `rate-limit.*` | 없음 | 게이트웨이나 앱에서 |
| `logging.*` | 그대로 (이름·기본값 같음) | 입력값을 거르는 점만 다릅니다 (가이드 4-8) |
| `trusted-proxy-count` | 그대로 | |
| `auto-filter-chain` | 그대로 (기본 `true`) | |
| `matcher.include`·`exclude` | 없음 | 앱 체인에 `securityMatcher`와 `@Order`. 기본 체인은 맨 뒤에서 나머지 주소를 받습니다 |
| `role-mapping.*` | 없음 (기본은 권한 없음) | `KeycloakPrincipalConverter` 빈에서 토큰 클레임을 권한으로 바꿉니다 (가이드 5-2) |
| `static-resources.*` | 없음 | 요청 인증이 앱 안에서 끝나 정적 파일마다 Keycloak을 부르지 않습니다. 공개할 경로는 `permit-all-paths` |

### 3-3. v3에서 새로 생긴 키

| 키 | 기본값 | 필수 | 설명 |
|---|---|---|---|
| `frontend.base-url` | | 필수 | 화면 주소. CORS·Origin 확인, 로그인 뒤·로그아웃 뒤 주소. 화면과 API가 같은 주소면 그 주소 |
| `frontend.logout-success-path` | `/` | | 로그아웃 뒤 화면 경로 |
| `cookie.app-name` | client id | | `__Host-{앱 이름}_sid` |
| `session.table-name` | `auth_session` | | |
| `session.absolute-timeout` | `12h` | | 로그인부터 이 시간이 지나면 다시 로그인 |
| `session.refresh-reuse-window` | `10s` | | 동시 갱신을 "방금 갱신함"으로 볼 시간 |
| `token.clock-skew` | `30s` | | 시간 검사 오차 (0~5분) |
| `token.required-audience` | client id | | 액세스 토큰 `aud`에 있어야 하는 값 |
| `request.background-header` | `X-Background` | | 이 헤더가 붙은 요청은 토큰을 갱신하지 않음 |
| `csrf.endpoint` | `/api/csrf` | | CSRF 토큰을 주는 주소 |
| `logout.revoke-refresh-token-on-local-logout` | `false` | | 로컬 로그아웃 때 Keycloak 리프레시 토큰도 폐기 |
| `crypto.active-key-id` | | 필수 | 새로 암호화할 때 쓰는 키 id |
| `crypto.keys.{id}` | | 필수 | base64 키, 32바이트 이상 (`openssl rand -base64 32`). 환경 변수·비밀 저장소에서 |
| `registration-id` | `keycloak` | | `spring.security.oauth2.client.registration` id |
| `enabled` | `true` | | 끄면 자동 설정이 아무것도 올리지 않음 |

### 3-4. 바꾼 예

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

설정이 잘못되면 잘못된 키 이름을 모두 모아 보여 주고 기동하지 않습니다.

## 4. DB 스키마

세션 행 테이블 하나가 필요합니다. SQL은 core jar 안 `kss/schema-postgresql.sql`(테스트용 `kss/schema-h2.sql`)에 있고, 적용은 앱의 마이그레이션 도구가 합니다. 테이블이나 열이 없으면 스타터가 기동을 멈춥니다.

```sql
-- Flyway 예: src/main/resources/db/migration/V{n}__auth_session.sql
CREATE TABLE auth_session (
  id                  UUID         PRIMARY KEY,
  sid_hash            CHAR(64)     NOT NULL UNIQUE,  -- sid 쿠키의 SHA-256 (원문 저장 안 함)
  keycloak_user_id    VARCHAR(64)  NOT NULL,         -- 액세스 토큰 sub
  kc_sid              VARCHAR(64)  NOT NULL,         -- 액세스 토큰 sid (back-channel 로그아웃용)
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

| 항목 | 내용 |
|---|---|
| DB | PostgreSQL. H2는 테스트용. 다른 DB는 `KeycloakSessionStore`를 구현합니다 |
| 열 추가 | 앱이 열을 더 붙여도 됩니다. 라이브러리는 위 열만 읽고 씁니다 |
| 테이블 이름 | `keycloak.security.session.table-name` |
| v2 데이터 | 옮기지 않습니다. 배포하면 모두 한 번 다시 로그인합니다(v2 세션·쿠키는 v3가 읽지 않음) |
| Redis | v3는 쓰지 않습니다. v2 세션 키는 TTL로 사라집니다 |

## 5. Keycloak client 설정

| 항목 | 값 | 이유 |
|---|---|---|
| Client authentication | 켬 (비공개 client) | 갱신·로그아웃을 서버가 client secret으로 부릅니다. 공개 client면 기동하지 않습니다 |
| Standard flow | 켬 | 로그인 |
| Direct access grants, Implicit flow | 끔 | v3는 쓰지 않습니다 |
| PKCE Method | S256 | 라이브러리가 늘 S256을 보냅니다 |
| Valid redirect URIs | `https://{api}/login/oauth2/code/keycloak` 하나 | |
| Valid post logout redirect URIs | `{frontend.base-url}{logout-success-path}` | Keycloak 로그아웃 주소로 갈 때(서버 로그아웃 실패) 돌아올 곳 |
| Backchannel logout URL | `https://{api}/logout/connect/back-channel/keycloak` | Keycloak에서 앱 주소에 닿아야 합니다 |
| Backchannel logout session required | 켬 | `sid`로 세션 행을 지웁니다(`sid` 없는 토큰은 400) |
| Front channel logout | 끔 | |
| Audience | 액세스 토큰 `aud`에 client id (Audience mapper) | `token.required-audience` 기본값이 client id |
| Client scopes | 기본 `basic` 유지 | `sub`·`sid`가 액세스 토큰에 있어야 합니다 |
| Client Session Idle | 앱의 미사용 상한 | 리프레시 토큰 만료 = 미사용 로그아웃 |
| Client Session Max | `session.absolute-timeout`보다 짧거나 같게 | |
| Access Token Lifespan | 짧게 (Keycloak 기본 5분) | back-channel 로그아웃 뒤에도 at 쿠키는 만료까지 통합니다 |

## 6. 코드

| v2 | v3 |
|---|---|
| `@AuthenticationPrincipal` (OIDC 사용자) | `@AuthenticationPrincipal KeycloakPrincipal user` (`subject()`, `sessionId()`, `username()`, 클레임). `Principal#getName()`은 sub |
| `KeycloakLoginService` (토큰으로 로그인) | 없음. 로그인은 Keycloak 화면으로만 |
| 역할 → `ROLE_REALM_*`·`ROLE_CLIENT_*` | 기본 권한 없음. `KeycloakPrincipalConverter` 빈으로 |
| `http.with(KeycloakHttpConfigurer.keycloak(), ...)` | 그대로. 설정기에 `login`·`csrf`·`cors`·`logout` `Customizer`가 생겼습니다 |
| `LoggingValueSanitizer`, `LoggingContextAccessor` 빈 | 그대로 |
| 수동 배선(`auto-filter-chain: false` + 컴포넌트 직접 조립) | `auto-filter-chain: false` + 앱 체인에 `KeycloakHttpConfigurer`. 필터는 설정기가 만듭니다 |

## 7. 화면(프런트엔드)

| 할 일 | 내용 |
|---|---|
| 로그인 | `location.href = "{api}/oauth2/authorization/keycloak?return=/현재/경로"` |
| API 호출 | `credentials: "include"`. 401이면 본문의 `loginUrl`로 보냅니다 |
| 상태 바꾸는 요청 | `GET {api}/api/csrf`로 받은 `token`을 `X-XSRF-TOKEN` 헤더(또는 폼 `_csrf`)에. 403 `INVALID_CSRF_TOKEN`이면 다시 받아 한 번 더 |
| 주기적 호출 | `X-Background: 1` 헤더 (세션이 끝없이 늘지 않게) |
| 로그아웃 | `POST {api}/logout` (CSRF 토큰 포함). 응답 302를 따라갑니다 |
| 로그인 실패 | 화면 `/?login_error=코드` (`invalid_state`, `access_denied`, `invalid_token`, `login_failed`) |

## 8. 차례

1. 앱을 Spring Boot 4.1로 올립니다.
2. 의존성을 3.0.0으로 바꾸고 Redis·spring-session 의존성을 지웁니다.
3. `auth_session` 마이그레이션을 더합니다.
4. 설정을 3절 표대로 바꾸고 키(`crypto.keys`)를 비밀 저장소에 넣습니다.
5. Keycloak client를 5절 표대로 바꿉니다.
6. 화면을 7절대로 바꿉니다.
7. 배포하면 사용자는 한 번 다시 로그인합니다.
