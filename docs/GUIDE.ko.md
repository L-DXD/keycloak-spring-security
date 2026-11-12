# keycloak-spring-security 사용 가이드 (3.x)

[English](GUIDE.md) | **한국어**

Spring Boot 앱에 Keycloak 로그인을 붙이는 라이브러리입니다. 스타터 하나와 설정 몇 줄이면 브라우저 화면용 로그인·요청 인증·토큰 갱신·로그아웃이 켜집니다.

- **지원**: Java 17+, Spring Boot 4.1.x, Spring Security 7.1.x, Servlet(Spring MVC). WebFlux는 3.1.0
- **방식**: 앱이 화면 대신 토큰을 맡는 BFF. 화면은 쿠키만 들고, 액세스 토큰은 앱 안에서 검증하고, 리프레시 토큰은 앱 DB에 암호화해 둡니다
- 2.x에서 옮기는 경우: [v2 → v3 옮기기](MIGRATION-v3.ko.md). 2.x 문서: [docs/v2](v2/GUIDE.ko.md)

## 목차

1. [빠른 시작](#1-빠른-시작)
2. [동작 방식](#2-동작-방식)
3. [설정](#3-설정)
4. [기능별 안내](#4-기능별-안내)
5. [바꿔 끼우기 (확장)](#5-바꿔-끼우기-확장)
6. [문제 해결](#6-문제-해결)

---

## 1. 빠른 시작

### 1-1. 의존성

```gradle
implementation("io.github.l-dxd:keycloak-spring-security-web-starter:3.0.0")
implementation("org.springframework.boot:spring-boot-starter-webmvc")
implementation("org.springframework.boot:spring-boot-starter-jdbc")
implementation("org.springframework.boot:spring-boot-starter-flyway")   // 테이블을 만드는 도구 (다른 것도 됨)
runtimeOnly("org.flywaydb:flyway-database-postgresql")
runtimeOnly("org.postgresql:postgresql")
```

### 1-2. Keycloak client

| 항목 | 값 |
|---|---|
| Client authentication | 켬 (비공개 client, secret 사용) |
| Authentication flow | Standard flow만 |
| PKCE Method | S256 |
| Valid redirect URIs | `https://{앱 주소}/login/oauth2/code/keycloak` |
| Valid post logout redirect URIs | `{화면 주소}/` (로그아웃 뒤 화면) |
| Backchannel logout URL | `https://{앱 주소}/logout/connect/back-channel/keycloak` |
| Backchannel logout session required | 켬 |
| 액세스 토큰 `aud` | client id가 들어가게 Audience mapper |
| Client Session Idle / Max | 미사용 로그아웃 시간 / 최대 로그인 시간 |

자세한 이유는 [옮기기 문서 5절](MIGRATION-v3.ko.md#5-keycloak-client-설정)에 있습니다.

### 1-3. 세션 테이블

core jar 안 `kss/schema-postgresql.sql`을 마이그레이션 파일로 옮깁니다(예: `src/main/resources/db/migration/V2__auth_session.sql`). 테이블이 없으면 앱이 기동하지 않습니다.

### 1-4. 설정

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
      base-url: https://app.example.com          # 화면 주소. 화면과 API가 같은 주소면 그 주소
    permit-all-paths: [/api/public/**]
    crypto:
      active-key-id: k1
      keys:
        k1: ${KSS_KEY_K1}                        # openssl rand -base64 32
```

### 1-5. 확인

```bash
curl -i https://api.example.com/api/me
# 401 {"code":"AUTHENTICATION_REQUIRED","message":"...","loginUrl":"/oauth2/authorization/keycloak"}
```

브라우저로 `https://api.example.com/oauth2/authorization/keycloak?return=/` 를 열면 Keycloak 로그인 화면이 나오고, 로그인하면 화면 주소로 돌아옵니다. 그 뒤 `/api/me`는 200입니다.

```java
@GetMapping("/api/me")
Map<String, Object> me(@AuthenticationPrincipal KeycloakPrincipal user) {
    return Map.of("sub", user.subject(), "username", user.username());
}
```

---

## 2. 동작 방식

### 2-1. 쿠키

| 쿠키 | 담는 것 | 수명 |
|---|---|---|
| `__Host-{앱}_sid` | 세션 행을 찾는 난수 (DB에는 SHA-256만) | 절대 상한까지 |
| `__Host-{앱}_at` | 액세스 토큰(JWT) | 토큰 만료까지 |
| `__Host-{앱}_csrf` | sid로 서명한 CSRF 토큰 원본 | 절대 상한까지 |
| `__Host-{앱}_login` | 로그인 중 PKCE·state·돌아갈 경로 (암호화) | 5분 |

모두 Secure, HttpOnly, SameSite=Lax, Path=/ 입니다. ID 토큰은 어디에도 두지 않습니다.

### 2-2. 요청 한 번

```text
MdcRequestFilter            traceId 등 로그 값
→ CorsFilter                허용 화면 하나만
→ KeycloakOriginFilter      상태 바꾸는 요청의 Origin 확인
→ CsrfFilter                sid 서명 CSRF 토큰 확인
→ KeycloakAccessTokenFilter at 쿠키를 앱 안에서 검증 (Keycloak·DB 안 부름)
     ├ 만료·없음 → 세션 행을 잠그고 Keycloak에서 갱신 → 새 at 쿠키
     └ 그 밖의 실패 → 행·쿠키 삭제 (로컬 로그아웃)
→ MdcAuthenticationFilter   userId 등 로그 값
→ AuthorizationFilter       permit-all-paths 말고는 로그인 필요
```

### 2-3. 세션이 끝나는 때

| 사유 | 언제 | Keycloak 호출 |
|---|---|---|
| `logout` | 사용자가 `POST /logout` | 리프레시 토큰으로 Keycloak 로그아웃 |
| `backchannel_logout` | 다른 앱 로그아웃, 관리자가 세션 삭제 | Keycloak이 앱을 부름 |
| `idle` | Keycloak Client Session Idle이 지남 | 없음 |
| `absolute` | `session.absolute-timeout`이 지남 | 없음 (옵션으로 폐기) |
| `refresh_failed` | Keycloak이 갱신을 거절 (`invalid_grant`) | |
| `invalid_token` | 토큰 서명·iss·aud 등이 맞지 않음 | 없음 (옵션으로 폐기) |
| `decryption_failed` | 리프레시 토큰을 풀 수 없음 (키를 지움) | 없음 |
| `relogin` | 같은 브라우저로 다시 로그인 | 없음 |

---

## 3. 설정

모두 `keycloak.security.*` 아래입니다. 잘못된 값이 있으면 키 이름을 모두 모아 보여 주고 기동하지 않습니다. 비밀값은 오류·로그에 나오지 않습니다.

| 키 | 기본값 | 설명 |
|---|---|---|
| `enabled` | `true` | 끄면 자동 설정이 아무것도 올리지 않음 |
| `registration-id` | `keycloak` | `spring.security.oauth2.client.registration` id |
| `frontend.base-url` | (필수) | 화면 주소. https만 (http는 localhost만) |
| `frontend.logout-success-path` | `/` | 로그아웃 뒤 화면 경로 |
| `permit-all-paths` | `[]` | 로그인 없이 허용하는 경로 |
| `auto-filter-chain` | `true` | 기본 보안 체인. 앱이 모든 주소를 자기 체인으로 지킬 때만 끔 ([5-4](#5-4-보안-체인-나누기)) |
| `cookie.app-name` | client id | 쿠키 이름의 앱 이름 |
| `session.store` | `jdbc` | `jdbc` 또는 `memory`(서버 한 대짜리 개발용) |
| `session.table-name` | `auth_session` | |
| `session.absolute-timeout` | `12h` | 로그인부터 이 시간이 지나면 다시 로그인 |
| `session.refresh-reuse-window` | `10s` | 동시 갱신을 "방금 갱신함"으로 볼 시간 |
| `session.cleanup-interval` | `10m` | 끝난 행을 지우는 주기 |
| `token.clock-skew` | `30s` | 시간 검사 오차 (0~5분) |
| `token.jwks-min-refetch-interval` | `5m` | 모르는 kid면 JWKS를 다시 받는 최소 간격 (10초~1시간). 길수록 엉터리 kid가 몰려도 Keycloak을 덜 부르고, Keycloak 키를 바꾼 직후 503이 길어질 수 있음 |
| `token.required-audience` | client id | 액세스 토큰 `aud`에 있어야 하는 값 |
| `request.background-header` | `X-Background` | 이 헤더가 붙은 요청은 갱신하지 않음 |
| `csrf.endpoint` | `/api/csrf` | CSRF 토큰을 주는 주소 |
| `logout.revoke-refresh-token-on-local-logout` | `false` | `absolute`·`invalid_token`으로 끝낼 때 Keycloak 리프레시 토큰도 폐기 |
| `crypto.active-key-id` | (필수) | 새로 암호화할 때 쓰는 키 id |
| `crypto.keys.{id}` | (필수) | base64 키, 32바이트 이상 |
| `trusted-proxy-count` | `0` | 로그 clientIp용 믿을 프록시 수. 0이면 `X-Forwarded-For`를 보지 않음 |
| `logging.*` | | [4-8](#4-8-로그-mdc) |

---

## 4. 기능별 안내

### 4-1. 로그인

화면이 `{앱}/oauth2/authorization/keycloak?return=/orders/1`로 보냅니다. 로그인하면 `{frontend.base-url}/orders/1`로 돌아옵니다. `return`은 `/`로 시작하는 상대 경로만 받고, 그 밖은 `/`가 됩니다.

실패하면 `{frontend.base-url}/?login_error=코드`로 돌아옵니다.

| 코드 | 뜻 |
|---|---|
| `invalid_state` | 로그인 임시 쿠키가 없거나 5분이 지남, state가 다름 |
| `access_denied` | Keycloak 화면에서 취소 |
| `invalid_token` | 받은 토큰이 검증 규칙에 맞지 않음 |
| `login_failed` | 그 밖 |

### 4-2. 컨트롤러에서 사용자

```java
@GetMapping("/api/me")
Map<String, Object> me(@AuthenticationPrincipal KeycloakPrincipal user) {
    return Map.of(
        "sub", user.subject(),                 // Principal#getName()도 sub
        "username", user.username(),           // preferred_username
        "email", user.claimAsString("email"));
}
```

기본으로는 권한이 없습니다. 역할을 권한으로 바꾸려면 [5-2](#5-2-역할을-권한으로).

### 4-3. 오류 응답

| 상태 | `code` | 화면이 할 일 |
|---|---|---|
| 401 | `AUTHENTICATION_REQUIRED` | 본문 `loginUrl`로 보냄 |
| 403 | `ACCESS_DENIED` | 권한 없음 |
| 403 | `INVALID_CSRF_TOKEN` | `/api/csrf`를 다시 받아 한 번 더 |
| 403 | `ORIGIN_NOT_ALLOWED` | 허용되지 않은 화면 |
| 405 | `METHOD_NOT_ALLOWED` | `/logout`은 POST만 |
| 503 | `KEYCLOAK_UNAVAILABLE` | Keycloak에 닿지 못함. 세션은 그대로, 잠시 뒤 다시 |

```json
{"code":"AUTHENTICATION_REQUIRED","message":"로그인이 필요합니다.","loginUrl":"/oauth2/authorization/keycloak"}
```

### 4-4. 갱신

액세스 토큰이 만료되면 다음 요청에서 앱이 알아서 갱신합니다. 화면은 모릅니다. 같은 세션의 동시 요청은 DB 행 잠금으로 줄을 서서 Keycloak은 한 번만 부릅니다.

화면이 주기적으로 부르는 요청(알림 확인 등)에는 `X-Background: 1`을 붙입니다. 그 요청은 갱신하지 않아서 사용자가 자리를 비우면 세션이 Keycloak Client Session Idle에 맞춰 끝납니다.

### 4-5. CSRF·Origin·CORS (화면 코드)

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

| 규칙 | 내용 |
|---|---|
| CORS | `frontend.base-url` origin 하나만, 쿠키 허용. 허용 헤더 `Content-Type`·`X-XSRF-TOKEN`·`X-Background` |
| Origin 확인 | GET·HEAD·OPTIONS·TRACE 말고는 `Origin`(없으면 `Referer`)이 허용 화면이어야 함 |
| CSRF | `X-XSRF-TOKEN` 헤더 또는 폼 칸 `_csrf`. 토큰은 sid에 묶여 있어 다른 사람 쿠키를 심어도 통하지 않음 |
| 빼기 | Keycloak이 부르는 back-channel 로그아웃과 OIDC 콜백은 자동으로 빠짐. 웹훅 등은 [5-3](#5-3-설정기-customizer) |

### 4-6. 로그아웃

화면이 CSRF 토큰과 함께 `POST {앱}/logout`을 보냅니다(폼 제출이면 302를 따라감). 앱은 세션 행과 쿠키를 지우고 리프레시 토큰으로 Keycloak 로그아웃을 부릅니다.

| 결과 | 응답 |
|---|---|
| Keycloak 로그아웃 성공, 또는 세션이 없었음 | `{frontend.base-url}{logout-success-path}`로 302 |
| Keycloak이 거절하거나 닿지 않음 | Keycloak 로그아웃 화면으로 302 (사용자가 확인하면 화면으로 돌아옴) |

`GET /logout`은 405입니다.

### 4-7. back-channel 로그아웃

다른 앱에서 로그아웃하거나 관리자가 Keycloak 세션을 지우면 Keycloak이 `POST {앱}/logout/connect/back-channel/keycloak`를 부릅니다. 앱은 토큰의 `sid`로 세션 행을 지웁니다. 브라우저의 at 쿠키는 만료(Access Token Lifespan)까지 통하고, 그다음 갱신 때 401이 됩니다. 바로 끊겨야 하면 Access Token Lifespan을 짧게 둡니다.

### 4-8. 로그 (MDC)

요청마다 MDC에 넣습니다. 이름과 기본값은 v2와 같습니다.

| 키 | 설정 (`logging.`) | 기본 |
|---|---|---|
| `traceId` | `include-trace-id` | 켬. `X-Request-Id`가 영문·숫자·`. _ : -` 128자 안이면 그 값, 아니면 새 UUID. 응답 `X-Request-Id`(`return-trace-id-header`) |
| `httpMethod`, `requestUri` | `include-http-method`, `include-request-uri` | 켬 |
| `queryString` | `include-query-string`, `max-query-length` | 끔, 512 |
| `clientIp` | `include-client-ip` | 켬. `trusted-proxy-count` 기준 |
| `userAgent` | `include-user-agent`, `max-user-agent-length` | 켬, 256 |
| `userId`, `username`, `sessionId` | `include-user-id`, `include-username`, `include-session-id` | 켬. `sessionId`는 Keycloak `sid` |
| `status`, `durationMs` | `include-response-metrics` | 끔 |
| (제외 경로) | `exclude-patterns` | `[/actuator/**]` |

쿼리·User-Agent·username은 `LoggingValueSanitizer`(기본: JWT·Bearer·이메일·전화·주민번호·카드 가리기)를 거칩니다. 토큰과 쿠키 값은 어떤 로그에도 넣지 않습니다.

### 4-9. 세션 이벤트와 감사 로그

로그인(CREATED), 갱신(REFRESHED), 끝남(ENDED + [사유](#2-3-세션이-끝나는-때))을 이벤트로 냅니다. 기본으로 로거 `com.ids.keycloak.security.audit`에 남깁니다(사용자 id는 앞 8자만).

```java
@EventListener
void onSession(KeycloakSessionEvent event) {
    if (event.type() == KeycloakSessionEvent.Type.ENDED) {
        audit.save(event.keycloakUserId(), event.endReason(), event.occurredAt());
    }
}
```

`KeycloakSessionEventListener` 빈을 올리면 기본 감사 로그 대신 그 빈이 받습니다.

### 4-10. 키 바꾸기

```yaml
keycloak.security.crypto:
  active-key-id: k2          # 새로 암호화하는 키
  keys:
    k1: ${KSS_KEY_K1}        # 옛 행을 읽으려고 남김
    k2: ${KSS_KEY_K2}
```

행에 키 id가 있어서 옛 행도 읽힙니다. 옛 키로 된 행이 모두 끝난 뒤(절대 상한이 지난 뒤) `k1`을 지웁니다. 먼저 지우면 그 세션은 `decryption_failed`로 끝납니다.

---

## 5. 바꿔 끼우기 (확장)

### 5-1. 빈

자동 설정의 빈은 모두 `@ConditionalOnMissingBean`입니다. 같은 타입의 빈을 올리면 그것을 씁니다. 자주 바꾸는 것:

| 빈 | 기본 | 바꾸는 예 |
|---|---|---|
| `KeycloakPrincipalConverter` | `KeycloakPrincipal`, 권한 없음 | 역할을 권한으로, 앱 사용자 테이블 조회 |
| `KeycloakSessionStore` | JDBC(PostgreSQL·H2) | 다른 DB |
| `KeycloakSessionEventListener` | 감사 로그 | 감사 테이블 |
| `KeycloakCookieWriter` | `__Host-{앱}_*` | 쿠키 이름 규칙 |
| `KeycloakErrorResponseWriter` | JSON `code`·`message` | 앱 오류 형식 |
| `KeycloakTokenClient` | Spring OAuth2 Client, 연결 2초·읽기 5초 | 프록시, 타임아웃 |
| `TokenCipher` | AES-256-GCM | KMS |
| `LoggingValueSanitizer`, `LoggingContextAccessor` | 가리기, SLF4J MDC | 사내 로깅 표준 |
| `keycloakCorsConfigurationSource` (이름) | 화면 origin 하나 | origin·헤더 더하기 |

전체 목록은 [01 설계 4-3](v3/01-설계.md#4-3-확장-지점-커스텀-열어-두기)에 있습니다.

### 5-2. 역할을 권한으로

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

Keycloak client에서 역할이 액세스 토큰에 들어가게(Full scope 또는 역할 scope) 해야 합니다.

### 5-3. 설정기 Customizer

```java
@Bean
SecurityFilterChain keycloakSecurityFilterChain(HttpSecurity http, ClientRegistrationRepository clients,
                                               LogoutHandler appCacheEvictor) throws Exception {
    var resolver = new DefaultOAuth2AuthorizationRequestResolver(clients, "/oauth2/authorization");
    resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce()   // PKCE는 꼭 남김
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

Customizer는 라이브러리 설정 뒤에 불려서 같은 값이면 앱 것이 이깁니다. 빈 이름을 `keycloakSecurityFilterChain`으로 하면 기본 체인 대신 쓰입니다. 앱 체인에서는 `permit-all-paths` 대신 그 체인의 `authorizeHttpRequests`가 허용 경로를 정합니다.

### 5-4. 보안 체인 나누기

앱이 일부 주소만 받는 체인을 더하면 기본 체인은 그 뒤에서 나머지 주소를 지킵니다.

```java
@Bean
@Order(0)
SecurityFilterChain actuator(HttpSecurity http) throws Exception {
    return http.securityMatcher("/actuator/**")
        .authorizeHttpRequests(a -> a.requestMatchers("/actuator/health").permitAll().anyRequest().denyAll())
        .build();
}
```

| 하고 싶은 것 | 방법 |
|---|---|
| 일부 주소만 다르게 | 위처럼 `securityMatcher` + `@Order`. 기본 체인은 그대로 |
| 기본 체인을 내 체인으로 | 빈 이름 `keycloakSecurityFilterChain` ([5-3](#5-3-설정기-customizer)) |
| 모든 체인을 직접 | `keycloak.security.auto-filter-chain: false` + 내 체인에 `KeycloakHttpConfigurer` |

모든 주소를 받는 체인을 다른 이름으로 하나 더 만들면 Spring Security가 기동을 멈춥니다(두 체인 가운데 하나는 쓰이지 않아서).

---

## 6. 문제 해결

| 증상 | 원인 / 할 일 |
|---|---|
| 기동 실패 `keycloak.security.crypto.keys` | 키가 없거나 32바이트보다 짧음. `openssl rand -base64 32` |
| 기동 실패 세션 테이블 | `auth_session` 마이그레이션이 없음 ([1-3](#1-3-세션-테이블)) |
| 기동 실패 공개 client | Keycloak client의 Client authentication을 켜고 secret 설정 |
| 로그인 뒤 `?login_error=invalid_state` | 로그인에 5분 넘게 걸림, 또는 앱 주소가 https가 아니어서 `__Host-` 쿠키가 안 남음 |
| 로그인 뒤 `?login_error=invalid_token` | 액세스 토큰 `aud`에 client id가 없음(Audience mapper), 또는 `sid`가 없음(`basic` scope). 또는 Keycloak 서명 키를 막 바꿨는데 앱이 JWKS를 마지막으로 받아 본 지 `token.jwks-min-refetch-interval`이 안 됨(지나면 다시 로그인하면 됨) |
| 상태 바꾸는 요청이 403 `ORIGIN_NOT_ALLOWED` | `frontend.base-url`과 화면 origin이 다름 |
| 상태 바꾸는 요청이 403 `INVALID_CSRF_TOKEN` | `X-XSRF-TOKEN` 헤더가 없음. `credentials: "include"` 확인 |
| 갑자기 503 `KEYCLOAK_UNAVAILABLE` | 앱에서 Keycloak(JWKS·토큰 주소)에 닿지 않음. 또는 Keycloak 서명 키를 막 바꿨는데 앱이 JWKS를 마지막으로 받아 본 지 `token.jwks-min-refetch-interval`(기본 5분)이 안 됨(그 시간이 지나면 다시 받음). 어느 쪽이든 세션은 남아 있음 |
| 다른 앱 로그아웃 뒤에도 잠깐 로그인 상태 | at 쿠키 만료까지는 통함 ([4-7](#4-7-back-channel-로그아웃)) |
| back-channel 로그아웃이 안 옴 | Keycloak에서 앱 주소에 닿는지, Backchannel logout URL·session required 확인 |
| 로그에 이메일이 `a***@…` | 값 가리기(정상). 끄려면 `NoOpLoggingValueSanitizer` 빈 |
