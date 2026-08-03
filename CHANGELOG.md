# Changelog

이 프로젝트의 주요 변경 사항을 기록합니다.
형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르며, [유의적 버전](https://semver.org/lang/ko/)을 준수합니다.

분류: `Added`(추가) · `Changed`(변경) · `Deprecated`(지원 중단 예정) · `Removed`(제거) · `Fixed`(수정) · `Security`(보안)

> 권장 버전 및 지원 정책은 [SECURITY.md](SECURITY.md)를 참고하세요.

## [Unreleased]

## [2.0.3] - 2026-07-16
### Fixed
- **`keycloak.security.error.*` 프로퍼티가 전혀 적용되지 않던 버그**: `KeycloakHttpConfigurer`가 `exceptionHandling`의 EntryPoint/AccessDeniedHandler를 `configure()`에서 등록해, 그보다 뒤에 실행되는 `oauth2Login`이 심는 기본 EntryPoint에 덮어씌워지고 있었음. 그 결과 `error.redirect-enabled`, `error.authentication-failed-redirect-url`, `error.access-denied-redirect-url` 등 에러 처리 설정이 무시되고 항상 Spring Security 기본 동작이 나갔음. 등록 시점을 `init()`으로 옮겨 라이브러리 핸들러가 최종 필터 체인에 반영되도록 수정. **1.9.0 ~ 2.0.2 공통 결함**이며, 이 수정으로 `error.*` 설정이 처음으로 실제 적용된다.
- **Basic Auth 실패 시 앞단 필터가 세운 인증까지 지우던 문제**: `BasicAuthenticationFilter`가 인증 실패·스킵 경로에서 `SecurityContextHolder.clearContext()`를 무조건 호출해, 앞단 필터(OIDC 쿠키 인증 등)가 이미 세워 둔 인증까지 함께 소거됐음. 자신이 세우지 않은 기존 인증은 보존하도록 조건부 clear로 변경.
- **정적 리소스 요청마다 Introspect/UserInfo 원격 호출이 발생하던 문제**: `matcher.include` 기본값 `/**` + `anyRequest().authenticated()` 조합에서 `/css/**`, `/js/**`, `/images/**`, `/webjars/**`, `/favicon.ico` 요청도 인증 대상이 되어, 로그인 세션이 있는 사용자는 정적 파일 하나당 Keycloak 원격 호출이 1회씩 발생했음(운영 실측 지연·장애 전파 원인). `static-resources.*` 설정으로 인증 필터·인가에서 제외할 수 있게 함(기본 패턴은 Spring Boot `StaticResourceLocation` 4종과 동일).
- **Redis 세션 손상 시 HTTP 500이 나던 문제**: `session.store-type=redis` 환경에서 세션 데이터가 손상(`creationTime` 누락 등)되면 역직렬화 예외가 그대로 전파되어 해당 사용자가 500으로 막히고 스스로 복구할 수 없었음. 폴백 매퍼로 손상 세션을 감지해 미인증으로 처리하여 정상적인 재로그인이 유도되도록 수정. 손상 세션의 Redis 키 삭제는 롤링 배포 중 직렬화 불일치를 손상으로 오인해 대량 강제 로그아웃을 유발할 수 있으므로 기본 비활성화(`session.cleanup-corrupted`, 기본 `false`)이며, 키는 `session.timeout` 경과 후 Redis TTL로 자연 만료된다.
- **인증 실패 사유가 로그에 남지 않던 문제**: 인증 실패 시 어떤 검증에서 떨어졌는지 로그로 확인할 수 없어 운영 장애 분석이 불가능했음. `ErrorCode` 기반의 구조화된 감사 로그(`AuthenticationEventLogger`)로 실패 사유를 남기도록 하고, servlet에만 있던 감사 로그를 webflux에도 신설해 두 스택의 격차를 해소.
- **백채널 로그아웃이 조용히 무동작하던 문제**: Back-Channel 로그아웃은 indexed session repository(`FindByIndexNameSessionRepository` / `ReactiveFindByIndexNameSessionRepository`)가 있어야 세션을 무효화할 수 있는데, 기본 `session.store-type=memory`는 이를 구현하지 않아 servlet은 200을 반환하면서도 세션이 남고(silent no-op) webflux는 404가 났음. 기동 시점에 원인과 해결 방법을 WARN 로그로 안내하며, `session.back-channel-logout-strict=true`로 기동 자체를 실패시킬 수 있다.
- `KeycloakAuthenticationFilter`가 principal이 `null`인 인증 객체를 로깅하다 NPE를 던지던 문제.
- context-path로 배포된 애플리케이션에서 OAuth2 로그인 authorization endpoint 리다이렉트에 context-path가 빠져 404가 되던 문제(Spring Security `LoginUrlAuthenticationEntryPoint`와 동일하게 `getContextPath()`를 prefix로 부여).
- webflux에서 `oauth2Login`이 구성되지 않은 상태로 authorization endpoint 리다이렉트가 발생해 무한 302 루프가 생기던 문제(자기참조 가드 포함).
- `matcher.include`/`exclude` 매칭 시 경로를 정규화(context-path 제거, traversal 방지)하도록 수정.

### Added
- **`KeycloakLoginService`** (servlet, `com.ids.keycloak.security.authentication`) — 외부에서 이미 획득한 토큰으로 인증 세션을 세우는 **프로그래밍 방식 로그인 API**. Token Exchange, 커스텀 SSO 핸드오프, 테스트 등 OIDC 리다이렉트 흐름 밖에서 로그인을 성립시켜야 할 때 사용한다. 토큰 검증은 `KeycloakAuthenticationProvider#createAuthenticatedToken` 단일 진입점을 반드시 경유하므로 검증 우회가 없고, 성공 시 세션 고정 방지(다른 사용자로 재로그인이면 세션 신규 생성, 동일 사용자면 세션 ID 회전) → `SecurityContext` 저장 → 토큰 쿠키 발급 → Refresh Token/Principal Name/Keycloak Session ID 세션 저장까지 OIDC 로그인 성공과 동등한 결과를 만든다. 토큰 묶음 값 객체 `KeycloakTokens`(`of(idToken, accessToken)` / `of(idToken, accessToken, refreshToken)`)를 함께 추가. 사용법은 [docs/GUIDE.md](docs/GUIDE.md) 4.11 참고.
- `keycloak.security.authentication.security-context-repository` — 인증 `SecurityContext`를 어디에 영속화할지 선택(`NULL` 기본값/`HTTP_SESSION`/`DELEGATING`). 기본값 `NULL`은 기존 동작(매 요청 재검증, 세션 미저장) 유지이며, 세션을 통해 인증을 이어받아야 하면 opt-in 한다.
- `keycloak.security.static-resources.enabled`(기본 `true`) / `.filter-skip`(기본 `true`) / `.permit-all`(기본 `false`) / `.patterns`(기본 `[/css/**, /js/**, /images/**, /webjars/**, /favicon.ico]`) — 정적 리소스를 인증 필터·인가에서 제외. `filter-skip`(인증 계산 스킵, 성능)과 `permit-all`(인가 면제)은 축이 분리되어 있으며, `filter-skip`은 `permit-all=true`일 때만 실제로 적용된다(둘을 독립적으로 켜면 정적 리소스가 영구 미인증으로 고정되어 무한 리다이렉트 루프가 발생하기 때문).
- `keycloak.security.csrf.token-repository` — CSRF 토큰 저장소 선택(`SESSION` 기본값/`COOKIE`). `matcher.exclude`로 제외한 경로는 Keycloak 체인이 적용되지 않아 세션 저장소로는 토큰을 읽거나 심을 수 없으므로, 그 경로에서도 CSRF 토큰이 필요하면 `COOKIE`로 전환한다.
- `keycloak.security.session.back-channel-logout-strict`(기본 `false`) — indexed session repository 부재로 Back-Channel 로그아웃이 무동작하는 상태를 기동 실패(`IllegalStateException`)로 막을지 여부. 기본값에서는 WARN 로그만 남기고 기동한다.
- `keycloak.security.session.cleanup-corrupted`(기본 `false`) — (redis 전용) 손상 세션 감지 시 Redis 키를 실제로 삭제할지 여부. 기본값에서도 손상 세션은 미인증으로 처리되며(500 없음), 키만 TTL로 자연 만료된다.
- `keycloak.security.error.oauth2-login-redirect-enabled`(기본 `true`) / `keycloak.security.error.oauth2-login-registration-id`(기본 `keycloak`) — `redirect-enabled=false`(API 모드, 기본값)에서 브라우저 HTML 네비게이션 요청을 `/oauth2/authorization/{registrationId}`로 위임할지 여부와 그 registrationId. 순수 API 서버는 `false`로 꺼서 항상 401 JSON을 받을 수 있다.

### Changed (Breaking)
- **미인증 응답 동작 변경 — `Accept: text/html`을 명시 수용하는 요청만 302, 나머지는 401 JSON**: 위 EntryPoint 수정으로 이 라이브러리의 EntryPoint가 처음으로 실제 적용되면서, 미인증 요청의 응답을 무엇으로 줄지가 `Accept` 헤더 기준으로 결정된다. **`Accept`에 `text/html`이 명시된 요청만** `/oauth2/authorization/{registrationId}`로 302되고, `Accept` 헤더가 없거나 `*/*` 단독인 요청(curl 기본 요청, 서버간 호출, 일부 모바일 클라이언트)은 **401 JSON**을 받는다(`*/*` 순수 와일드카드는 브라우저 네비게이션의 신뢰 가능한 신호가 아니므로 제외, `text/*`는 포함). 2.0.2까지는 이런 요청도 대부분 302를 받았으므로, 미인증 시 302를 기대하고 리다이렉트를 따라가도록 구현된 API 클라이언트는 동작이 바뀐다. **조치**: 브라우저 흐름은 그대로 두고, 302가 필요한 클라이언트는 `Accept: text/html`을 명시하거나 401을 처리하도록 변경한다. 순수 API 서버라면 `keycloak.security.error.oauth2-login-redirect-enabled=false`로 항상 401 JSON을 받도록 고정할 수 있다.
- **정적 리소스 `permit-all` 기본값 `false`**: `static-resources.permit-all`은 명시적 opt-in만 허용한다. `/images/**` 등에 컨트롤러로 보호 리소스를 서빙하는 애플리케이션이 업그레이드만으로 그 경로를 공개해버리는 인가 확대를 막기 위한 기본값이다. **조치**: 해당 패턴에 순수 정적 파일(CSS/JS/이미지 등)만 있고 컨트롤러로 매핑된 보호 리소스가 없다는 것을 확인한 뒤 `keycloak.security.static-resources.permit-all=true`로 켠다(정적 파일만 서빙하는 일반적인 풀스택 앱은 켜야 로그인 없이 자산이 로드된다). 켜지 않아도 정적 리소스는 필터가 OIDC 쿠키로 정상 재검증하므로 로그인 사용자에게는 문제가 없다.
- `OidcLoginSuccessHandler` 생성자에 `SecurityContextRepository` 파라미터가 추가됨(4-arg). 기존 3-arg 생성자는 `NullSecurityContextRepository`를 사용하는 하위 호환 생성자로 유지되므로, Starter 자동 구성만 사용하거나 3-arg로 직접 인스턴스화하던 코드는 컴파일이 깨지지 않는다. `security-context-repository`를 `NULL` 외의 값으로 opt-in 하려면 4-arg 생성자를 써야 한다.
- `KeycloakAuthenticationFilter`가 기존 인증이 `KeycloakPrincipal`이면 매 요청 재검증한다. 앞단 필터가 세운 **다른 타입의** 인증은 그대로 보존되므로(위 Basic Auth 조건부 clear와 동일한 원칙), 커스텀 필터로 인증을 세우고 Keycloak 필터를 통과시키던 구성은 오히려 정상화된다. 반대로 stale OIDC 컨텍스트가 세션에 남아 재검증이 영구히 스킵되던 동작에는 의존할 수 없다.

## [2.0.2] - 2026-07-15
### Fixed
- **Redis 세션 사용 시 인증 요청이 500으로 실패하던 회귀 수정**: `session.store-type=redis` + `GenericJackson2JsonRedisSerializer`(Jackson 세션 직렬화) 조합에서 세션에 저장된 `SecurityContext`(OIDC 인증 정보)를 역직렬화할 때마다 예외가 발생해 이후 모든 요청이 인증 실패로 처리되던 문제. 원인 2가지를 함께 수정.
  - 세션 전용 Jackson mixin(`KeycloakPrincipalMixin`/`KeycloakAuthenticationMixin`)이 getter 기반 introspection이라, `OidcUser`가 상속하는 setter 없는 파생 getter(`getAudience()` 등, `aud`는 OIDC 필수 클레임)까지 프로퍼티로 잡혀 `InvalidDefinitionException`(`no way to handle typed deser with setterless yet`)이 발생 → 필드 기반 introspection(`@JsonAutoDetect(fieldVisibility = ANY, getterVisibility = NONE)`)으로 전환(Spring 공식 `DefaultOidcUserMixin`과 동일 패턴).
  - claims 역직렬화 시 `java.time.Instant`(`iat`/`exp`/`nbf`) 타입이 알려진 타입 목록에 없어 예외 없이 2-원소 `List`로 조용히 손상되던 것을 복원하도록 수정.
  - 영향 범위: 2.0.0/2.0.1에서 `session.store-type=redis`를 사용하는 환경 전체(모든 인증 요청에서 재현). 세션 저장소가 `memory`(기본값)이거나 Redis를 JDK 직렬화로 쓰는 경우는 영향 없음.
  - 대응: 세션 직렬화 포맷·설정 변경 없이 라이브러리 업그레이드만으로 해결(앱 코드 변경 불필요). breaking change 없음.

## [2.0.1] - 2026-07-15
### Security
- **OIDC Access Token·ID Token subject 직접 비교 (외부 검토 High #1)**: 쿠키 기반 OIDC 인증에서 Access Token이 구조적으로 JWT이면 `TokenBindingValidator#validateAccessTokenSubject`로 Access Token의 `sub`를 ID Token `sub`와 직접 비교하도록 강화(servlet `KeycloakAuthenticationProvider`, webflux `KeycloakReactiveAuthenticationManager` 동일 적용). 기존에는 Access Token과 ID Token의 결합 여부를 UserInfo 엔드포인트 조회가 성공한 경우에만 확인했는데, UserInfo 조회가 실패하거나(장애) `require-user-info`가 기본값(`false`)이면 서로 다른 사용자의 Access Token과 ID Token이 조합되어도 인증이 성립할 수 있었음. **잔여 한계**: Opaque(불투명) Access Token은 로컬에서 `sub`를 파싱할 수 없어 이 직접 비교가 적용되지 않으며 여전히 UserInfo 일치 검증에만 의존함 — Opaque Access Token을 쓰는 환경은 `keycloak.security.authentication.require-user-info=true`로 UserInfo 검증을 필수화할 것을 권장.
- **WebFlux CSRF 매처의 안전 메서드 예외 누락 수정 (외부 검토 Medium #3)**: `KeycloakWebFluxSecurityConfigurer#configureCsrf()`의 CSRF 보호 대상 매처가 면제 경로 부정(NOT)만으로 구성되어 있어, CSRF 활성화 시 GET/HEAD/OPTIONS/TRACE 등 안전 메서드 요청(조회, OIDC 콜백 등)까지 CSRF 토큰을 요구해 `403`을 반환하던 문제. Spring 표준 안전-메서드 제외 매처(`CsrfWebFilter.DEFAULT_CSRF_MATCHER`)와 면제 경로 부정 매처를 AND로 결합해 servlet(`CsrfConfigurer`)과 동일한 방식으로 정렬.
- **브라우저 Front-Channel `/logout`의 강제 로그아웃 CSRF 우회 수정 (외부 검토 Medium #4, CWE-352)**: `bearer-token.enabled=true`일 때 CSRF 면제 경로 목록에 브라우저용 Front-Channel 로그아웃 경로(`/logout`)까지 함께 추가되던 로직을 제거(servlet `KeycloakHttpConfigurer`, webflux `KeycloakWebFluxSecurityConfigurer` 동일). Bearer 활성 여부와 무관하게 브라우저 폼 기반 `/logout`은 항상 CSRF 보호되며, Bearer 전용 로그아웃(`{prefix}/logout`)만 계속 면제됨.
- **(외부 검토 Low #1~#4 묶음)**: Bearer Token 엔드포인트 `token-endpoint.prefix`가 공백이거나 `"/"` 자체이면 기동을 실패시키는 검증을 추가(prefix가 비정상이면 Bearer 전용 로그아웃 경로가 브라우저 Front-Channel `/logout`과 사실상 동일해져 위 Medium #4가 재현될 수 있는 설정을 fail-fast로 차단); webflux `KeycloakReactiveAuthenticationManager`의 토큰 결합 검증 순서를 servlet `KeycloakAuthenticationProvider`와 동일하게 정렬(검증 결과는 동일, 두 스택 간 일관성 목적); `KeycloakAuthenticationFilter`에서 `TokenBindingException`을 포괄 `catch(Exception)`보다 먼저 전용 처리해 전체 스택트레이스 대신 warn 로그 한 줄만 남기도록 정리; `TokenBindingValidator`의 결합 검증 실패 예외 메시지에 그대로 노출되던 subject(UUID)를 기존 `LogMaskingUtil`로 마스킹.
### Changed (Breaking)
- Servlet OIDC 인증용 `JwtDecoder` 빈(`keycloakJwtDecoder` → `keycloakOidcJwtDecoder`)의 대체 조건(`@ConditionalOnMissingBean`)이 타입(`JwtDecoder.class`) 기반에서 빈 이름(`keycloakOidcJwtDecoder`) 기반으로 변경됨(webflux `keycloakOidcReactiveJwtDecoder`와 동일 패턴으로 정렬). 애플리케이션이 다른 issuer/resource-server용 `JwtDecoder` 빈을 이미 등록한 경우, 과거에는 이 전용 decoder가 생성되지 않거나(조용히 대체) 두 빈이 동시에 존재해 `NoUniqueBeanDefinitionException`으로 기동이 실패할 수 있었음. 이 decoder를 커스텀 재정의(override)하던 경우 빈 이름을 `keycloakOidcJwtDecoder`로 맞춰야 하며, 별도 resource-server용 JWT decoder가 필요하면 다른 이름을 쓰거나 소비 지점에서 `@Qualifier`로 명시 구분할 것.

## [2.0.0] - 2026-07-14
### Security
- **OIDC ID/Access Token 사용자·클라이언트 결합 검증 강화 (Advisory 1)**: 쿠키 기반 OIDC 인증에서 ID Token subject를 서명 검증 없이 파싱해 Principal로 신뢰하던 로직을 제거. `JwtDecoder`(servlet) / `ReactiveJwtDecoder`(webflux)로 서명·iss·exp·nbf를 검증한 뒤에만 subject를 사용하도록 변경하고, ID Token의 `aud`/`azp`가 애플리케이션 client-id와 일치하는지, ID Token subject와 UserInfo subject가 일치하는지 추가 검증(`TokenBindingValidator`)해 서로 다른 사용자·클라이언트의 토큰이 조합되어 인증되는 것을 차단(Access Token이 JWT 형식이면 `azp`도 함께 검증, Opaque Access Token은 UserInfo 일치 검증까지 — 회귀 없음). 함께, OIDC issuer(`iss`) 해석 우선순위를 명시 프로퍼티 → 표준 Spring Boot `issuer-uri` → `base-url` 파생 순으로 정리해, `base-url`이 서버간 통신용 내부 주소라 브라우저가 보는 실제 issuer와 다른 환경에서 로그인이 전면 실패하는 문제를 예방.
- **OIDC 로그인 세션 고정(Session Fixation) 방지 (Advisory 2)**: 로그인 성공 시 세션 전략을 `sessionFixation.none()`에서 명시적 `changeSessionId()`로 변경(servlet/webflux 동일 적용). 인증 전 발급된 세션 ID가 로그인 성공 후에도 그대로 유지되어, 공격자가 피해자에게 심어둔 세션 ID로 인증을 완료시키는 세션 고정 공격을 차단.
- **Rate Limit 클라이언트 IP 판정 일원화 및 강화 (Advisory 2)**: `RateLimitFilter`/`ReactiveRateLimitFilter`와 Basic Auth 인증 이벤트 로깅의 클라이언트 IP 판정을 `ClientIpResolver` 하나로 통일해, 신뢰 프록시 수(`trusted-proxy-count`)를 넘어서는 `X-Forwarded-For` 스푸핑으로 rate limit 카운터를 매번 다른 키로 우회하던 경로를 제거. 토큰 발급 엔드포인트(`/auth/token`)가 `invalid_grant`로 반환하는 HTTP 400도 실패 횟수에 집계해 브루트포스 시도가 rate limit을 완전히 우회하던 문제를 수정. 카디널리티 공격에 의한 메모리 무한 증가를 막기 위해 인메모리 카운터 맵에 추적 키 상한(`max-tracked-keys`)을 추가(상한 도달 시 신규 키는 fail-closed로 즉시 차단).
- **Basic Auth 전면 CSRF 면제 제거 (Advisory 3, CWE-352)**: `Authorization: Basic` 헤더 보유만으로 모든 경로의 CSRF 검증을 면제하던 로직을 제거. 브라우저가 캐시한 Basic 자격증명이 cross-origin 폼 제출에 자동 재전송되어 CSRF 검증을 우회할 수 있었음(servlet `KeycloakHttpConfigurer`, reactive `KeycloakWebFluxSecurityConfigurer` 동일 수정). Basic Auth를 사용하는 머신 전용 API에서 CSRF 면제가 필요하면 `keycloak.security.csrf.ignore-paths`에 해당 경로를 명시적으로 등록해야 함(전면 면제 → 명시 allowlist로 전환).
- **백채널 로그아웃 로그 마스킹 (Advisory 5)**: `logout_token` 원문을 debug 로그에 그대로 남기던 것을 제거하고, `sub`/`sid` 등 식별자는 모든 로그 레벨에서 마스킹(공용 `LogMaskingUtil`, 4자 이하 짧은 값이 마스킹 없이 그대로 노출되던 결함도 함께 수정). 백채널 로그아웃 처리 중 발생한 예외 상세는 HTTP 응답 본문에 노출하지 않고 고정 에러 메시지로 응답하도록 변경(상세는 로그로만 확인).
- **인메모리 세션 저장소 용량 상한 및 정리 (Advisory 6, CWE-400/CWE-770)**: `session.store-type: memory` 저장소가 동시에 보유할 수 있는 최대 세션 수(`max-sessions`, 기본 10,000)를 두어, 상한 도달 시 신규 세션 생성을 fail-closed 처리. 전용 데몬 스레드에서 별도 스케줄(`cleanup-interval`, 기본 5분)로 만료 세션을 주기적으로 회수해, 세션 쿠키를 보관하지 않고 OIDC 로그인을 반복 개시하는 방식의 메모리 고갈(DoS)을 방지.
- **Realm/Client Role 권한 네임스페이스 분리 (Advisory 7, CWE-863)**: `realm_access.roles`와 `resource_access.{clientId}.roles`가 동일한 `ROLE_<이름>` 권한으로 병합되어, 동명의 realm 역할과 client 역할을 구분할 수 없던 문제를 수정. 기본 전략(`role-mapping.mode=SEPARATE_NAMESPACE`)에서 realm 역할은 `ROLE_REALM_<이름>`, client 역할은 `ROLE_CLIENT_<CLIENT>_<이름>`으로 네임스페이스가 분리되어, realm 역할 보유자가 client 전용 `hasRole(...)` 검사를 의도치 않게 통과하던 인가 혼동을 차단.
- **WebFlux 백채널 로그아웃 decoder 검증 강화 (Advisory 8)**: `logout_token` 전용 `ReactiveJwtDecoder`가 client-id 미설정 시 aud 검증을 건너뛰지 않고 기동 자체를 실패시키도록 변경하고, `iat`/`exp` 클레임이 아예 없는 토큰도 거부하도록 강화. 이 decoder의 대체 조건(`@ConditionalOnMissingBean`)을 타입이 아닌 **빈 이름** 기준으로 좁혀, 애플리케이션이 다른 용도(OIDC 쿠키 인증 등)의 `ReactiveJwtDecoder`를 등록해도 백채널 전용 decoder가 의도치 않게 대체되지 않도록 보장.
### Changed (Breaking)
- `basic-auth.enabled=true`이면서 기존 자동 CSRF 면제에 의존하던 상태 변경 요청(POST/PUT/PATCH/DELETE)은 CSRF 토큰 없이 호출 시 `403`을 받게 됨. 영향받는 머신 클라이언트 경로를 `csrf.ignore-paths`에 추가하거나, 해당 API를 CSRF 보호 대상에서 제외할 별도 stateless 체인으로 분리할 것.
- Realm/Client Role 매핑 기본값이 `SEPARATE_NAMESPACE`로 변경됨. 기존에 realm 역할과 client 역할을 구분 없이 `hasRole("ADMIN")` 등으로 검사하던 코드는 권한 문자열이 `ROLE_REALM_ADMIN`/`ROLE_CLIENT_<CLIENT>_ADMIN`으로 분리되어 더 이상 매치되지 않음. 과거 병합 동작이 반드시 필요하면 `keycloak.security.role-mapping.mode=LEGACY_MERGED`로 명시 전환할 것(비권장, 마이그레이션 기간 한정).
- (webflux) `KeycloakReactiveAuthenticationManager#createAuthenticatedToken`의 반환 타입이 `Authentication` → `Mono<Authentication>`으로 변경. 두 클래스 모두 생성자에 `JwtDecoder`/`ReactiveJwtDecoder` 파라미터가 추가되어(servlet `KeycloakAuthenticationProvider` 동일), `new KeycloakReactiveAuthenticationManager(client, clientId)`처럼 구 시그니처로 직접 인스턴스화하던 수동 배선(auto-filter-chain 미사용) 코드는 컴파일이 깨짐. Starter 자동 구성만 사용하는 경우 영향 없음.
- 백채널 로그아웃 전용 `ReactiveJwtDecoder` 빈의 대체 조건이 타입 기반에서 빈 이름(`keycloakBackChannelJwtDecoder`) 기반으로 변경됨. 이 빈을 직접 재정의(override)하던 경우 동일한 빈 이름을 사용해야 함.
### Changed
- webflux 인증 이벤트 로그 포맷을 servlet과 동일한 `AuthenticationEventLogger` 구현으로 통합하면서 로그 태그가 `[AuthEvent]` → `[AUTH]`, 필드명이 `clientIp=` → `ip=`로 통일됨(servlet 쪽 canonical 포맷에 맞춤). 테스트로 고정된 동작은 아니었으나, webflux 로그를 파싱하는 외부 로그 수집기·대시보드가 있다면 패턴 갱신 필요.
### Added
- `keycloak.security.authentication.issuer-uri` — OIDC ID/Access Token 서명 검증에 사용할 issuer 명시 지정(기본값 없음, 미설정 시 표준 프로퍼티 → `base-url` 파생 순으로 자동 해석)
- `keycloak.security.rate-limit.max-tracked-keys` — 인메모리 rate limiter가 동시에 추적할 최대 키(IP/username) 수(기본값 100,000)
- `keycloak.security.session.max-sessions` — 인메모리 세션 저장소가 동시에 보유할 최대 세션 수(기본값 10,000)
- `keycloak.security.session.cleanup-interval` — 인메모리 세션 만료 정리 스케줄 주기(기본값 5분)
- `keycloak.security.role-mapping.mode`(`REALM_ONLY`/`CLIENT_ONLY`/`SEPARATE_NAMESPACE`/`LEGACY_MERGED`, 기본값 `SEPARATE_NAMESPACE`), `keycloak.security.role-mapping.realm-role-prefix`(기본 `ROLE_REALM_`), `keycloak.security.role-mapping.client-role-prefix`(기본 `ROLE_CLIENT_`)

## [1.10.2] - 2026-06-24
### Fixed
- **webflux**: 토큰 무효화(백채널 로그아웃 등) 후 보호 경로 접근 시 refresh 재발급 실패가 `500`을 반환하던 문제. 이제 미인증으로 처리되어 `ExceptionTranslationWebFilter` → EntryPoint(로그인 리다이렉트 302/401)를 경유합니다. servlet과 동작 일관화. ([#54](https://github.com/L-DXD/keycloak-spring-security/issues/54))

## [1.10.1] - 2026-06-23
### Fixed
- `isAjaxRequest`가 브라우저 `Accept: */*`를 JSON으로 오판하여, `error.ajax-returns-json=true` 시 미인증 브라우저가 로그인 리다이렉트 대신 `401`을 받던 문제. webflux/servlet 판정을 "명시적 JSON & HTML 비수용" 규칙으로 통일. ([#52](https://github.com/L-DXD/keycloak-spring-security/issues/52))

## [1.10.0] - 2026-06-10
### Security
- **reactive 백채널 로그아웃**: `logout_token`을 JWKS로 **서명·iss·aud 검증**한 뒤에만 세션을 무효화 (위조 토큰 거부, fail-close). 이전에는 서명 미검증으로 임의 세션 강제 종료가 가능 (CVSS 8.2)
- Redis 세션 직렬화를 JDK → JSON(Gadget 역직렬화 차단), PII 마스킹에 JWT·OAuth2 파라미터 패턴 추가, `RestTemplate` 타임아웃, X-Forwarded-For 신뢰 프록시 등 보안 전수 검토 13건 반영
### Changed (Breaking)
- 쿠키 `secure` 기본값 `false` → `true` (HTTP 개발환경은 `keycloak.security.cookie.secure=false`로 해제)
- `X-Forwarded-For` 신뢰: `keycloak.security.trusted-proxy-count` 기본 `0`(=remoteAddr, XFF 무시). 프록시 환경은 `=N`, 레거시 동작은 `=-1`
- `/logout` CSRF 면제는 `bearer-token.enabled=true`일 때만
- servlet 토큰 응답에 `Cache-Control: no-store` 적용, SameSite 실제 적용
### Added
- 인가 결정 캐시 `keycloak.security.authorization.cache.*`(기본 off)
- `keycloak.security.authentication.require-user-info`(기본 off) — UserInfo 조회 실패를 인증 실패로 승격

## [1.9.0] - 2026-06-09
### Added
- OIDC authorize 요청 파라미터 커스터마이즈 — `keycloak.security.authentication.authorization-request.{acr-values, max-age, prompt}`. LoA step-up / `max_age` 재인증 / `prompt` 지원. 경로별 step-up은 `OAuth2AuthorizationRequestResolver` 빈 재정의로 가능

## [1.8.0] - 2026-06-09
### Added
- **Reactive(WebFlux) 스택 전체** — servlet과 기능 동등: OIDC 로그인·세션·인가(Authorization Services)·Bearer·Basic·Rate Limiting·CSRF·Front/Back-Channel 로그아웃·MDC 로깅. `keycloak-spring-security-webflux-starter` 신규

## [1.7.0] - 2026-06-08
### Added
- MDC 응답 메트릭(`status`/`durationMs`, `logging.include-response-metrics`, 기본 off)
- MDC 필터 제외 경로 `logging.exclude-patterns`(기본 `[/actuator/**]`)

## [1.6.0] - 2026-06-08
### Added
- MDC `userAgent`, `queryString` 정제(디코딩+길이제한+마스킹), 응답 `X-Request-Id` 회신
- PII 마스킹 SPI `LoggingValueSanitizer` + 기본 구현 `DefaultPiiMaskingSanitizer`
### Changed
- PII 마스킹 **기본 on** (이메일/휴대폰/주민번호/카드/Bearer). 해제는 `NoOpLoggingValueSanitizer` 빈 등록
### Fixed
- `WebMdcContextAccessor.clear()`가 `MDC.clear()`로 외부 키까지 비우던 누수 → 라이브러리가 put한 키만 제거

## [1.5.0] - 2026-06-08
### Security
- **SecurityFilterChain Fail-Open 수정** (CVSS 8.1) — 사용자가 자체 `SecurityFilterChain`(예: actuator)을 추가하면 Keycloak 필터 체인이 통째로 비활성화되어 인증이 사라지던 문제. Bean 이름 기반 조건 + `securityMatcher` + `@Order(LOWEST_PRECEDENCE)`로 공존
### Changed (Breaking)
- 위 수정으로 자체 체인 사용 시 Keycloak 체인이 함께 활성화됨 → `keycloak.security.matcher.exclude` 또는 `auto-filter-chain: false`로 조정
### Added
- `keycloak.security.matcher.{include,exclude}`, `auto-filter-chain`

## [1.4.1] - 2026-04-22
### Fixed
- stateless 인증 경로에서 HttpSession 전제 제거 (#35)

## [1.4.0] - 2026-04-08
### Added
- Bearer Token / Basic Auth 인가 지원 — `KeycloakAuthorizationManager`가 다중 인증 타입 처리

## [1.3.0] - 2026-04-06
### Added
- CSRF 설정 기능 (`keycloak.security.csrf.*`)

## [1.2.0] - 2026-03-27
### Added
- Rate Limiting 토큰 발급 보호 + 인증 이벤트 로깅
- Bearer Token 인증(Resource Server + 토큰 발급 API)

## [1.1.0] - 2026-03-25
### Added
- Basic Auth 병렬 지원(Direct Access Grants)

## [1.0.4] - 2026-03-17
### Added
- `@EnableMethodSecurity` 적용, 초기 OIDC 로그인/세션/로그아웃/Redis 세션 등 기반 기능

[Unreleased]: https://github.com/L-DXD/keycloak-spring-security/compare/v2.0.3...HEAD
[2.0.3]: https://github.com/L-DXD/keycloak-spring-security/compare/v2.0.2...v2.0.3
[2.0.2]: https://github.com/L-DXD/keycloak-spring-security/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/L-DXD/keycloak-spring-security/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/L-DXD/keycloak-spring-security/compare/v1.10.2...v2.0.0
[1.10.2]: https://github.com/L-DXD/keycloak-spring-security/compare/v1.10.1...v1.10.2
[1.10.1]: https://github.com/L-DXD/keycloak-spring-security/compare/v1.10.0...v1.10.1
[1.10.0]: https://github.com/L-DXD/keycloak-spring-security/compare/v1.9.0...v1.10.0
[1.9.0]: https://github.com/L-DXD/keycloak-spring-security/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/L-DXD/keycloak-spring-security/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/L-DXD/keycloak-spring-security/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/L-DXD/keycloak-spring-security/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/L-DXD/keycloak-spring-security/compare/v1.4.1...v1.5.0
[1.4.1]: https://github.com/L-DXD/keycloak-spring-security/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/L-DXD/keycloak-spring-security/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/L-DXD/keycloak-spring-security/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/L-DXD/keycloak-spring-security/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/L-DXD/keycloak-spring-security/compare/v1.0.4...v1.1.0
[1.0.4]: https://github.com/L-DXD/keycloak-spring-security/releases/tag/v1.0.4
