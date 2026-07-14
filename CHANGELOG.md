# Changelog

이 프로젝트의 주요 변경 사항을 기록합니다.
형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르며, [유의적 버전](https://semver.org/lang/ko/)을 준수합니다.

분류: `Added`(추가) · `Changed`(변경) · `Deprecated`(지원 중단 예정) · `Removed`(제거) · `Fixed`(수정) · `Security`(보안)

> 권장 버전 및 지원 정책은 [SECURITY.md](SECURITY.md)를 참고하세요.

## [Unreleased]
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

[Unreleased]: https://github.com/L-DXD/keycloak-spring-security/compare/v1.10.2...HEAD
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
