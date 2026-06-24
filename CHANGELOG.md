# Changelog

이 프로젝트의 주요 변경 사항을 기록합니다.
형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르며, [유의적 버전](https://semver.org/lang/ko/)을 준수합니다.

분류: `Added`(추가) · `Changed`(변경) · `Deprecated`(지원 중단 예정) · `Removed`(제거) · `Fixed`(수정) · `Security`(보안)

> 권장 버전 및 지원 정책은 [SECURITY.md](SECURITY.md)를 참고하세요.

## [Unreleased]

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
