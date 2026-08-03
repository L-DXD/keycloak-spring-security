# 보안 정책 (Security Policy)

[English](SECURITY.md) | **한국어**

## 지원 버전 (Supported Versions)

| 버전 | 지원 | 비고 |
|------|------|------|
| **2.0.3+** | **권장** | `error.*` 프로퍼티가 전혀 적용되지 않던 버그(EntryPoint/AccessDeniedHandler가 `oauth2Login`에 밀림) 수정, Basic Auth 실패 시 앞단 필터 인증까지 소거하던 문제, 정적 리소스 요청마다 Introspect/UserInfo 원격 호출, Redis 세션 손상 시 HTTP 500, 인증 실패 감사 로그 부재, 백채널 로그아웃 조용한 무동작 수정. 2.0.2 내용 전부 포함. 프로덕션 권장 |
| 2.0.2 | 업그레이드 권고 | 2.0.3 Fixed 항목 미반영 — `error.*` 설정이 조용히 무시되고(1.9.0~2.0.2 공통), 정적 리소스 요청마다 원격 호출 발생. 외부 보안 검토 4건(2.0.1분) + 보안 전수 검토 8건(2.0.0분)은 모두 포함하나 2.0.3으로 업그레이드 권고. 2.0.3에는 breaking 3건이 있으니 [CHANGELOG.md](CHANGELOG.md) 확인 |
| 2.0.1 | **사용 금지 (deprecated)** | Redis + Jackson 세션 사용 시 인증 요청마다 500 (`SecurityContext` 역직렬화 실패) — 2.0.2에서 수정. 즉시 2.0.2로 업그레이드 |
| 2.0.0 | **사용 금지 (deprecated)** | 2.0.1과 동일한 세션 역직렬화 500 회귀 + 외부 검토 4건 미반영 — 즉시 2.0.2로 업그레이드 |
| 1.10.2 | 업그레이드 권고 | Advisory 1/2/3/5/6/7/8 미반영 — OIDC 토큰 결합 검증, 세션 고정 방지, CSRF 전면 면제 제거 등 (아래 "과거 보안 수정" 참고) |
| 1.10.1 | 업그레이드 권고 | [#54](https://github.com/L-DXD/keycloak-spring-security/issues/54)(백채널 로그아웃 후 500) 미수정, Advisory 1/2/3/5/6/7/8도 미반영 |
| 1.10.0 | 업그레이드 권고 | #52 / #54 미수정, Advisory 1/2/3/5/6/7/8도 미반영 |
| 1.6.0 – 1.9.x | 업그레이드 권고 | 보안 전수 검토(1.10.0) 미반영 — reactive 백채널 JWKS 검증, 쿠키 `secure` 기본값, X-Forwarded-For 신뢰, Redis JSON 직렬화 등, Advisory 1/2/3/5/6/7/8도 미반영 |
| < 1.5.0 | 미지원 | **SecurityFilterChain Fail-Open** (CVSS 8.1) — 즉시 업그레이드 |

> 프로덕션에서는 **항상 2.0.3 이상**을 사용하세요. **2.0.0 / 2.0.1은 Redis + Jackson 세션 역직렬화 회귀(인증 요청마다 500)로 사용 금지**이며 2.0.2에서 수정됐습니다. 버전별 상세 변경은 [CHANGELOG.md](CHANGELOG.md)를 참고하세요.

## 과거 보안 수정 (Resolved Advisories)

| 버전 | 내용 | 심각도 |
|------|------|--------|
| **2.0.3** | `keycloak.security.error.*` 프로퍼티가 전혀 적용되지 않던 버그 수정(EntryPoint/AccessDeniedHandler가 `configure()`에서 등록돼 `oauth2Login`이 심는 기본 EntryPoint에 밀림 → `init()`으로 이동, 1.9.0~2.0.2 공통), Basic Auth 실패 시 앞단 필터가 세운 인증까지 지우던 문제(조건부 clear), 정적 리소스 요청마다 Introspect/UserInfo 원격 호출이 발생하던 문제, Redis 세션 손상 시 HTTP 500(미인증 처리로 정상 재로그인 유도), 인증 실패 사유가 로그에 남지 않던 문제(`ErrorCode` 기반 구조화 감사 로그, webflux 감사 로그 신설), 백채널 로그아웃이 indexed session repository 없이 조용히 무동작하던 문제(기동 경고) | Mixed (가용성 / 운영 가시성) |
| **2.0.2** | Redis + Jackson(`GenericJackson2JsonRedisSerializer`) 세션에서 `SecurityContext` 역직렬화가 실패해 인증 요청마다 500이던 회귀 수정(2.0.0/2.0.1 영향, 가용성). 원인: OIDC 토큰 claims의 setterless getter 오검출 및 값 타입(iss=URL·iat/exp=Instant·중첩 객체) 손상 → 필드 기반 mixin + 범용 언랩 + JavaTimeModule로 수정 | Medium (가용성) |
| **2.0.1** | OIDC Access Token subject를 ID Token subject와 직접 비교해 UserInfo 조회 실패 시 서로 다른 사용자 토큰 결합 차단(외부 검토 High #1, Opaque Access Token은 잔여 한계 — `require-user-info` 권장), WebFlux CSRF 매처 안전 메서드 예외 누락 수정(Medium #3), 브라우저 Front-Channel `/logout` 강제 로그아웃 CSRF 우회 차단(Medium #4, CWE-352), Bearer prefix 검증·인증 검증 순서 정렬·로그 정리·subject 마스킹(Low #1~#4) — 외부 보안 검토 4건 | Mixed |
| **2.0.0** | OIDC ID/Access Token 결합 검증 강화(Advisory 1), 로그인 세션 고정 방지(Advisory 2), Rate Limit IP 판정 일원화(Advisory 2), Basic Auth CSRF 전면 면제 제거(Advisory 3, CWE-352), 백채널 로그아웃 로그 마스킹(Advisory 5), 인메모리 세션 저장소 용량 상한(Advisory 6, CWE-400/CWE-770), Realm/Client Role 네임스페이스 분리(Advisory 7, CWE-863), WebFlux 백채널 decoder 검증 강화(Advisory 8) — 보안 전수 검토 8건 | Mixed |
| **1.10.2** | webflux 토큰 무효화 후 재발급 실패가 500 (로그인 리다이렉트 대신) — DoS성 (#54) | Medium |
| **1.10.0** | reactive 백채널 로그아웃 `logout_token` 서명 미검증 → 임의 세션 강제 종료 (CVSS 8.2) | **High** |
| **1.10.0** | 쿠키 `secure` 기본 false, X-Forwarded-For 무검증 신뢰, Redis JDK 직렬화(Gadget), 토큰 응답 캐시 등 보안 전수 검토 13건 | Mixed |
| **1.5.0** | SecurityFilterChain Fail-Open — 사용자 자체 체인 추가 시 인증 우회 (CVSS 8.1) | **High** |

## 취약점 신고 (Reporting a Vulnerability)

보안 취약점을 발견하시면 **공개 이슈로 등록하지 마시고** 아래로 비공개 신고해 주세요.

- **이메일**: **yui5227@gmail.com** (비공개 신고)
- 또는 **GitHub Security Advisory**: 본 저장소의 **Security → Advisories → Report a vulnerability** (비공개)

신고 시 다음을 포함해 주세요: 영향 받는 버전, 재현 절차, 영향 범위(인증 우회/세션/토큰 노출 등), 가능하면 PoC.

접수 후 확인·수정·릴리스 절차를 거쳐 수정 버전과 함께 advisory를 공개합니다.

## 보안 권장 설정

- `keycloak.security.cookie.secure=true` (1.10.0+ 기본) — HTTPS 환경 필수
- `keycloak.security.cookie.same-site=Lax` (또는 `Strict`)
- 리버스 프록시 뒤라면 `keycloak.security.trusted-proxy-count`를 프록시 수에 맞게 설정 (XFF 스푸핑 방지)
- Redis 세션 사용 시 라이브러리 기본 JSON 직렬화 유지(JDK 직렬화 금지)
- PII 마스킹(`DefaultPiiMaskingSanitizer`) 기본 on 유지
- 자세한 마이그레이션/설정은 [docs/GUIDE.ko.md](docs/GUIDE.ko.md) 참고
