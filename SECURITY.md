# 보안 정책 (Security Policy)

## 지원 버전 (Supported Versions)

| 버전 | 지원 | 비고 |
|------|------|------|
| **2.0.0+** | ✅ **권장** | 보안 전수 검토 8건 반영(Advisory 1/2/3/5/6/7/8). 프로덕션 권장 |
| 1.10.2 | ⚠️ 업그레이드 권고 | Advisory 1/2/3/5/6/7/8 미반영 — OIDC 토큰 결합 검증, 세션 고정 방지, CSRF 전면 면제 제거 등 (아래 "과거 보안 수정" 참고) |
| 1.10.1 | ⚠️ 업그레이드 권고 | [#54](https://github.com/L-DXD/keycloak-spring-security/issues/54)(백채널 로그아웃 후 500) 미수정, Advisory 1/2/3/5/6/7/8도 미반영 |
| 1.10.0 | ⚠️ 업그레이드 권고 | #52 / #54 미수정, Advisory 1/2/3/5/6/7/8도 미반영 |
| 1.6.0 – 1.9.x | ⚠️ 업그레이드 권고 | 보안 전수 검토(1.10.0) 미반영 — reactive 백채널 JWKS 검증, 쿠키 `secure` 기본값, X-Forwarded-For 신뢰, Redis JSON 직렬화 등, Advisory 1/2/3/5/6/7/8도 미반영 |
| < 1.5.0 | ❌ 미지원 | **SecurityFilterChain Fail-Open** (CVSS 8.1) — 즉시 업그레이드 |

> 프로덕션에서는 **항상 최신 2.0.x**를 사용하세요. 버전별 상세 변경은 [CHANGELOG.md](CHANGELOG.md)를 참고하세요.

## 과거 보안 수정 (Resolved Advisories)

| 버전 | 내용 | 심각도 |
|------|------|--------|
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
- 자세한 마이그레이션/설정은 [docs/GUIDE.md](docs/GUIDE.md) 참고
