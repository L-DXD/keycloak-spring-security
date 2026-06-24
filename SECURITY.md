# 보안 정책 (Security Policy)

## 지원 버전 (Supported Versions)

| 버전 | 지원 | 비고 |
|------|------|------|
| **1.10.2+** | ✅ **권장** | 최신 보안 패치 포함. 프로덕션 권장 |
| 1.10.1 | ⚠️ 업그레이드 권고 | [#54](https://github.com/L-DXD/keycloak-spring-security/issues/54)(백채널 로그아웃 후 500) 미수정 |
| 1.10.0 | ⚠️ 업그레이드 권고 | #52 / #54 미수정 |
| 1.6.0 – 1.9.x | ⚠️ 업그레이드 권고 | 보안 전수 검토(1.10.0) 미반영 — reactive 백채널 JWKS 검증, 쿠키 `secure` 기본값, X-Forwarded-For 신뢰, Redis JSON 직렬화 등 |
| < 1.5.0 | ❌ 미지원 | **SecurityFilterChain Fail-Open** (CVSS 8.1) — 즉시 업그레이드 |

> 프로덕션에서는 **항상 최신 1.10.x**를 사용하세요. 버전별 상세 변경은 [CHANGELOG.md](CHANGELOG.md)를 참고하세요.

## 과거 보안 수정 (Resolved Advisories)

| 버전 | 내용 | 심각도 |
|------|------|--------|
| **1.10.2** | webflux 토큰 무효화 후 재발급 실패가 500 (로그인 리다이렉트 대신) — DoS성 (#54) | Medium |
| **1.10.0** | reactive 백채널 로그아웃 `logout_token` 서명 미검증 → 임의 세션 강제 종료 (CVSS 8.2) | **High** |
| **1.10.0** | 쿠키 `secure` 기본 false, X-Forwarded-For 무검증 신뢰, Redis JDK 직렬화(Gadget), 토큰 응답 캐시 등 보안 전수 검토 13건 | Mixed |
| **1.5.0** | SecurityFilterChain Fail-Open — 사용자 자체 체인 추가 시 인증 우회 (CVSS 8.1) | **High** |

## 취약점 신고 (Reporting a Vulnerability)

보안 취약점을 발견하시면 **공개 이슈로 등록하지 마시고** 아래로 비공개 신고해 주세요.

- **GitHub Security Advisory**: 본 저장소의 **Security → Advisories → Report a vulnerability** (권장, 비공개)
- 또는 메인테이너에게 직접 연락

신고 시 다음을 포함해 주세요: 영향 받는 버전, 재현 절차, 영향 범위(인증 우회/세션/토큰 노출 등), 가능하면 PoC.

접수 후 확인·수정·릴리스 절차를 거쳐 수정 버전과 함께 advisory를 공개합니다.

## 보안 권장 설정

- `keycloak.security.cookie.secure=true` (1.10.0+ 기본) — HTTPS 환경 필수
- `keycloak.security.cookie.same-site=Lax` (또는 `Strict`)
- 리버스 프록시 뒤라면 `keycloak.security.trusted-proxy-count`를 프록시 수에 맞게 설정 (XFF 스푸핑 방지)
- Redis 세션 사용 시 라이브러리 기본 JSON 직렬화 유지(JDK 직렬화 금지)
- PII 마스킹(`DefaultPiiMaskingSanitizer`) 기본 on 유지
- 자세한 마이그레이션/설정은 [docs/GUIDE.md](docs/GUIDE.md) 참고
