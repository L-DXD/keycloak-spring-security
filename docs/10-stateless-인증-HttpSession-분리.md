# 10. Stateless 인증 경로 분리 — HttpSession 전제 제거 (v1.4.1, #35)

## 배경 및 문제

`KeycloakAuthenticationFilter`는 본래 **OIDC 쿠키(access_token / id_token) 기반 인증** 전용 필터입니다.
그러나 기존 구현에서는 Bearer · Basic · Credential-Login 등 **stateless 인증 경로에서도 동일하게 HTTP Session 존재를 전제**하고 있어, 매 로그인(`POST /api/keycloak/login`)마다 아래 부작용이 발생했습니다.

| 부작용 | 내용 |
|--------|------|
| ERROR 로그 폭주 | `AuthenticationFailedException: HTTP Session이 없음` 스택트레이스 100+ 라인 |
| 감사 로그 오탐 | `[AUTH] result=FAILURE method=OIDC_COOKIE reason=HTTP Session이 없음` |
| Rate-Limiter 오동작 | FAILURE 카운터 증가로 정상 로그인 차단 위험 |
| 보안 알림 피로 | 오탐으로 인한 실제 공격 탐지 저해 |

기능 자체는 200 OK로 정상 동작하나, 보안·운영 텔레메트리의 신뢰성이 훼손되는 긴급 버그.

GitHub 이슈: [#35](https://github.com/L-DXD/keycloak-spring-security/issues/35)

---

## 근본 원인

`doFilterInternal`이 **모든 요청**에 대해 세션을 조회하는 단일 경로를 사용:

```
요청 수신
  └─ getSession(false) 호출 → null
      └─ throw AuthenticationFailedException("HTTP Session이 없음")  ← NG
          └─ catch(Exception) → log.error + logFailure(OIDC_COOKIE)
```

Bearer 요청은 내부 조건문으로 early return 처리되어 있었지만, **Basic / Credential-Login 경로에는 동일 처리가 없었음**.

---

## 해결 구조

### AuthenticationMethod enum

| 값 | 판별 조건 |
|----|-----------|
| `BEARER` | `Authorization: Bearer ` 헤더 |
| `BASIC` | `Authorization: Basic ` 헤더 |
| `CREDENTIAL_LOGIN` | POST + `loginPaths` 목록에 포함된 URI |
| `OIDC_COOKIE` | `access_token` 또는 `id_token` 쿠키 존재 |
| `NONE` | 위 어느 조건에도 해당하지 않음 |

### AuthenticationMethodDetector

판별 책임을 필터에서 분리한 독립 클래스. 판별 우선순위:

```
1. Authorization: Bearer  → BEARER
2. Authorization: Basic   → BASIC
3. POST + loginPaths URI  → CREDENTIAL_LOGIN
4. OIDC 쿠키 존재         → OIDC_COOKIE
5. 그 외                  → NONE
```

body 파싱 없이 **헤더 + URI + HTTP 메서드**만 사용하므로 InputStream 소비 문제 없음.

### KeycloakAuthenticationFilter — doFilterInternal 재설계

```
요청 수신
  └─ AuthenticationMethodDetector.detect(request)
      ├─ BEARER / BASIC / CREDENTIAL_LOGIN
      │     └─ logSkipped + chain.doFilter + return   ← 세션 조회 없음
      ├─ NONE
      │     └─ chain.doFilter + return
      └─ OIDC_COOKIE
            └─ handleOidcCookieAuth(...)
                  ├─ getSession(false) == null
                  │     └─ logNoSession + 쿠키삭제 + chain.doFilter + return  ← 예외 없음
                  └─ 기존 인증 로직 수행
```

변경 전후 비교:

| 항목 | 변경 전 | 변경 후 |
|------|---------|---------|
| 세션 검사 위치 | 모든 요청 공통 | OIDC_COOKIE 분기 내부만 |
| 세션 없음 처리 | `throw AuthenticationFailedException` | `logNoSession` + pass-through |
| catch(Exception) 로그 레벨 | `log.error` | `log.warn` |
| stateless 경로 처리 | 없음 (OIDC_COOKIE 경로로 낙하) | `logSkipped` + 즉시 return |

---

## 변경된 공개 설정 (신규)

### `keycloak.security.authentication.login-paths`

Credential-Login으로 판별할 경로 목록. POST 메서드 + 이 목록에 포함된 URI이면 `CREDENTIAL_LOGIN`으로 분류하여 OIDC 필터를 우회합니다.

```yaml
keycloak:
  security:
    authentication:
      login-paths:
        - /api/keycloak/login      # 기본값 (생략 가능)
        - /api/auth/login          # 추가 경로 예시
```

**기본값**: `["/api/keycloak/login"]`

**설정 클래스**: `KeycloakAuthenticationProperties.loginPaths`
**주입 경로**: `KeycloakHttpConfigurer` → `KeycloakAuthenticationFilter` 6-arg 생성자 → `AuthenticationMethodDetector`

---

## 감사 로그 변경

### 신규 로그 이벤트

```
# stateless 경로 pass-through (INFO)
[AUTH] result=SKIPPED method=BEARER ip=10.0.0.1 username=unknown reason=stateless 인증 경로
[AUTH] result=SKIPPED method=CREDENTIAL_LOGIN ip=10.0.0.1 username=unknown reason=stateless 인증 경로

# OIDC 쿠키 경로 세션 없음 (DEBUG)
[AUTH] result=NO_SESSION method=OIDC_COOKIE ip=10.0.0.1 username=unknown reason=session_not_found
```

- `SKIPPED` / `NO_SESSION` 이벤트는 rate-limit 카운터 대상에서 제외
- 실제 인증 실패(잘못된 자격증명, 토큰 만료)만 `result=FAILURE`로 기록

---

## 변경 파일 목록

| 파일 | 변경 유형 | 내용 |
|------|-----------|------|
| `AuthenticationEventLogger.java` | 수정 | `logSkipped`, `logNoSession` 메서드 추가 |
| `AuthenticationMethod.java` | 신규 | BEARER/BASIC/CREDENTIAL_LOGIN/OIDC_COOKIE/NONE enum |
| `AuthenticationMethodDetector.java` | 신규 | 판별 로직 클래스 분리 |
| `KeycloakAuthenticationFilter.java` | 수정 | doFilterInternal 재설계, throw 제거, catch log.warn 하향 |
| `KeycloakAuthenticationProperties.java` | 수정 | `loginPaths` 필드 추가 |
| `KeycloakHttpConfigurer.java` | 수정 | 6-arg 생성자 주입 |

---

## 테스트 결과

- `keycloak-spring-security-web` 단위 테스트: 217건 통과
- `integration-tests/servlet-app` 통합 테스트: 14건 통과
- `AuthenticationMethodDetectorTest`: Bearer/Basic/CREDENTIAL_LOGIN/OIDC_COOKIE/NONE 각 분기 및 우선순위 검증
- `KeycloakAuthenticationFilterTest`: session null + OIDC_COOKIE 경로 예외 미발생 검증

---

## 후속 태스크 후보 (code-review Major 지적사항)

| 우선순위 | 내용 | 이슈 유형 |
|----------|------|-----------|
| High | catch 블록 `request.getSession()` → `getSession(false)` 방어 (신규 세션 생성 버그 위험) | 버그 |
| High | `loginPaths` 하드코딩 중복 3곳 → 상수 통일 | 코드 품질 |
| Medium | `auth.unexpected_error` 메트릭 분리 (FAILURE와 구분하여 Grafana 알림 정밀화) | 관측성 |
| Medium | `AntPathMatcher` 도입 — loginPaths 패턴 매칭 확장 (`/api/**` 형태 지원) | 기능 확장 |
| Medium | 통합 테스트 실제 HTTP 레벨(MockMvc / @SpringBootTest) 보강 | 테스트 |
| Low | Phase 5 — SecurityFilterChain stateless/OIDC 분리 (`@Order`) | 아키텍처 |

---

## 관련 문서

- 태스크: `02.Tasks/keycloak-spring-security/14-Bearer-로그인-엔드포인트-세션없음-오탐-수정.md`
- 브랜치: `bugfix/35-stateless-auth-session-decoupling`
- 베이스: `release/1.4.0`
- 릴리즈 버전: `1.4.1`
