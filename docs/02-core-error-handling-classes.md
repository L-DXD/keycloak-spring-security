# 이슈: [Core] 표준 예외 처리 클래스 설계

## 🎯 목표
라이브러리 전반에 걸쳐 일관된 오류 처리를 지원하기 위해, 커스텀 예외 처리 클래스들을 `core` 모듈에 설계 및 구현합니다.

## 📋 작업 상세 내용

### 1. 공통 예외 클래스 (`KeycloakSecurityException`) 생성
- `RuntimeException`을 상속받는 최상위 공통 예외 클래스 `KeycloakSecurityException`을 생성합니다.
- 이 클래스는 `errorCode`와 `message`를 필드로 가집니다.
- 위치: `keycloak-spring-security-core` 모듈의 `com.ids.keycloak.security.exception` 패키지.

### 2. 세부 커스텀 예외 클래스 생성
- `KeycloakSecurityException`을 상속받는 구체적인 예외 클래스들을 정의합니다.
- 예시 클래스:
  - `RefreshTokenException`
  - `AuthenticationFailedException`
  - `AuthenticationRequiredException`
  - `AuthorizationFailedException`
  - `AuthorityMappingException`
- 각 예외는 고유한 `errorCode`를 가집니다.

### 3. 에러 코드 및 HTTP 상태 코드 매핑 가이드
- 이 테이블은 라이브러리 사용자가 예외를 처리할 때 참고할 수 있는 가이드입니다.

| 오류 상황 (Error Scenario) | `errorCode` | 권장 HTTP 상태 코드 | 예외 클래스 | 기본 메시지 |
| :--- | :--- | :--- | :--- | :--- |
| 리프레시 토큰 없음 | `REFRESH_TOKEN_NOT_FOUND`| 401 Unauthorized | `RefreshTokenException` | "요청에서 리프레시 토큰을 찾을 수 없습니다." |
| 인증 실패 (자격 증명/토큰 오류) | `AUTHENTICATION_FAILED` | 401 Unauthorized | `AuthenticationFailedException` | "유효하지 않은 자격 증명 또는 토큰으로 인해 인증에 실패했습니다." |
| 인증 정보 없음 | `AUTHENTICATION_REQUIRED` | 401 Unauthorized | `AuthenticationRequiredException` | "이 리소스에 접근하려면 완전한 인증이 필요합니다." |
| 인가 실패 (권한 부족) | `ACCESS_DENIED` | 403 Forbidden | `AuthorizationFailedException`| "이 리소스에 접근할 권한이 없습니다." |
| 권한 매핑 실패 | `AUTHORITY_MAPPING_FAILED` | 500 Internal Server Error | `AuthorityMappingException` | "토큰으로부터 권한을 매핑하는 데 실패했습니다." |
| 설정/초기화 오류 | `CONFIGURATION_ERROR` | 500 Internal Server Error | `KeycloakSecurityException` | "보안 설정 중 구성 오류가 발생했습니다." |

### 4. 예외 처리 책임 (Exception Handling Responsibility)
`core` 모듈은 예외를 정의할 뿐, 실제 HTTP 응답을 생성하지 않습니다. 예외를 HTTP 응답으로 변환하는 책임은 각 웹 환경을 담당하는 모듈에 있습니다.

- **`keycloak-spring-security-servlet`**:
  - `AuthenticationEntryPoint` 구현체를 통해 인증 예외를 처리하고, `ErrorCode`에 정의된 HTTP 상태 코드와 메시지를 담은 응답을 생성합니다.
  - `AccessDeniedHandler` 구현체를 통해 인가 예외를 처리합니다.

- **`keycloak-spring-security-reactive`**:
  - `ServerAuthenticationEntryPoint` 구현체를 통해 Reactive 환경의 인증 예외를 처리합니다.
  - `ServerAccessDeniedHandler` 구현체를 통해 Reactive 환경의 인가 예외를 처리합니다.

## ✅ 인수 조건
### Core Module
- [x] `keycloak-spring-security-core` 모듈의 `com.ids.keycloak.security.exception` 패키지 내에 모든 예외 클래스가 생성되어야 한다.
- [x] 각 커스텀 예외 클래스는 `KeycloakSecurityException`을 상속해야 한다.

### Servlet Module
- [ ] `keycloak-spring-security-servlet` 모듈에 `AuthenticationEntryPoint` 구현체가 생성되어야 한다.
- [ ] `keycloak-spring-security-servlet` 모듈에 `AccessDeniedHandler` 구현체가 생성되어야 한다.

### Reactive Module
- [ ] `keycloak-spring-security-reactive` 모듈에 `ServerAuthenticationEntryPoint` 구현체가 생성되어야 한다.
- [ ] `keycloak-spring-security-reactive` 모듈에 `ServerAccessDeniedHandler` 구현체가 생성되어야 한다.
