# 이슈: [Core] 토큰 기반 Principal 변환 및 인증 흐름 재정의

## 🎯 목표
Keycloak 기반의 OIDC 인증 환경에서, Access Token (JWT)과 ID Token을 브라우저 쿠키를 통해 관리하고, 이 토큰들로부터 Spring Security의 `Principal` 객체를 생성하는 매퍼 및 커스텀 인증 흐름을 구현합니다.

## 📋 작업 상세 내용

### 1. Spring Security의 Principal 및 토큰 관리 전략

#### 1.1. Principal 구성 요소
Spring Security `Principal`은 인증된 사용자의 정보를 담으며, 다음 요소들을 포함합니다:
- **사용자 식별 (Username):** 사용자를 고유하게 식별합니다 (예: `preferred_username` 클레임).
- **권한 정보 (Granted Authorities):** 사용자가 가진 역할 및 권한 목록입니다 (예: `ROLE_USER`, `ROLE_ADMIN`).
- **추가 속성 (Attributes):** JWT 클레임 등 추가 사용자 정보를 담습니다.

#### 1.2. 토큰 저장 전략
- **Access Token (JWT):** 보호된 리소스 접근에 사용되며, **브라우저 쿠키**에 저장됩니다. 이를 통해 HTTP 요청 시 자동으로 포함되어 전송됩니다.
- **ID Token (JWT):** 사용자 인증 정보를 담으며, **브라우저 쿠키**에 저장됩니다.

### 2. 커스텀 인증 흐름 구현

기존 `oauth2ResourceServer().jwt()` 방식은 주로 `Authorization` 헤더에서 JWT를 기대하므로, 쿠키에서 JWT를 추출하기 위한 커스텀 인증 로직이 필요합니다.

#### 2.1. `authenticationManager` (Core 모듈)
`core` 모듈 내부에 커스텀 `authenticationManager`를 구현하여 전체 인증 흐름을 관리합니다. 이 매니저는 다음 로직을 포함할 수 있습니다:
- HTTP 요청에서 쿠키를 통해 Access Token (JWT)을 추출합니다.
- 추출된 JWT의 유효성을 검증합니다.
- 유효한 JWT로부터 `Authentication` 객체를 생성합니다.

#### 2.2. `JwtAuthenticationConverter` 활용
`KeycloakJwtAuthenticationConverter`는 추출된 Access Token (JWT) 클레임으로부터 `JwtAuthenticationToken` 형태의 `Authentication` 객체를 생성하는 매퍼 역할을 계속 수행합니다.
- `preferred_username` 클레임을 `JwtAuthenticationToken`의 `name`으로 설정합니다.
- `realm_access.roles` 및 `resource_access.<client_id>.roles` 클레임에서 역할 정보를 추출하여 `ROLE_` 접두사를 포함한 `GrantedAuthority` 컬렉션으로 변환합니다.

#### 2.3. 쿠키에서 JWT 추출 메커니즘
- HTTP 요청에서 Access Token (JWT) 쿠키를 파싱하여 JWT를 추출하는 전용 컴포넌트(예: 커스텀 `ServerHttpBearerAuthenticationConverter` 또는 `RequestHeaderAuthenticationFilter`에 유사한 기능 구현)가 필요합니다.

### 3. 통합 및 활용 방안

- 구현된 `authenticationManager`와 쿠키 기반 JWT 추출 로직을 Spring Security 설정(예: `HttpSecurity`)에 통합합니다.
- `starter` 모듈에서 관련 Bean들을 자동 구성 가능하게 제공하는 방안을 고려합니다.

### 4. 테스트
- 구현된 커스텀 인증 흐름 및 `JwtAuthenticationConverter`의 단위/통합 테스트를 작성합니다.
- 쿠키에서 JWT 추출, Principal 변환, 역할 매핑 등 각 단계의 올바른 동작을 검증합니다.

## ✅ 인수 조건
- [x] `core` 모듈에 구현된 `authenticationManager`가 쿠키에서 추출된 JWT를 기반으로 사용자 인증을 성공적으로 처리한다.
- [x] `KeycloakJwtAuthenticationConverter`가 추출된 JWT로부터 `preferred_username` 매핑 및 `realm_access`, `resource_access` 역할 매핑을 포함하여 `JwtAuthenticationToken`을 올바르게 생성한다.
- [x] 모든 관련 컴포넌트에 대한 단위/통합 테스트가 존재하며 모든 테스트를 통과한다.