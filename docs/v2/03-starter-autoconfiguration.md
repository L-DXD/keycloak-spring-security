# 이슈: [Starter] 환경 자동 감지 및 AutoConfiguration 구현

## 🎯 목표
사용자가 `keycloak-spring-security-web-starter` (Servlet) 또는 `keycloak-spring-security-webflux-starter` (Reactive) 의존성을 추가하면, 해당 환경에 맞는 Keycloak 보안 설정을 자동으로 활성화합니다. 이를 통해 복잡한 보안 설정 없이 의존성 추가만으로 안전한 애플리케이션을 구성할 수 있는 'Zero-Configuration' 경험을 제공합니다.

## 📋 구현 상세 내용

### 1. 모듈 구조 분리
기존 단일 스타터 계획에서 실행 환경(Servlet vs Reactive)에 따른 명확한 의존성 관리와 설정 분리를 위해 두 개의 스타터 모듈로 분리하였습니다.
- **`keycloak-spring-security-web-starter`**: Spring MVC (Servlet) 기반 애플리케이션용
- **`keycloak-spring-security-webflux-starter`**: Spring WebFlux (Reactive) 기반 애플리케이션용 (현재 구조 마련 단계)

### 2. Servlet 환경 자동 설정 (`KeycloakServletAutoConfiguration`)
`keycloak-spring-security-web-starter` 모듈의 핵심 설정 클래스입니다. `src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`에 등록되어 Spring Boot에 의해 로드됩니다.

#### 2.1 활성화 조건
- `@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)`: Servlet 웹 애플리케이션에서만 동작합니다.
- `@AutoConfiguration`: Spring Boot의 자동 설정 메커니즘을 따릅니다.
- `@EnableConfigurationProperties`: `KeycloakSecurityProperties`, `CookieProperties` 등을 활성화합니다.

#### 2.2 구성요소 (Nested Configuration)
설정의 복잡도를 낮추고 역할별로 Bean을 관리하기 위해 내부 정적 클래스로 구성을 분리하였습니다.

1.  **`SessionConfiguration`**
    -   `KeycloakSessionManager`: 세션 관리 핵심 컴포넌트
    -   `IndexedMapSessionRepository`: 백채널 로그아웃 지원을 위한 Principal Name 인덱싱 기능이 포함된 인-메모리 세션 저장소 (`@ConditionalOnMissingBean`으로 사용자 정의 가능)

2.  **`KeycloakInfrastructureConfiguration`**
    -   `ObjectMapper`, `RestTemplate`: Keycloak API 통신 및 데이터 처리를 위한 유틸리티
    -   `KeycloakClient`: Keycloak Admin REST API 클라이언트 (설정 파일의 프로퍼티로 초기화)

3.  **`KeycloakAuthenticationConfiguration`**
    -   `AuthenticationManager`: `KeycloakAuthenticationProvider`를 사용하는 인증 매니저 구성

4.  **`KeycloakWebSecurityConfiguration`**
    -   **보안 핸들러**: `KeycloakAuthenticationEntryPoint`, `KeycloakAccessDeniedHandler`, `OidcLoginSuccessHandler`, `KeycloakLogoutHandler` 등을 등록합니다.
    -   **`SecurityFilterChain`**: 가장 중요한 보안 체인 설정입니다.
        -   `KeycloakHttpConfigurer`를 사용하여 핵심 보안 로직(필터, 프로바이더, OIDC, CSRF 등)을 적용합니다.
        -   `KeycloakSecurityProperties`의 `permitAllPaths` 설정을 통해 인증 제외 경로를 구성합니다.
        -   `@ConditionalOnMissingBean(SecurityFilterChain.class)`이 적용되어 있어, 사용자가 직접 `SecurityFilterChain`을 빈으로 등록하면 이 기본 설정은 물러납니다.

### 3. KeycloakHttpConfigurer (`keycloak-spring-security-web`)
복잡한 `HttpSecurity` 설정을 캡슐화한 `AbstractHttpConfigurer` 구현체입니다. 자동 설정뿐만 아니라, 사용자가 커스텀 보안 체인을 구성할 때도 다음과 같이 쉽게 Keycloak 보안을 적용할 수 있게 돕습니다.

```java
http.with(KeycloakHttpConfigurer.keycloak(), Customizer.withDefaults());
```

주요 역할:
-   **필터 등록**: `KeycloakAuthenticationFilter`를 `UsernamePasswordAuthenticationFilter` 앞에 배치
-   **인증 프로바이더**: `KeycloakAuthenticationProvider` 등록
-   **OIDC 로그인**: `oauth2Login()` 설정 및 성공 핸들러 연동
-   **로그아웃**: Front-Channel 및 Back-Channel 로그아웃 핸들러 설정
-   **예외 처리**: 인증 진입점 및 접근 거부 처리기 설정
-   **CSRF**: 로그아웃 엔드포인트에 대한 CSRF 면제 처리

### 4. 배너 자동 설정 (`KeycloakBannerAutoConfiguration`)
애플리케이션 시작 시 라이브러리 로고, 버전, 현재 활성화된 웹 스택(Servlet/Reactive) 정보를 콘솔에 출력하여 라이브러리 동작 여부를 시각적으로 확인시켜줍니다.

## ✅ 인수 조건 및 검증 결과

### 1. Zero-Configuration 동작 확인
- [x] 스타터 의존성 추가만으로 인증/인가, 로그인/로그아웃, 세션 관리 기능이 동작해야 한다.
    - **결과**: `integration-tests/servlet-app`에서 별도의 Security Config 없이 프로퍼티 설정만으로 Keycloak 연동이 정상 동작함을 확인.

### 2. 사용자 정의 유연성 (@ConditionalOnMissingBean)
- [x] 사용자가 직접 `SecurityFilterChain` Bean을 등록하면, 스타터의 기본 체인은 생성되지 않아야 한다.
- [x] 사용자가 특정 핸들러(예: `AuthenticationEntryPoint`)만 재정의하면, 나머지 설정은 유지된 채 해당 빈만 교체되어야 한다.
    - **결과**: 테스트를 통해 사용자가 등록한 빈이 우선순위를 가지며, 자동 설정 로그가 출력되지 않거나(전체 대체) 필요한 부분만 교체됨을 확인.

### 3. 커스텀 구성 지원
- [x] 사용자가 복잡한 보안 요구사항(예: 다중 필터 체인)을 가질 경우, `KeycloakHttpConfigurer`를 활용하여 쉽게 통합할 수 있어야 한다.


