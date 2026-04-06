# Architecture & Development Guidelines

이 문서는 **Keycloak Spring Security Open Source Library**의 아키텍처 원칙, 프로젝트 구조, 배포 전략, 그리고 설정 가이드를 정의합니다.
본 프로젝트는 **Spring Security 공식 GitHub 리포지토리의 구조**를 따르며, **Servlet(Blocking)** 과 **Reactive(Non-blocking)** 스택을 모두 지원하는 것을 목표로 합니다.

---

## 1. Artifact Naming & Deployment (배포 명명 규칙)

Maven Central 배포 시 라이브러리 식별 충돌 방지와 명확한 가독성을 위해 아래 규칙을 **엄격히 준수**합니다.
단순 명사(예: `core`, `servlet`)를 ArtifactId로 사용하는 것을 금지합니다.

### 📦 Coordinates
* **GroupId**: `com.ids.keycloak`
* **Version**: Semantic Versioning (ex: `1.0.0-SNAPSHOT`)

### 🏷️ ArtifactId Policy
모든 모듈의 ArtifactId는 **`keycloak-spring-security-`** 접두사를 포함해야 합니다.

| Module Role | Folder Name | **ArtifactId (Maven/Gradle)** | Description |
| :--- | :--- | :--- | :--- |
| **Root** | `root` | `keycloak-spring-security` | BOM 및 공통 빌드 설정 관리 |
| **Core** | `*-core` | **`keycloak-spring-security-core`** | 외부 프레임워크 의존성 없는 순수 로직 (POJO) |
| **Servlet** | `*-servlet` | **`keycloak-spring-security-servlet`** | Spring MVC (Tomcat) 기반 구현체 |
| **Reactive** | `*-reactive` | **`keycloak-spring-security-reactive`** | Spring WebFlux (Netty) 기반 구현체 |
| **Servlet Starter** | `*-servlet-starter` | **`keycloak-spring-security-servlet-starter`** | Servlet (Spring MVC) 환경용 스타터 |
| **Reactive Starter**| `*-reactive-starter`| **`keycloak-spring-security-reactive-starter`**| Reactive (WebFlux) 환경용 스타터 |

> 🚫 **Bad Practice (사용 금지):**
> * `com.ids.keycloak:servlet:1.0.0` (X) -> 타 라이브러리(Jakarta Servlet 등)와 혼동됨
> * `com.ids.keycloak:core:1.0.0` (X) -> 식별 불가능

---

## 2. Module Structure & Responsibility (모듈 구조)

우리는 **Multi-Module** 전략을 취하며, 각 모듈의 역할은 엄격히 분리됩니다.

### 🔹 Core Module (`...-core`)
* **역할:** 비즈니스 로직의 심장. Spring Web/Servlet/Reactive에 의존하지 않는 순수 Java 코드.
* **주요 기능:** 토큰 파싱(Parsing), 검증(Verification), 권한 매핑(Authority Mapping), 도메인 모델.
* **제약:** `javax.servlet`, `org.springframework.web` 패키지 import 금지.

### 🔹 Servlet Module (`...-servlet`)
* **역할:** Blocking I/O 기반의 Spring MVC 애플리케이션 지원.
* **의존성:** `core`, `spring-security-web`, `jakarta.servlet-api`
* **주요 기능:** `OncePerRequestFilter`, `AuthenticationProvider`, `AbstractHttpConfigurer`.

### 🔹 Reactive Module (`...-reactive`)
* **역할:** Non-blocking I/O 기반의 Spring WebFlux 애플리케이션 지원.
* **의존성:** `core`, `spring-security-webflux`, `reactor-core`
* **주요 기능:** `ReactiveAuthenticationManager`, `ServerAuthenticationConverter`.

### 🔹 Starter Modules (`...-servlet-starter`, `...-reactive-starter`)
* **역할:** 사용자가 자신의 환경에 맞는 의존성 하나만 추가하여 라이브러리 기능을 쉽게 사용할 수 있도록 하는 **환경별 진입점**입니다.
* **구조:**
    * **`servlet-starter`:** `servlet` 구현체 모듈과 자동 설정 로직을 포함합니다. Servlet 기반의 Spring MVC 환경에서 사용됩니다.
    * **`reactive-starter`:** `reactive` 구현체 모듈과 자동 설정 로직을 포함합니다. Reactive 기반의 Spring WebFlux 환경에서 사용됩니다.
* **주의:** 기존의 통합 `starter`는 두 개의 환경별 `starter`로 분리되었습니다.

---

## 3. Package Structure Strategy (패키지 구조)

패키지명은 **`com.ids.keycloak.security`** 를 Root로 하며, **계층(Layer)** 이 아닌 **기능(Feature)** 단위로 구성합니다.

### 📂 Common Pattern
```text
com.ids.keycloak.security
  ├── config          // 설정 지원 (Configurer, Customizer)
  ├── authentication  // 인증 처리 (Provider, Manager, Token)
  ├── authorization   // 인가 처리 (Provider, Manager)
  ├── filter          // (Servlet only) 필터 체인 관련
  ├── web             // (Reactive only) 웹 교환 처리
  ├── exception       // 예외 처리
  └── util            // 유틸리티
```

### 📂 Core Module Detail
```text
├── token           // TokenVerifier, TokenParser
├── authority       // GrantedAuthoritiesMapper
└── model           // KeycloakUserDetails, KeycloakPrincipal
```

---

## 4. Development Principles (개발 원칙)

오픈소스 라이브러리로서 **확장성**을 최우선으로 고려합니다.

### ✅ Extension Points (확장성)
1.  **`@ConditionalOnMissingBean` 활용:**
   * Starter의 모든 Bean 등록에는 이 어노테이션을 붙여, 사용자가 재정의(Override)할 수 있는 구멍을 열어둡니다.
2.  **Customizer 패턴:**
   * 설정 클래스는 `Customizer<T>`를 인자로 받아, 사용자가 람다식으로 설정을 추가할 수 있게 합니다.
3.  **상속 허용:**
   * 보안상 필수적인 경우를 제외하고는 `final` 클래스 사용을 지양합니다.

### 📝 Coding Convention
1.  **Logging:**
   * `System.out.println` 절대 금지.
   * `slf4j` 인터페이스 사용 (`@Slf4j` 권장).
2.  **Exception:**
   * Checked Exception 지양, `RuntimeException` 기반의 커스텀 예외(`KeycloakSecurityException`) 사용.

---

## 5. Configuration Strategy (설정 및 확장 전략) 

사용자에게 편의성과 제어권을 동시에 제공하며, **환경별 Starter를 통해 명시적인 의존성 관리**를 유도하는 전략을 사용합니다.

### 🔹 Strategy A: Explicit Environment Selection (환경별 스타터 선택)
사용자는 자신의 애플리케이션 환경(Spring MVC 또는 WebFlux)을 명확히 인지하고, 그에 맞는 `starter` 의존성 하나를 직접 선택하여 추가해야 합니다. 이를 통해 불필요한 `reactive` 또는 `servlet` 의존성이 프로젝트에 포함되는 것을 방지합니다.
 
* **Mechanism:** Gradle/Maven 의존성 관리
* **Implementation:**
    * **Servlet 환경:** 사용자는 `keycloak-spring-security-servlet-starter` 의존성을 추가합니다.
    * **Reactive 환경:** 사용자는 `keycloak-spring-security-reactive-starter` 의존성을 추가합니다.

### 🔹 Strategy B: Zero-Configuration (Auto Config)
초기 설정 없이 동작하도록 기본 `SecurityFilterChain`을 제공합니다.
단, 사용자의 커스텀 설정을 방해하지 않기 위해 **반드시 `@ConditionalOnMissingBean`을 사용**합니다.

```java
// Servlet AutoConfiguration Example
@Bean
@ConditionalOnMissingBean(SecurityFilterChain.class)
public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) {
    return http.with(KeycloakHttpConfigurer.keycloak(), Customizer.withDefaults()).build();
}
```
### 🔹 Strategy C: Modular Configuration (Configurer Pattern)
사용자가 직접 설정을 구성할 때를 대비해, 내부 로직을 캡슐화한 Configurer를 제공합니다.

```java
// User Usage Example
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) {
    return http
        .authorizeHttpRequests(...) 
        .addFilterBefore(new MyCustomFilter(), ...) 
        .with(KeycloakHttpConfigurer.keycloak(), Customizer.withDefaults()) // 한 줄로 기능 적용
        .build();
}

```

---

## 6. Build Configuration (Gradle)

* **Build Tool:** Gradle
* **Java Version:** JDK 17 이상
* **Supported Versions:**
    *   Spring Boot 3.5.9 (Stable)
    *   Spring Security 6.5.7 (Stable)
* **Usage:** 사용자는 환경 구분 없이 아래 의존성 하나만 사용합니다.

```build.gradle
// for MVC and Servlet environment
implementation("com.ids.keycloak:keycloak-spring-security-web-starter:1.0.0")

// for WebFlux and Reactive environment
implementation("com.ids.keycloak:keycloak-spring-security-webflux-starter:1.0.0")
```

---

## 7. Feature Toggle Configuration (기능별 설정 가이드)

모든 기능은 `keycloak.security.*` 네임스페이스의 yaml 설정으로 제어됩니다.

### 🔹 CSRF Protection

CSRF(Cross-Site Request Forgery) 보호 설정입니다. 기본값은 **활성화(true)** 이며, 로그아웃 및 토큰 발급 엔드포인트는 자동으로 면제됩니다.

```yaml
keycloak:
  security:
    csrf:
      enabled: true                     # 기본값: true (CSRF 보호 활성화)
      ignore-paths:                     # 추가 CSRF 면제 경로 (Ant 패턴)
        - /api/**
        - /webhook/**
```

| 속성 | 타입 | 기본값 | 설명 |
|------|------|--------|------|
| `enabled` | boolean | `true` | CSRF 보호 활성화 여부. `false` 시 완전 비활성화 |
| `ignore-paths` | List&lt;String&gt; | `[]` | 추가 CSRF 면제 경로. Ant 패턴 지원 (`/api/**` 등) |

**기본 면제 경로 (하드코딩):**
- `/logout` (Front-Channel 로그아웃)
- `/logout/connect/back-channel/**` (Back-Channel 로그아웃)
- Bearer Token 활성화 시: `/auth/token`, `/auth/refresh`, `/auth/logout`

**Basic Auth 연동:**
`basic-auth.enabled: true` 설정 시, `Authorization: Basic` 헤더가 포함된 요청은 자동으로 CSRF 면제됩니다. Basic Auth는 헤더 기반 API 클라이언트용이므로 CSRF 토큰을 전달할 수 없기 때문입니다.

### 🔹 Basic Authentication

```yaml
keycloak:
  security:
    basic-auth:
      enabled: false                    # 기본값: false (opt-in)
```

### 🔹 Bearer Token

```yaml
keycloak:
  security:
    bearer-token:
      enabled: false                    # 기본값: false (opt-in)
      token-endpoint:
        prefix: /auth                   # 기본값: /auth
```

### 🔹 Rate Limiting

```yaml
keycloak:
  security:
    rate-limit:
      enabled: false                    # 기본값: false (opt-in)
      max-requests: 5                   # 시간 윈도우 내 최대 요청 수
      window-seconds: 60               # 시간 윈도우 (초)
      block-duration-seconds: 300      # 차단 지속 시간 (초)
      key-strategy: IP_AND_USERNAME    # IP, USERNAME, IP_AND_USERNAME
      include-basic-auth: true         # Basic Auth에도 적용
```
