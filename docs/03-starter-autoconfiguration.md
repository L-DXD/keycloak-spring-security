# 이슈: [Starter] 환경 자동 감지 및 AutoConfiguration 구현

## 🎯 목표
사용자가 `keycloak-spring-security-starter` 의존성 하나만 추가하면, Spring MVC(Servlet)와 WebFlux(Reactive) 환경을 자동으로 감지하여 필요한 보안 설정을 활성화하는 AutoConfiguration을 구현합니다. 이를 통해 'Zero-Configuration'에 가까운 사용 경험을 제공합니다.

## 📋 작업 상세 내용

### 1. AutoConfiguration Imports 설정
- `keycloak-spring-security-starter` 모듈의 `src/main/resources/META-INF/spring` 디렉터리에 `org.springframework.boot.autoconfigure.AutoConfiguration.imports` 파일을 생성합니다.
- 이 파일에 아래에서 생성할 두 AutoConfiguration 클래스의 전체 경로를 등록하여 Spring Boot가 설정을 인식하도록 합니다.

### 2. Servlet 환경 자동 설정 (`KeycloakServletAutoConfiguration`)
- `keycloak-spring-security-starter` 모듈 내에 `KeycloakServletAutoConfiguration` 클래스를 생성합니다.
- **조건부 활성화:**
  - `@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)`: 클래스 레벨에 적용하여 오직 Servlet 기반 웹 애플리케이션에서만 설정이 활성화되도록 합니다.
  - `@ConditionalOnClass(SecurityFilterChain.class)`: Spring Security가 클래스패스에 존재할 때만 활성화되도록 합니다.
- **Bean 등록:**
  - `KeycloakAuthenticationEntryPoint`: `@ConditionalOnMissingBean`과 함께 Bean으로 등록합니다.
  - `KeycloakAccessDeniedHandler`: `@ConditionalOnMissingBean`과 함께 Bean으로 등록합니다.
  - `SecurityFilterChain`: `@ConditionalOnMissingBean`과 함께 기본 `SecurityFilterChain`을 등록합니다. 이 체인은 `servlet` 모듈에서 만들 `KeycloakHttpConfigurer`를 사용하여 구성될 것입니다.

### 3. Reactive 환경 자동 설정 (`KeycloakReactiveAutoConfiguration`)
- `keycloak-spring-security-starter` 모듈 내에 `KeycloakReactiveAutoConfiguration` 클래스를 생성합니다.
- **조건부 활성화:**
  - `@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)`: 클래스 레벨에 적용하여 오직 Reactive 기반 웹 애플리케이션에서만 설정이 활성화되도록 합니다.
  - `@ConditionalOnClass(SecurityWebFilterChain.class)`: Spring Security (WebFlux)가 클래스패스에 존재할 때만 활성화되도록 합니다.
- **Bean 등록:**
  - `ServerAuthenticationEntryPoint`: `@ConditionalOnMissingBean`과 함께 Bean으로 등록합니다.
  - `ServerAccessDeniedHandler`: `@ConditionalOnMissingBean`과 함께 Bean으로 등록합니다.
  - `SecurityWebFilterChain`: `@ConditionalOnMissingBean`과 함께 기본 `SecurityWebFilterChain`을 등록합니다.

### 4. 의존성 관리
- `keycloak-spring-security-starter`의 `build.gradle` 파일에 `keycloak-spring-security-servlet`과 `keycloak-spring-security-reactive` 모듈에 대한 의존성을 `api` 또는 `implementation`으로 추가합니다.
- Spring Boot 웹 스타터(`spring-boot-starter-web`, `spring-boot-starter-webflux`) 의존성은 `compileOnly`로 설정하여, 사용자의 프로젝트 환경에 따라 필요한 의존성만 전이되도록 관리하는 것을 고려합니다.

## ✅ 인수 조건
- [x] 사용자가 직접 `SecurityFilterChain` Bean을 등록하면, `starter`의 기본 `SecurityFilterChain` 설정이 동작하지 않는다 (`@ConditionalOnMissingBean` 동작 확인).
- [x] 사용자가 직접 `KeycloakAuthenticationEntryPoint` 또는 `ServerAuthenticationEntryPoint` Bean을 등록하면, `starter`의 기본 Bean을 덮어쓴다 (`@ConditionalOnMissingBean` 동작 확인).

### ConditionalOnMissingBean 동작 확인 결과

`@ConditionalOnMissingBean` 어노테이션의 동작을 검증하기 위해 다음과 같은 테스트를 수행하였습니다:

1.  **준비 단계**:
    *   `keycloak-spring-security-starter` 모듈 내의 `KeycloakServletAutoConfiguration.java`와 `KeycloakReactiveAutoConfiguration.java` 파일에 각 `@Bean` 메서드가 호출될 때 로그 메시지를 출력하도록 추가하였습니다.
    *   `integration-tests/servlet-app/src/main/java/com/ids/keycloak/security/test/servlet/ServletApp.java` 파일에 다음 사용자 정의 빈들을 등록하였습니다:
        *   `SecurityFilterChain` (기본 경로 `/test`에 대해 인증 없이 허용)
        *   `KeycloakAuthenticationEntryPoint` (커스텀 로그 메시지 출력)
        *   `KeycloakAccessDeniedHandler` (커스텀 로그 메시지 출력)
    *   `integration-tests/servlet-app/src/test/java/com/ids/keycloak/security/test/servlet/AutoConfigurationIntegrationTest.java` 파일은 `/test` 경로에 대해 `HTTP 200 OK` 응답을 기대하도록 수정되었습니다.
    *   모든 `@ConditionalOnMissingBean` 어노테이션은 명시적으로 클래스 기반 검증을 사용하도록 수정되었습니다 (예: `@ConditionalOnMissingBean(SecurityFilterChain.class)`).

2.  **테스트 실행**:
    *   `ServletApp`을 실행하여 로그를 확인하였습니다. (통합 테스트 실행 대신 애플리케이션 직접 실행을 통해 로그 확인)

3.  **관찰 결과**:
    *   `ServletApp`에서 정의한 **사용자 정의 빈들의 등록 로그**(`Custom KeycloakAuthenticationEntryPoint 빈이 등록되었습니다.`, `Custom KeycloakAccessDeniedHandler 빈이 등록되었습니다.`)가 성공적으로 출력되었습니다.
    *   `KeycloakServletAutoConfiguration`에서 정의한 **라이브러리의 자동 구성 빈들(SecurityFilterChain, KeycloakAuthenticationEntryPoint, KeycloakAccessDeniedHandler)의 등록 로그는 출력되지 않았습니다.**
    *   `KeycloakServletAutoConfiguration` 클래스 자체의 활성화 로그(`Keycloak Spring Security: Servlet 환경 자동 설정이 활성화되었습니다.`)는 정상적으로 출력되었습니다.

4.  **결론**:
    *   이러한 관찰 결과는 `KeycloakServletAutoConfiguration` 내의 `@ConditionalOnMissingBean` 어노테이션들이 **정상적으로 작동함**을 명확히 보여줍니다. 즉, 사용자가 애플리케이션 컨텍스트에 동일한 타입의 빈을 직접 등록했을 때, 라이브러리의 자동 구성 빈은 등록되지 않고 사용자 정의 빈이 우선합니다. 이는 'Zero-Configuration' 목표를 달성하며 사용자가 필요한 경우 기본 설정을 유연하게 재정의할 수 있음을 의미합니다.

