# 06. [Servlet] OIDC 로그인 성공 처리: 토큰 쿠키 발급 및 세션 저장

## 🎯 목표

OIDC `oauth2Login` 성공 시, `docs/04`에서 정의한 커스텀 인증 필터(`KeycloakAuthenticationFilter`)가 동작하는 데 필요한 환경을 구축합니다. 이를 위해, 커스텀 `AuthenticationSuccessHandler`를 구현하여 **토큰을 쿠키에 저장**하고, 동시에 **`OAuth2AuthorizedClient` 객체를 `HttpSession`에 저장**하는 과정을 상세히 설명합니다.

또한, `HttpSession`의 저장소 전략(In-Memory vs. Spring Session)을 비교하고, 특히 **백채널 로그아웃**과 같은 고급 기능을 구현하기 위한 최적의 아키텍처를 제시합니다.

---

## 📋 `docs/04` 아키텍처를 위한 로그인 성공 흐름

`docs/04`에서 설계한 `KeycloakAuthenticationFilter`는 매 요청마다 쿠키에 담긴 토큰을 읽어 stateless 인증을 수행합니다. 이 흐름이 가능하려면, 최초 로그인 시점에 해당 토큰들이 쿠키로 발급되고 `OAuth2AuthorizedClient` 객체가 서버 세션에 저장되어야 합니다.

### 1단계: 커스텀 `OidcLoginSuccessHandler` 실행

-   **컴포넌트:** `OidcLoginSuccessHandler` (우리가 직접 구현한 `AuthenticationSuccessHandler`)
-   **동작:**
    1.  사용자가 Keycloak에서 성공적으로 로그인하고 애플리케이션으로 돌아오면, Spring Security는 사전에 설정된 우리 커스텀 핸들러를 호출합니다.
    2.  이 핸들러는 Access Token과 ID Token을 쿠키로 발급하는 역할을 수행합니다.

### 2단계: Access Token 및 ID Token 쿠키 발급

-   **컴포넌트:** `OidcLoginSuccessHandler`
-   **동작:**
    1.  핸들러는 `Authentication` 객체로부터 `OAuth2AuthorizedClient`와 `OidcUser` 정보를 얻습니다.
    2.  `OAuth2AuthorizedClient`에서는 **Access Token**을, `OidcUser`에서는 **ID Token**을 각각 추출합니다.
    3.  추출된 토큰 값으로 `access_token`, `id_token`이라는 이름의 **쿠키를 생성**하고 `HttpOnly` 속성을 부여합니다.
    4.  `HttpServletResponse`에 생성된 두 개의 토큰 쿠키를 추가하여 브라우저에 전달합니다.

### 3단계: `OAuth2AuthorizedClient` 객체를 `HttpSession`에 저장

-   **컴포넌트:** `OidcLoginSuccessHandler`의 부모 클래스(`SavedRequestAwareAuthenticationSuccessHandler`), `OAuth2AuthorizedClientRepository`
-   **동작:**
    1.  쿠키 발급이 끝난 후, `OidcLoginSuccessHandler`는 `super.onAuthenticationSuccess()`를 호출하여 Spring Security의 나머지 기본 동작을 위임합니다.
    2.  `docs/04` 아키텍처에서는 `NullSecurityContextRepository`를 사용하므로 `SecurityContext`가 세션에 저장되지는 않습니다.
    3.  이 단계에서 **`OAuth2AuthorizedClientRepository`** 구현체를 통해 **`Refresh Token을 포함한 OAuth2AuthorizedClient` 객체 전체가 `HttpSession`에 저장**됩니다. 이 객체는 향후 토큰 갱신 등의 OAuth2 관련 작업에 사용됩니다.
    4.  이 과정에서 `HttpSession`이 생성되면, 서블릿 컨테이너는 이 세션을 식별하기 위한 **`JSESSIONID` 쿠키를 자동으로 발급**합니다. 이 쿠키는 `docs/04`의 `KeycloakAuthenticationFilter`가 `OAuth2AuthorizedClient` 객체를 조회하기 위한 `sessionId`의 역할을 수행합니다.

---

## 4. 세션 저장소 전략: In-Memory vs. Spring Session

`3단계`에서 저장된 `OAuth2AuthorizedClient` 객체를 담고 있는 `HttpSession`은 Refresh Token 관리의 중요한 기반이 됩니다. 이 세션을 어디에 저장할지는 애플리케이션의 확장성과 기능(특히 백채널 로그아웃)에 큰 영향을 미칩니다.

### 옵션 1: 기본 메모리 세션 (Tomcat 관리 방식)

-   **설명:** 별도의 설정이 없으면, `HttpSession`은 Tomcat과 같은 서블릿 컨테이너의 메모리에 저장됩니다.
-   **장점:**
    -   구성이 매우 간단하며 추가적인 의존성이 필요 없습니다.
-   **단점:**
    -   **백채널 로그아웃 구현의 어려움:** Keycloak에서 특정 사용자의 로그아웃을 통지해도, 메모리에 흩어져 있는 세션 중 어떤 것이 해당 사용자의 세션인지 효율적으로 찾을 방법이 없습니다. 모든 활성 세션을 일일이 순회해야 하므로 비효율적이고 구현이 복잡합니다.
    -   **확장성 부재:** 서버를 여러 대로 확장(Scale-out)할 경우, 세션이 각 서버에 따로 저장되어 사용자 요청이 다른 서버로 전달되면 로그인이 풀립니다. (스티키 세션 설정이 필요함)
    -   **서버 재시작 시 세션 유실:** 서버가 재시작되면 메모리의 모든 세션 정보가 사라집니다.

### 옵션 2: 외부 저장소 세션 (Spring Session + Redis 권장)

-   **설명:** `Spring Session` 라이브러리를 사용하여 `HttpSession`의 관리 주체를 Tomcat에서 `Spring Session`으로 옮기고, 세션 데이터를 **Redis**와 같은 외부 Key-Value 저장소에 저장합니다.
-   **장점:**
    -   **백채널 로그아웃 구현 용이:** `Spring Session`은 **사용자 ID(`Principal`, 즉 `sub`)를 기준으로 세션을 검색**하는 `FindByIndexNameSessionRepository` 기능을 제공합니다. 이를 통해 백채널 로그아웃 요청 시 특정 사용자의 모든 세션을 즉시 찾아 삭제할 수 있습니다.
    -   **세션 클러스터링 및 확장성:** 여러 대의 서버가 Redis의 중앙 세션 저장소를 공유하므로, 어떤 서버로 요청이 들어와도 동일한 세션 상태를 유지할 수 있습니다.
    -   **안정성 및 데이터 보존:** 서버가 재시작되어도 세션 데이터는 Redis에 안전하게 보존됩니다.
    -   **동시 세션 제어 용이:** Spring Security의 동시 세션 제어 기능을 다중 서버 환경에서도 문제없이 활용할 수 있습니다.
-   **단점:**
    -   `Redis`와 같은 외부 저장소를 구축하고 관리해야 합니다.
    -   `spring-boot-starter-data-redis`, `spring-session-data-redis` 의존성을 프로젝트에 추가해야 합니다.

### 권장 사항

프로토타입이나 소규모 단일 서버 환경에서는 **메모리 세션**으로 시작할 수 있습니다. 하지만 안정적인 서비스 운영과 확장성, 그리고 **완벽한 싱글 사인아웃(Single Sign-Out)을 위한 백채널 로그아웃**, **다중 서버 환경에서의 동시 세션 제어** 등을 고려한다면 **Spring Session과 Redis를 도입하는 것을 강력히 권장**합니다.

---

## 5. 최종 리디렉션

-   **컴포넌트:** `OidcLoginSuccessHandler`의 부모 클래스(`SavedRequestAwareAuthenticationSuccessHandler`)
-   **동작:**
    1.  모든 쿠키 발급과 세션 저장이 완료되면, 부모 핸들러의 기본 로직에 따라 사용자는 원래 접속하려던 페이지 또는 애플리케이션의 기본 페이지 (`/`)로 최종 리디렉션됩니다.

## ✅ 결론: `docs/04` 아키텍처의 완성

OIDC 로그인 성공 시, 이 커스텀 흐름을 통해 브라우저는 총 3개의 핵심 쿠키를 전달받게 됩니다.

1.  **`access_token` 쿠키:** `KeycloakAuthenticationFilter`가 사용자의 리소스 접근 권한을 확인할 때 사용합니다.
2.  **`id_token` 쿠키:** `KeycloakAuthenticationFilter`가 사용자의 신원을 증명할 때 사용합니다.
3.  **`JSESSIONID` 쿠키:** `KeycloakAuthenticationFilter`가 `OAuth2AuthorizedClient` 객체를 조회하고 토큰 갱신이 필요할 때, 이 `sessionId`를 통해 `HttpSession`에 저장된 해당 객체를 찾기 위해 사용합니다.

이로써, 최초 로그인 이후의 모든 요청은 `docs/04`에 설계된 stateless 인증 방식으로 동작할 수 있는 모든 준비를 마치게 됩니다.