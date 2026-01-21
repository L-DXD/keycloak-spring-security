# 05. [Servlet] OIDC 로그인 성공 처리: 토큰 쿠키 발급 및 세션 저장

## 🎯 목표

Standard OIDC `oauth2Login` 성공 시, `docs/04`에서 설계한 커스텀 인증 필터(`KeycloakAuthenticationFilter`)가 동작하는 데 필요한 **하이브리드 토큰 환경**을 구축합니다. 
이를 위해 커스텀 `AuthenticationSuccessHandler`를 구현하여 **Access/ID Token은 쿠키**로, **Refresh Token과 로그아웃 메타데이터는 세션**으로 분산 저장하는 과정을 상세히 설명합니다.

---

## 📋 로그인 성공 처리 흐름

Spring Security의 표준 `OAuth2LoginAuthenticationFilter`가 인증을 마치면, 우리가 등록한 `OidcLoginSuccessHandler`가 호출되어 하이브리드 저장 전략을 실행합니다.

### 1단계: 표준 인증 및 AuthorizedClient 저장 (Spring Security 내부 동작)
-   사용자가 Keycloak에서 로그인을 마치고 돌아오면, 표준 필터가 `Authorization Code`를 `Access/Refresh Token`으로 교환합니다.
-   교환된 토큰 정보를 담은 `OAuth2AuthorizedClient` 객체는 `OAuth2AuthorizedClientRepository`를 통해 저장됩니다 (기본적으로 HttpSession).

### 2단계: 커스텀 핸들러 실행 (`OidcLoginSuccessHandler`)
-   **동작**:
    1.  저장된 `OAuth2AuthorizedClient`를 조회하여 토큰 정보를 확보합니다.
    2.  `KeycloakSessionManager`를 통해 **세션에 핵심 정보**를 저장합니다.
    3.  `CookieUtil`을 통해 **브라우저에 토큰 쿠키**를 발급합니다.

### 3단계: 세션 저장 (`KeycloakSessionManager`)
-   **목적**: 토큰 갱신 및 백채널 로그아웃 지원
-   **저장 데이터**:
    1.  **Refresh Token**: 보안상 브라우저에 노출하지 않고 세션에만 보관하여, 서버 측에서 토큰 갱신을 수행합니다.
    2.  **Principal Name**: `FindByIndexNameSessionRepository` 인덱스용 (백채널 로그아웃 시 사용자 세션 검색).
    3.  **Keycloak Session ID (sid)**: ID Token의 `sid` 클레임. 특정 기기/브라우저 세션만 로그아웃 시키기 위해 저장합니다.

### 4단계: 쿠키 발급 (`CookieUtil`)
-   **목적**: Stateless 인증 (`KeycloakAuthenticationFilter`)
-   **발급 쿠키**:
    1.  **`access_token`**: API 호출 권한 증명 (HttpOnly)
    2.  **`id_token`**: 사용자 신원 증명 (HttpOnly)
-   이 쿠키들은 매 요청마다 서버로 전송되어 `KeycloakAuthenticationFilter`가 세션 조회 없이도 1차적인 인증을 수행할 수 있게 합니다.

---

## 4. 세션 저장소 전략: In-Memory vs. Spring Session

`KeycloakSessionManager`가 사용하는 `HttpSession`의 저장 위치는 애플리케이션의 확장성과 백채널 로그아웃 기능의 완성도를 결정합니다.

### 옵션 1: 기본 메모리 세션 (Tomcat)
-   **설명**: 단일 서버의 메모리에 세션을 저장합니다.
-   **제약사항**:
    -   서버 재시작 시 로그인 정보(Refresh Token) 유실.
    -   다중 서버 환경(Scale-out)에서 세션 공유 불가.
    -   **백채널 로그아웃 제한**: 특정 사용자의 모든 세션을 찾아 만료시키는 기능 구현이 어렵거나 불가능합니다.

### 옵션 2: 외부 저장소 세션 (Spring Session + Redis 권장)
-   **설명**: 세션 데이터를 Redis 등 외부 저장소에서 중앙 관리합니다.
-   **이점**:
    -   **백채널 로그아웃 완벽 지원**: `FindByIndexNameSessionRepository`를 통해 `Principal Name`으로 모든 서버에 흩어진 사용자의 세션을 즉시 검색하고 만료시킬 수 있습니다.
    -   **고가용성**: 서버가 재시작되어도 로그인 상태가 유지됩니다.
    -   **확장성**: 서버를 늘려도 세션 불일치 문제가 발생하지 않습니다.

### 💡 권장 아키텍처
프로덕션 환경에서는 **Spring Session + Redis** 조합을 사용하여 `KeycloakSessionManager`가 관리하는 Refresh Token과 로그아웃 정보를 안정적으로 유지하는 것을 권장합니다.

---

## ✅ 결론: 하이브리드 인증 아키텍처 완성

로그인이 성공하면 클라이언트와 서버는 다음과 같은 상태를 가집니다.

| 저장소 | 저장 데이터 | 용도 | 사용 컴포넌트 |
| :--- | :--- | :--- | :--- |
| **브라우저 쿠키** | `access_token`<br>`id_token` | 매 요청 인증 (Stateless) | `KeycloakAuthenticationFilter` |
| **서버 세션** | `refresh_token`<br>`sid`<br>`principal_name` | 토큰 갱신 및<br>백채널 로그아웃 | `KeycloakAuthenticationProvider`<br>`BackChannelLogoutHandler` |

이 구조를 통해 **빠른 인증(쿠키)**과 **강력한 보안 관리(세션)**의 장점을 모두 취할 수 있습니다.