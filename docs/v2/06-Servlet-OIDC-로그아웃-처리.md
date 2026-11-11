# 06. [Servlet] OIDC 로그아웃 처리: 하이브리드 세션 관리 및 글로벌 로그아웃

## 🎯 목표

OIDC(OpenID Connect) 환경에서 완벽한 싱글 사인아웃(Single Sign-Out)을 구현합니다. 사용자가 직접 수행하는 **프론트 채널 로그아웃**과 Keycloak 서버가 전파하는 **백채널 로그아웃**을 모두 처리하여, 분산 환경에서도 사용자의 보안 세션을 안전하게 종료하는 것을 목표로 합니다.

---

## 📋 프론트 채널 로그아웃 (Front-Channel Logout)

사용자가 애플리케이션의 로그아웃 버튼을 눌러 시작되는 흐름입니다.

### 1. 커스텀 `KeycloakLogoutHandler`
Spring Security의 기본 로그아웃 로직에 더해, 우리 아키텍처에 필요한 세 가지 핵심 작업을 수행합니다.
-   **Keycloak API 로그아웃**: 세션에 저장된 `Refresh Token`을 사용하여 Keycloak 서버에 해당 사용자의 세션 종료를 요청합니다.
-   **로컬 세션 무효화**: `KeycloakSessionManager`를 통해 현재 HTTP 세션을 파기하고, 세션에 저장된 Refresh Token과 로그아웃 메타데이터를 제거합니다.
-   **쿠키 삭제**: 브라우저에 저장된 `access_token`, `id_token` 쿠키를 즉시 만료시켜 클라이언트 측의 인증 수단을 제거합니다.

### 2. `OidcClientInitiatedLogoutSuccessHandler`
-   로컬 로그아웃 처리가 완료된 후, 사용자를 Keycloak의 로그아웃 엔드포인트로 리디렉션합니다.
-   이를 통해 Keycloak의 SSO 세션(브라우저 쿠키)까지 완전히 종료되어, 다른 앱으로의 자동 로그인을 방지합니다.

---

## 🚀 백채널 로그아웃 (Back-Channel Logout)

Keycloak 관리자 콘솔에서 세션을 종료하거나, 다른 연동 앱에서 로그아웃했을 때 Keycloak이 우리 서버로 직접 로그아웃 신호를 보내는 흐름입니다.

### 1. `OidcBackChannelSessionLogoutHandler` 구현
우리 라이브러리는 Spring Security 6의 `oidcLogout` 기능을 활용하며, 세션 파기 효율을 높이기 위해 커스텀 핸들러를 사용합니다.

-   **핵심 메커니즘**: `FindByIndexNameSessionRepository` (Spring Session) 활용
-   **동작 흐름**:
    1.  Keycloak으로부터 `logout_token` (JWT)을 수신합니다.
    2.  토큰 내부의 `sub`(사용자 ID)와 `sid`(Keycloak 세션 ID)를 추출합니다.
    3.  **정밀 타격 (sid 존재 시)**: `sid`가 포함된 경우, 사용자의 여러 세션 중 해당 브라우저/기기에 해당하는 특정 세션만 찾아 파기합니다.
    4.  **전체 로그아웃 (sid 미존재 시)**: `sub`를 기준으로 해당 사용자의 모든 활성 세션을 검색하여 일괄 삭제합니다.

### 2. 세션 검색 및 삭제 로직
```java
// OidcBackChannelSessionLogoutHandler 내부 로직 요약
public void logout(...) {
    String subject = logoutToken.getSubject();
    String sid = logoutToken.getSessionId();

    // 1. Principal Name(sub)으로 모든 세션 조회
    Map<String, Session> sessions = sessionRepository.findByPrincipalName(subject);

    // 2. sid가 일치하는 세션만 골라 삭제 (또는 전체 삭제)
    sessions.forEach((id, session) -> {
        if (sid == null || sid.equals(session.getAttribute("KEYCLOAK_SESSION_ID"))) {
            sessionRepository.deleteById(id);
        }
    });
}
```

---

## ⚙️ Security 설정 통합

`KeycloakHttpConfigurer`를 통해 위 핸들러들을 자동으로 구성합니다.

```java
// Front-Channel 설정
http.logout(logout -> logout
    .logoutUrl("/logout")
    .addLogoutHandler(keycloakLogoutHandler)
    .logoutSuccessHandler(oidcLogoutSuccessHandler)
);

// Back-Channel 설정
http.oidcLogout(oidc -> oidc
    .backChannel(backChannel -> backChannel
        .logoutHandler(new OidcBackChannelSessionLogoutHandler(sessionRepository))
    )
);
```

---

## ✅ 결론

우리 아키텍처는 **인증은 쿠키 기반(Stateless)**으로 빠르게 처리하되, **로그아웃 관리와 토큰 갱신은 세션 기반(Stateful)**으로 엄격하게 통제하는 하이브리드 방식을 취합니다. 

Spring Session과 Redis를 연동할 경우, `OidcBackChannelSessionLogoutHandler`를 통해 다중 서버 환경에서도 단 한 번의 요청으로 사용자의 모든 세션을 즉시 무효화할 수 있는 강력한 글로벌 로그아웃 기능을 제공합니다.
