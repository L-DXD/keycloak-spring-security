# 08. [Servlet] Web 인가 처리: Introspector 어댑터 구현

## 목표

Spring Security의 `AuthorizationManager`를 커스텀 구현하여, 애플리케이션의 리소스(URL) 접근 제어를 Keycloak의 **Authorization Services** (Policy Enforcement Point)에 위임하는 **Introspector 어댑터**를 개발합니다.

기존의 정적인 `antMatchers` 권한 설정 대신, Keycloak 서버에 실시간으로 권한 판단을 요청함으로써 동적이고 중앙 집중화된 인가 관리를 실현합니다.

이 구현체는 `KeycloakAuthorizationManager`로 명명하며, 현재 프로젝트의 인증 객체인 `KeycloakAuthentication`과 연동됩니다.

---

## 구현 개요

`KeycloakAuthorizationManager`는 Spring Security의 인가 결정 흐름에 개입하여 다음과 같은 로직을 수행합니다.

1.  **요청 정보 추출**: 사용자가 접근하려는 **Endpoint(URL)**와 **HTTP Method**를 파악합니다.
2.  **인증 상태 확인**: 현재 사용자의 인증 객체(`KeycloakAuthentication`)가 유효한지 검증합니다.
3.  **Keycloak 인가 요청**: 사용자 `Access Token`과 요청 정보(URL, Method)를 Keycloak에 전송하여 접근 허용 여부를 질의합니다.
4.  **최종 결정**: Keycloak의 응답(`Granted`/`Denied`)에 따라 `AuthorizationDecision`을 반환합니다.

---

## 코드 구현

### KeycloakAuthorizationManager

```java
package com.ids.keycloak.security.manager;

import com.ids.keycloak.security.authentication.KeycloakAuthentication;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakAuthorizationResult;
import com.sd.KeycloakClient.factory.KeycloakClient;
import jakarta.servlet.http.HttpServletRequest;
import java.util.function.Supplier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * Keycloak Authorization Services를 이용한 커스텀 인가 관리자.
 * 요청마다 Keycloak에 권한 확인(Policy Enforcement)을 수행합니다.
 */
@RequiredArgsConstructor
@Slf4j
public class KeycloakAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final KeycloakClient keycloakClient;

    /**
     * 특정 요청(RequestAuthorizationContext)에 대한 접근 허용 여부를 결정합니다.
     */
    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext context) {
        HttpServletRequest request = context.getRequest();
        String method = request.getMethod();
        String endpoint = request.getRequestURI();

        log.debug("[Authorization] 인가 검증 시작: {} {}", method, endpoint);

        Authentication auth = authentication.get();
        if (!(auth instanceof KeycloakAuthentication keycloakAuth) || !auth.isAuthenticated()) {
            log.warn("[Authorization] 인증되지 않은 사용자이거나, 지원하지 않는 인증 토큰입니다.");
            return new AuthorizationDecision(false);
        }

        log.debug("[Authorization] Keycloak에 인가 요청...");
        String accessToken = keycloakAuth.getAccessToken();

        KeycloakResponse<KeycloakAuthorizationResult> response = keycloakClient.auth().authorization(accessToken, endpoint, method);

        boolean granted = response.getBody()
            .map(KeycloakAuthorizationResult::isGranted)
            .orElse(false);

        log.debug("[Authorization] 인가 결과: {} {} -> {}", method, endpoint, granted ? "허용" : "거부");

        return new AuthorizationDecision(granted);
    }
}
```

---

## 설정 방법

### application.yaml

```yaml
keycloak:
  security:
    # 인증 없이 접근 가능한 경로
    permit-all-paths:
      - /public/**
      - /health
      - /actuator/**

    # Keycloak Authorization Services 활성화 (기본값: false)
    authorization-enabled: true
```

### 설정 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `authorization-enabled: false` | 기본 | 인증만 확인 (`authenticated()`) |
| `authorization-enabled: true` | - | 매 요청마다 Keycloak에 인가 검증 |

---

## 주요 로직 설명

### 1. `AuthorizationManager<RequestAuthorizationContext>`
Spring Security 5.5+ 부터 도입된 인가 매니저 인터페이스입니다. `AccessDecisionManager`를 대체하며, 제네릭을 통해 다양한 컨텍스트(여기서는 `RequestAuthorizationContext`)의 인가 처리를 지원합니다.

### 2. Keycloak 연동 (`KeycloakClient`)
-   이 매니저는 직접 권한 로직을 계산하지 않고, **Keycloak을 외부 의사 결정 포인트(PDP: Policy Decision Point)**로 활용합니다.
-   `keycloakClient.auth().authorization(...)` 메서드를 호출하여 실시간으로 정책을 평가합니다. 이는 권한 정책이 변경되어도 애플리케이션 재배포 없이 즉시 반영됨을 의미합니다.

### 3. 인증 객체 (`KeycloakAuthentication`)
-   `KeycloakAuthenticationProvider`를 통해 생성된 `KeycloakAuthentication` 객체를 사용합니다.
-   `keycloakAuth.getAccessToken()`을 통해 인증에 사용된 JWT Access Token을 가져와, Keycloak Authorization API 호출 시 증명 자료(Bearer Token)로 사용합니다.

### 4. AutoConfiguration
-   `KeycloakAuthorizationManager`는 `KeycloakServletAutoConfiguration`에서 자동으로 Bean 등록됩니다.
-   `authorization-enabled: true` 설정 시 `SecurityFilterChain`에서 `.access(keycloakAuthorizationManager)`로 인가 처리를 위임합니다.

---

## 고려사항

-   **성능 이슈**: 매 요청마다 Keycloak 서버와 통신하므로 네트워크 오버헤드가 발생할 수 있습니다.
-   **예외 처리**: Keycloak 서버 장애 시 애플리케이션 접속이 불가능해질 수 있으므로, 적절한 예외 처리가 필요합니다.
