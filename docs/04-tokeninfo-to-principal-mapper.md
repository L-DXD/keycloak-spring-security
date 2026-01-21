# 04. [Core] 토큰 기반 인증 및 세션 관리 흐름

## 🎯 목표

Keycloak 기반의 OIDC 인증 환경에서, 브라우저 쿠키(Access/ID Token)와 서버 세션(Refresh Token)을 결합한 하이브리드 토큰 관리 전략을 구현합니다. Spring Security의 `AuthenticationProvider`를 통해 토큰을 검증/갱신하고, 커스텀 `Authentication` 객체를 통해 인증 상태를 관리하는 전체 흐름을 설계합니다.

---

## 1. 핵심 인증 객체 및 저장소 설계

표준 `OAuth2AuthorizedClient`를 사용하는 대신, 역할에 따라 명확히 분리된 커스텀 객체와 저장소를 사용합니다.

### 1.1 인증 객체 (Authentication Objects)
-   **`KeycloakAuthentication`**: `SecurityContext`에 저장되는 핵심 `Authentication` 구현체입니다.
    -   **Principal**: `KeycloakPrincipal` (인증 전/후 동일 타입 사용)
        -   인증 전: 빈 authorities/attributes로 생성
        -   인증 후: 사용자 정보, 권한, 속성 포함
    -   **Credentials**: `idToken` (검증의 주체)
    -   **Details**: `refreshToken` (갱신용) 또는 `KeycloakTokenInfo` (갱신 결과)
    -   **AccessToken**: 별도 필드로 보관 (API 호출용)

-   **`KeycloakPrincipal`**: 사용자를 나타내며 `OAuth2User`를 구현합니다. 인증 완료 후 `resource_access` 클레임에서 권한을 추출하여 보유합니다.

### 1.2 토큰 저장 전략 (Hybrid Approach)
-   **Access Token / ID Token**: **브라우저 쿠키**에 저장
    -   **이유**: 매 요청마다 서버로 전달되어야 하며, 클라이언트(브라우저)에서 접근할 필요가 없음(HttpOnly).
-   **Refresh Token**: **HTTP Session**에 저장 (`KeycloakSessionManager` 관리)
    -   **이유**: 보안상 브라우저 노출을 최소화하고, 서버 측에서 수명 주기를 관리하기 위함.

---

## 2. 인증 흐름 (Authentication Flow)

```text
      요청 (Request)
─────────>
┌────────────────────────────────┐
│           Client               │
└────────────────────────────────┘
             |
             | 1. 쿠키(idToken, accessToken) 포함 요청
             V
┌────────────────────────────────┐
│  KeycloakAuthenticationFilter  │
└────────────────────────────────┘
             |
             | 2. 쿠키에서 토큰 추출
             | 3. Session에서 RefreshToken 추출 (via KeycloakSessionManager)
             | 4. '미인증' Authentication 객체 생성
             |    - Principal: KeycloakPrincipal (sub만 포함, 빈 authorities)
             |    - Details:   RefreshToken
             |
             V
┌────────────────────────────────┐
│     AuthenticationManager      │
└────────────────────────────────┘
             |
             | 5. 인증 위임
             V
┌────────────────────────────────┐
│  KeycloakAuthenticationProvider│
└────────────────────────────────┘
             |
             | 6. ID Token 검증 (서명, 만료 확인)
             |
             | 7. [분기] 검증 실패(만료) 시:
             |    a. Refresh Token으로 재발급 시도 (KeycloakClient)
             |    b. 성공 시 새 토큰들로 교체
             |
             | 8. 최종 'KeycloakPrincipal' 생성
             |    - AccessToken의 'resource_access'에서 Role 추출
             |
             V  9. '인증 완료' Authentication 반환
┌────────────────────────────────┐
│  KeycloakAuthenticationFilter  │
└────────────────────────────────┘
             |
             | 10. [분기] 토큰 재발급 발생 시:
             |     a. 새 RefreshToken -> Session 업데이트
             |     b. 새 Access/ID Token -> Response Cookie 업데이트
             |
             | 11. SecurityContext에 인증 객체 등록
             V
┌────────────────────────────────┐
│     SecurityContextHolder      │
└────────────────────────────────┘
             |
             | 12. 요청 처리 (Controller 등)
             V
      응답 (Response)
<─────────
```

### 2.1 주요 구성 요소 역할

1.  **`KeycloakAuthenticationFilter`**
    -   **토큰 추출**: 쿠키(`CookieUtil`)와 세션(`KeycloakSessionManager`)에서 필요한 토큰을 모두 모읍니다.
    -   **인증 위임**: 수집한 토큰으로 미인증 `KeycloakAuthentication`을 만들어 매니저에게 넘깁니다.
    -   **상태 동기화**: 인증 과정에서 토큰이 갱신되었다면(반환된 객체의 `details` 확인), 이를 세션과 응답 쿠키에 반영하여 클라이언트 상태를 최신화합니다.
    -   **Context 설정**: 최종 인증 객체를 `SecurityContextHolder`에 태웁니다.

2.  **`KeycloakAuthenticationProvider`**
    -   **토큰 검증**: `JwtDecoder`를 사용하여 ID Token과 Access Token의 서명 및 만료를 확인합니다.
    -   **자동 갱신**: ID Token이 만료되었다면, `details`에 있는 Refresh Token을 사용하여 Keycloak 서버에 토큰 재발급(`reissueToken`)을 요청합니다.
    -   **권한 매핑**: Access Token의 `resource_access` -> `account` -> `roles` 등에서 역할을 추출하여 Spring Security 권한(`GrantedAuthority`)으로 변환합니다.

3.  **`KeycloakSessionManager`**
    -   세션에 대한 추상화 계층을 제공합니다.
    -   Refresh Token 저장/조회/삭제
    -   Principal Name 저장 (Back-Channel 로그아웃 검색용)
    -   Keycloak Session ID (sid) 저장

---

## 3. 핵심 코드 구조

### 3.1 SecurityConfig 구성

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, 
                                         KeycloakAuthenticationProvider provider,
                                         KeycloakSessionManager sessionManager) throws Exception {
        http
            // 1. 세션 생성 정책: 필요시 생성 (NEVER 권장 - 필터가 세션을 필요로 할 때만 사용)
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.NEVER))
            
            // 2. 인증 필터 등록
            .addFilterBefore(
                new KeycloakAuthenticationFilter(authenticationManager, objectMapper, sessionManager),
                UsernamePasswordAuthenticationFilter.class
            )
            
            // 3. Provider 등록
            .authenticationProvider(provider);
            
        return http.build();
    }
}
```

### 3.2 KeycloakSessionManager

```java
public class KeycloakSessionManager {
    private static final String REFRESH_TOKEN_ATTR = "KEYCLOAK_REFRESH_TOKEN";

    public void saveRefreshToken(HttpSession session, String refreshToken) {
        session.setAttribute(REFRESH_TOKEN_ATTR, refreshToken);
    }

    public Optional<String> getRefreshToken(HttpSession session) {
        return Optional.ofNullable((String) session.getAttribute(REFRESH_TOKEN_ATTR));
    }
}
```

## ✅ 인수 조건
- [x] **토큰 추출**: Filter가 쿠키(Access/ID)와 세션(Refresh)에서 토큰을 올바르게 읽어와야 한다.
- [x] **검증 및 갱신**: Provider가 만료된 토큰을 감지하면 Refresh Token을 사용해 자동으로 재발급받아야 한다.
- [x] **상태 동기화**: 토큰 재발급 시, Filter가 변경된 토큰을 세션과 브라우저 쿠키에 즉시 반영해야 한다.
- [x] **권한 부여**: Access Token에 포함된 Keycloak Role이 Spring Security의 Authority로 올바르게 매핑되어야 한다.