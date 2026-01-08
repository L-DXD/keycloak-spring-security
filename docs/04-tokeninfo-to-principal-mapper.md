# 04. [Core] 토큰 기반 인증 흐름 설계

## 🎯 목표

Keycloak 기반의 OIDC 인증 환경에서, 브라우저 쿠키를 통해 전달된 토큰을 검증하고, Spring Security의 표준 **`OAuth2AuthorizedClientRepository`** 메커니즘을 사용하여 토큰(Access/Refresh)을 **`HttpSession`에 통일된 방식으로 저장 및 관리**합니다. 또한, 커스텀 `Authentication` 객체를 생성하여 `SecurityContext`에 사용자의 신원 정보를 저장하는 전체 흐름을 설계합니다.

---

## 1. 핵심 인증 객체 설계

이 설계는 Spring Security의 표준 `OAuth2AuthorizedClient` 메커니즘을 적극적으로 활용하며, 인증 전후 상태를 명확히 구분하는 커스텀 `Authentication` 객체를 중심으로 합니다.

-   **`KeycloakAuthentication`**: `SecurityContext`에 저장될 핵심 `Authentication` 객체입니다.
-   **`PreAuthenticationPrincipal`**: 인증을 "요청"하는 상태의 임시 `Principal`입니다.
-   **`KeycloakPrincipal`**: 인증이 "완료된" 사용자를 나타내는 최종 `Principal`입니다. `OAuth2User` 인터페이스를 구현합니다.
-   **`OAuth2AuthorizedClient` 관련 객체**:
    -   **`OAuth2AuthorizedClient`**: **(토큰 저장소 역할)** 사용자의 토큰(Access Token, Refresh Token)을 `ClientRegistration`(클라이언트 정보) 및 인증된 `Principal`과 연결하여 관리하는 표준 객체입니다.
    -   **`OAuth2AuthorizedClientRepository`**: `OAuth2AuthorizedClient` 객체를 **영속성 계층(Persistence Layer)에 저장하고 조회**하는 표준 인터페이스입니다. 우리는 이 구현체로 `HttpSession`을 사용하는 `HttpSessionOAuth2AuthorizedClientRepository`를 채택합니다.

아래는 이 설계의 전체적인 인증 흐름을 나타낸 다이어그램입니다.

```text
      요청 (Request)
─────────>
┌────────────────────────────────┐
│           Client               │
└────────────────────────────────┘
             |
             | 1. 쿠키(idToken, accessToken, sessionId)가 포함된 API 요청
             V
┌────────────────────────────────┐
│  KeycloakAuthenticationFilter  │
└────────────────────────────────┘
             |
             | 2. 토큰 및 세션ID 추출, '미인증' Authentication 객체 생성
             |    - Principal: PreAuthenticationPrincipal (sub 포함)
             |    - Details:   RawTokens (idToken, accessToken)
             |
             V
┌────────────────────────────────┐
│     AuthenticationManager      │
└────────────────────────────────┘
             |
             | 3. Provider에게 인증 위임
             V
┌────────────────────────────────┐
│  KeycloakAuthenticationProvider│
└────────────────────────────────┘
             |
             | 4. ID Token 검증 (서명, 만료, 클레임 등)
             |
             | 5. 검증 성공 시 2가지 작업 수행
             |    a. 최종 'KeycloakPrincipal' 생성 (사용자 정보만)
             |    b. 토큰들로 'OAuth2AuthorizedClient' 객체 생성 후
             |       'OAuth2AuthorizedClientRepository'를 통해 HttpSession에 저장
             |
             V  6. '인증 완료' Authentication 객체 반환 (KeycloakPrincipal 포함)
┌────────────────────────────────┐
│  KeycloakAuthenticationFilter  │
└────────────────────────────────┘
             |
             | 7. SecurityContext에 최종 인증 정보 등록
             V
┌────────────────────────────────┐
│     SecurityContextHolder      │
└────────────────────────────────┘
             |
             | 8. 요청 처리 완료
             V
      응답 (Response)
<─────────
```

### 2. 인증 흐름 단계

1.  **토큰 추출 (in `KeycloakAuthenticationFilter`):**
    -   HTTP 요청 쿠키에서 `idToken`, `accessToken`을 읽어 `RawTokens` 객체를 생성합니다.
    -   `idToken`을 간단히 파싱하여 `sub` 클레임을 추출하고, 이를 담은 `PreAuthenticationPrincipal` 객체를 생성합니다.
    -   `PreAuthenticationPrincipal`을 Principal로, `RawTokens`를 Details로 설정하여 미인증 `KeycloakAuthentication` 객체를 생성하고 `AuthenticationManager`에 전달합니다.

2.  **인증 처리 (in `KeycloakAuthenticationProvider`):**
    -   미인증 `Authentication` 객체에서 `idToken` (`getCredentials()`)과 `RawTokens` (`getDetails()`)를 꺼냅니다.
    -   `idToken`의 유효성을 `jwtDecoder`로 검증합니다.
    -   모든 검증 성공 시:
        a. JWT 클레임을 바탕으로 최종 `KeycloakPrincipal` 객체를 생성합니다.
        b. `ClientRegistration`을 조회하고, 인증된 `KeycloakPrincipal`과 토큰들(`accessToken`, `refreshToken` 등)을 사용하여 `OAuth2AuthorizedClient` 객체를 생성합니다.
        c. 생성된 `OAuth2AuthorizedClient`를 **`oAuth2AuthorizedClientRepository`를 통해 `HttpSession`에 저장**합니다.
        d. 생성된 최종 `KeycloakPrincipal`을 담아 인증된 `KeycloakAuthentication` 객체를 생성하여 반환합니다.

3.  **Security Context 등록 (in `KeycloakAuthenticationFilter`):**
    -   `AuthenticationManager`가 인증된 `KeycloakAuthentication` 객체를 반환하면, 필터는 이 객체를 `SecurityContextHolder`에 등록합니다.

## 3. Spring Security 설정 통합

이 아키텍처에 필요한 핵심 빈(Bean)들을 `SecurityConfig`에 설정합니다.

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    // --- OAuth2AuthorizedClient 관련 빈 설정 ---

    // 1. ClientRegistration 설정 (Keycloak 클라이언트 정보)
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        ClientRegistration registration = ClientRegistration.withRegistrationId("keycloak") // ID
            .clientId("your-client-id")
            .clientSecret("your-client-secret") // 실제 값 사용
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .scope("openid", "profile", "email")
            .authorizationUri("https://<keycloak-host>/realms/<realm>/protocol/openid-connect/auth")
            .tokenUri("https://<keycloak-host>/realms/<realm>/protocol/openid-connect/token")
            .userInfoUri("https://<keycloak-host>/realms/<realm>/protocol/openid-connect/userinfo")
            .jwkSetUri(jwkSetUri) // JWK Set URI
            .userNameAttributeName(IdTokenClaimNames.SUB)
            .build();
        return new InMemoryClientRegistrationRepository(registration);
    }

    // 2. OAuth2AuthorizedClientRepository 설정
    //
    // 별도의 Bean을 등록하지 않습니다.
    // 이렇게 비워두면, `spring-boot-starter-oauth2-client` 의존성이 있을 경우
    // Spring Boot 자동 설정이 기본 구현체인 `HttpSessionOAuth2AuthorizedClientRepository`를
    // 자동으로 Bean으로 등록해줍니다. 이 클래스가 HttpSession에 토큰을 저장하는 역할을 수행합니다.
    //
    // 만약 `spring-session-data-redis` 의존성이 추가된다면,
    // Spring Boot는 자동으로 Redis 기반의 Repository를 Bean으로 등록하여 세션 클러스터링을 지원합니다.

    // --- JWT 및 커스텀 인증 Provider/Filter 설정 ---

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            JwtDecoder jwtDecoder,
            KeycloakClient keycloakClient) {
        
        KeycloakAuthenticationProvider provider = new KeycloakAuthenticationProvider(
            jwtDecoder, keycloakClient);
        return new ProviderManager(provider);
    }

    public KeycloakAuthenticationFilter keycloakAuthenticationFilter(
            AuthenticationManager authenticationManager,
            OAuth2AuthorizedClientRepository authorizedClientRepository,
            ClientRegistrationRepository clientRegistrationRepository,
            ObjectMapper objectMapper) {
        return new KeycloakAuthenticationFilter(authenticationManager, authorizedClientRepository, clientRegistrationRepository, objectMapper);
    }

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            AuthenticationManager authenticationManager,
            OAuth2AuthorizedClientRepository authorizedClientRepository,
            ClientRegistrationRepository clientRegistrationRepository,
            ObjectMapper objectMapper) throws Exception {
        http
            // SecurityContext는 HttpSessionSecurityContextRepository를 통해 HttpSession에 저장됩니다.
            .securityContext(sc -> sc
                .securityContextRepository(new HttpSessionSecurityContextRepository())
            )
            .addFilterBefore(
                keycloakAuthenticationFilter(authenticationManager, authorizedClientRepository, clientRegistrationRepository, objectMapper),
                UsernamePasswordAuthenticationFilter.class
            )
            // ... 기타 설정 ...
            ;
        return http.build();
    }
}
```

## 4. 테스트
-   **단위 테스트:** `KeycloakAuthenticationProvider`가 JWT를 검증하고, `KeycloakPrincipal`을 올바르게 생성하며, `OAuth2AuthorizedClientRepository`를 통해 토큰 저장을 위임하는지 테스트합니다.
-   **통합 테스트:** `KeycloakAuthenticationFilter`가 쿠키에서 토큰을 성공적으로 추출하고 전체 인증 흐름을 통해 `SecurityContext`에 `KeycloakAuthentication`이 등록되는지 검증합니다.

✅ **인수 조건**
-   [ ] `KeycloakAuthenticationFilter`가 HTTP 요청 쿠키에서 토큰들을 추출하여 `PreAuthenticationPrincipal`과 `RawTokens`를 포함한 미인증 `Authentication` 객체를 생성하고 `AuthenticationManager`로 전달한다.
-   [ ] `KeycloakAuthenticationProvider`가 `idToken`을 검증하고, 최종 `KeycloakPrincipal`을 생성하며, `OAuth2AuthorizedClientRepository`를 통해 `HttpSession`에 `OAuth2AuthorizedClient`를 저장한다.
-   [ ] 인증 성공 시, `KeycloakPrincipal`을 포함한 인증된 `KeycloakAuthentication` 객체가 `SecurityContext`에 성공적으로 등록된다.
-   [ ] 모든 관련 컴포넌트에 대한 단위/통합 테스트가 존재하며 모든 테스트를 통과한다.