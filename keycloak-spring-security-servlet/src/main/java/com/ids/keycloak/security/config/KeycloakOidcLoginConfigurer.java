package com.ids.keycloak.security.config;

import com.ids.keycloak.security.web.OidcSessionValidationFilter;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.authentication.logout.LogoutFilter;

/**
 * Keycloak OIDC 로그인을 위한 HTTP 보안 설정을 구성하는 클래스입니다.
 * 이 Configurer는 {@link OidcSessionValidationFilter}를 필터 체인에 추가하여
 * 세션 기반 OIDC 인증의 유효성을 매 요청마다 검증합니다.
 */
public class KeycloakOidcLoginConfigurer extends AbstractHttpConfigurer<KeycloakOidcLoginConfigurer, HttpSecurity> {

    /**
     * {@link HttpSecurity} 초기화 시 표준 OIDC `oauth2Login()` 흐름을 활성화합니다.
     * @param http 구성할 {@link HttpSecurity} 인스턴스
     * @throws Exception 초기화 중 오류 발생 시
     */
    @Override
    public void init(HttpSecurity http) throws Exception {
        // 표준 OIDC oauth2Login() 흐름 활성화
        http.oauth2Login();
    }

    /**
     * {@link HttpSecurity} 구성 시 커스텀 필터인 {@link OidcSessionValidationFilter}를 추가합니다.
     * 이 필터는 Spring의 ApplicationContext에서 필요한 의존성을 주입받아 생성됩니다.
     * @param http 구성할 {@link HttpSecurity} 인스턴스
     * @throws Exception 구성 중 오류 발생 시
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);

        // ApplicationContext에서 필요한 빈들을 가져옵니다.
        OAuth2AuthorizedClientService authorizedClientService = applicationContext.getBean(OAuth2AuthorizedClientService.class);
        @SuppressWarnings("unchecked")
        OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> accessTokenResponseClient =
                applicationContext.getBean(OAuth2AccessTokenResponseClient.class);

        // OidcSessionValidationFilter 인스턴스 생성
        OidcSessionValidationFilter oidcSessionValidationFilter = new OidcSessionValidationFilter(
                authorizedClientService,
                accessTokenResponseClient
        );

        // OidcSessionValidationFilter를 LogoutFilter 뒤에 추가합니다.
        // 세션이 유효한 상태에서 토큰의 유효성을 검증해야 하므로,
        // 세션을 무효화하는 LogoutFilter 이후에 위치시키는 것이` 적절합니다.
        // 정확한 필터 순서는 OAuth2LoginAuthenticationFilter 이후, 인가(Authorization) 필터 이전입니다.
        // LogoutFilter 뒤는 일반적으로 이 조건을 만족시킵니다.
        http.addFilterAfter(oidcSessionValidationFilter, LogoutFilter.class);
    }
}