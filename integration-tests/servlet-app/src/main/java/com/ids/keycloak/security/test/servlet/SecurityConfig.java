package com.ids.keycloak.security.test.servlet;

import com.ids.keycloak.security.config.KeycloakOidcLoginConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .apply(new KeycloakOidcLoginConfigurer());

        return http.build();
    }

    /**
     * 리프레시 토큰을 사용하여 액세스 토큰을 갱신하는 데 사용되는 클라이언트를 Bean으로 등록합니다.
     * Deprecated된 DefaultRefreshTokenTokenResponseClient 대신 RestClientRefreshTokenTokenResponseClient를 사용합니다.
     * @return OAuth2AccessTokenResponseClient for refresh token grants
     */
    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshTokenTokenResponseClient() {
        return new RestClientRefreshTokenTokenResponseClient();
    }
}
