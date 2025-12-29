package com.ids.keycloak.security.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

/**
 * Keycloak 관련 보안 설정을 HttpSecurity에 적용하는 Configurer 스켈레톤
 */
public class KeycloakHttpConfigurer extends AbstractHttpConfigurer<KeycloakHttpConfigurer, HttpSecurity> {

    // 정적 팩토리 메서드
    public static KeycloakHttpConfigurer keycloak() {
        return new KeycloakHttpConfigurer();
    }

    @Override
    public void init(HttpSecurity builder) throws Exception {
        // TODO: 인증 및 인가 필터 초기화 로직 구현 예정
        super.init(builder);
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        // TODO: 필터 체인에 필터 추가 및 설정 로직 구현 예정
        super.configure(builder);
    }
}
