package com.ids.keycloak.security.autoconfigure;

import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

import com.ids.keycloak.security.config.KeycloakSecurityConfigurationException;

/**
 * 설정이 잘못돼 기동하지 못했을 때, 스택 트레이스 대신 잘못된 설정 이름과 고칠 곳을 보여 준다 (CONF-02~04).
 */
public class KeycloakSecurityConfigurationFailureAnalyzer extends AbstractFailureAnalyzer<KeycloakSecurityConfigurationException> {

    @Override
    protected FailureAnalysis analyze(Throwable rootFailure, KeycloakSecurityConfigurationException cause) {
        return new FailureAnalysis(cause.getMessage(),
            "application.yml(또는 환경 변수)에서 위 설정을 고치세요. 키는 'openssl rand -base64 32'로 만들어 비밀 저장소에 둡니다. "
                + "설정 표: https://github.com/L-DXD/keycloak-spring-security (docs/v3/01-설계.md 6절)",
            cause);
    }
}
