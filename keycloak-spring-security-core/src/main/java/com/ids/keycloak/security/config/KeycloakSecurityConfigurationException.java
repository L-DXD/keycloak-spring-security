package com.ids.keycloak.security.config;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 설정이 잘못돼서 기동하지 않는다. 잘못된 설정 이름과 이유를 모두 담는다 (CONF-02~04).
 * <p>
 * 비밀값(키, client secret)은 메시지에 넣지 않는다.
 */
public class KeycloakSecurityConfigurationException extends IllegalStateException {

    private final List<Problem> problems;

    public KeycloakSecurityConfigurationException(List<Problem> problems) {
        super(describe(problems));
        this.problems = List.copyOf(problems);
    }

    /** 잘못된 설정들. 비어 있지 않다. */
    public List<Problem> getProblems() {
        return problems;
    }

    private static String describe(List<Problem> problems) {
        return "keycloak-spring-security 설정이 잘못됐습니다:" + problems.stream()
            .map(p -> "\n - " + p.property() + ": " + p.message())
            .collect(Collectors.joining());
    }

    /**
     * 잘못된 설정 하나.
     *
     * @param property 설정 이름. 예: {@code keycloak.security.frontend.base-url}
     * @param message  무엇이 왜 잘못됐는지
     */
    public record Problem(String property, String message) {
    }
}
