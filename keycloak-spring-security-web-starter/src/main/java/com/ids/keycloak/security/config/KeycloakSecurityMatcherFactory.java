package com.ids.keycloak.security.config;

import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.List;

/**
 * {@link KeycloakMatcherProperties}의 include/exclude(Ant 패턴)를 {@link RequestMatcher}로 변환하는 팩토리입니다.
 * <p>
 * Keycloak {@code SecurityFilterChain}의 {@code securityMatcher}로 사용되어, 사용자가 등록한 다른
 * {@code SecurityFilterChain}과 담당 경로를 분리합니다(Fail-Open 방지).
 * </p>
 * <ul>
 *   <li>exclude가 비어 있으면 {@code (include)} OR 매처를 반환합니다.</li>
 *   <li>exclude가 있으면 {@code (include) AND NOT(exclude)} 형태로 결합합니다.</li>
 * </ul>
 * <p>
 * RequestMatcher 조합은 spring-security-web 의존성이 있는 web-starter에서 수행합니다.
 * (core 모듈은 순수 로직 모듈로 Servlet/Web 의존성을 갖지 않으므로 Properties에 변환 로직을 두지 않습니다.)
 * </p>
 * <p>
 * <b>주의(요구사항 4번):</b> 이 매처가 {@code false}를 반환하는 요청(즉 exclude에 매칭된 경로)은
 * {@code http.securityMatcher(this.from(...))}에 의해 Keycloak {@code SecurityFilterChain} 자체가
 * 적용되지 않는다. 인증뿐 아니라 이 체인이 등록하는 CSRF·예외 처리·MDC 로깅 등도 전부 미적용되므로,
 * "인증만 제외"가 필요하다면 이 매처(exclude)가 아니라
 * {@code keycloak.security.authentication.permit-all-paths}(authorizeHttpRequests permitAll)를
 * 사용해야 한다. 자세한 배경은 {@link KeycloakMatcherProperties#getExclude()} Javadoc 참고.
 * </p>
 */
final class KeycloakSecurityMatcherFactory {

    private KeycloakSecurityMatcherFactory() {
    }

    static RequestMatcher from(KeycloakMatcherProperties properties) {
        RequestMatcher includeMatcher = toOrMatcher(properties.getInclude());

        List<String> exclude = properties.getExclude();
        if (exclude == null || exclude.isEmpty()) {
            return includeMatcher;
        }

        RequestMatcher excludeMatcher = toOrMatcher(exclude);
        return new AndRequestMatcher(includeMatcher, new NegatedRequestMatcher(excludeMatcher));
    }

    private static RequestMatcher toOrMatcher(List<String> patterns) {
        List<RequestMatcher> matchers = new ArrayList<>();
        for (String pattern : patterns) {
            matchers.add(new AntPathRequestMatcher(pattern));
        }
        // 단일 패턴이면 OrRequestMatcher(빈/단일 요소 시 예외)로 감싸지 않고 그대로 반환
        return matchers.size() == 1 ? matchers.get(0) : new OrRequestMatcher(matchers);
    }
}
