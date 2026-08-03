package com.ids.keycloak.security.config;

/**
 * {@code HttpSecurity#securityContext(...)}에 등록할 {@code SecurityContextRepository} 종류를
 * 선택하는 열거형입니다.
 *
 * <p><b>배경:</b> 이 라이브러리는 {@code KeycloakAuthenticationFilter}가 매 요청마다 OIDC 쿠키(및
 * HTTP Session의 Refresh Token)로부터 인증을 다시 계산하므로, 기본적으로는 Spring Security의
 * {@code SecurityContext}를 세션에 영속시키지 않아도 됩니다({@link #NULL}). 다만
 * {@code SecurityContextHolderFilter}는 매 요청 시작 시 등록된 repository로부터 얻은 지연(lazy)
 * SecurityContext를 무조건 {@code SecurityContextHolder}에 설정하므로({@code
 * ThreadLocalSecurityContextHolderStrategy#setDeferredContext}가 이전 값을 무조건 덮어씀),
 * {@code NULL} 상태에서는 이 필터보다 앞서 실행되는 필터(예: 애플리케이션이 직접 등록한
 * {@code FilterRegistrationBean} 기반 핸드오프 필터)가 세워둔 인증이 있더라도 항상 빈 컨텍스트로
 * 대체됩니다. 그 인증이 애초에 세션에 저장되어 있지 않다면 이 라이브러리 체인 안에서 복구할 수 없고,
 * 소비자는 결과적으로 해당 경로를 이 라이브러리의 {@code securityMatcher}에서 완전히 제외하는 우회를
 * 하게 됩니다.</p>
 *
 * <p>이 프로퍼티는 그 repository를 교체 가능하게 하여, 앞단 필터·핸드오프 인증을 세션을 통해 보존해야
 * 하는 소비자가 {@code securityMatcher} 우회 없이 이 라이브러리의 필터 체인을 그대로 탈 수 있도록
 * 합니다.</p>
 *
 * <pre>
 * keycloak:
 *   security:
 *     authentication:
 *       security-context-repository: HTTP_SESSION
 * </pre>
 */
public enum SecurityContextRepositoryMode {

    /**
     * {@link org.springframework.security.web.context.NullSecurityContextRepository}를 사용합니다.
     * <b>기본값(기존 동작 유지)</b>입니다.
     * <p>
     * {@code SecurityContext}를 어디에도 저장·조회하지 않습니다. OIDC 쿠키 인증은
     * {@code KeycloakAuthenticationFilter}가 매 요청 재계산하므로 영향이 없지만, 이 라이브러리의
     * 필터 체인보다 앞서 실행되는 필터가 세워둔 인증은 {@code SecurityContextHolderFilter} 진입 시
     * 무조건 소거됩니다(세션에도 없으므로 복구 불가).
     * </p>
     */
    NULL,

    /**
     * {@link org.springframework.security.web.context.HttpSessionSecurityContextRepository}를
     * 사용합니다.
     * <p>
     * {@code SecurityContext}를 HTTP Session의 {@code SPRING_SECURITY_CONTEXT} 속성에
     * 저장·조회합니다. {@code AbstractAuthenticationProcessingFilter} 기반 인증(OAuth2 Login 등)은
     * 성공 시 자동으로 이 repository에 저장되며, 앞단 필터·핸드오프 필터가 동일한 세션 키에 인증을
     * 직접 저장해두면 {@code SecurityContextHolderFilter}가 그 인증을 세션에서 복원하여 유지합니다.
     * </p>
     * <p><b>앞단 필터·핸드오프 인증을 보존하려면 이 값을 사용하세요.</b></p>
     */
    HTTP_SESSION,

    /**
     * {@link org.springframework.security.web.context.RequestAttributeSecurityContextRepository}와
     * {@link org.springframework.security.web.context.HttpSessionSecurityContextRepository}를
     * {@link org.springframework.security.web.context.DelegatingSecurityContextRepository}로 조합해
     * 사용합니다. Spring Security가 {@code securityContext(...)}를 전혀 커스터마이즈하지 않았을 때
     * 적용하는 기본 조합과 동일합니다.
     * <p>
     * 요청 속성(request attribute)에도 저장하므로, 동일 요청 내 forward/error 디스패치 등으로
     * {@code SecurityContextHolderFilter}를 다시 통과하는 경우에도 컨텍스트가 유지됩니다. 세션 저장은
     * {@link #HTTP_SESSION}과 동일합니다.
     * </p>
     */
    DELEGATING
}
