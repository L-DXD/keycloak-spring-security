package com.ids.keycloak.security.config;

import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.Setter;

/**
 * 정적 리소스(CSS/JS/이미지/webjars/favicon) 경로를 인증·인가에서 기본 제외하기 위한 설정입니다
 * (항목 3).
 * <p>
 * <b>배경:</b> {@code matcher.include} 기본값 {@code /**}와 {@code anyRequest().authenticated()}
 * 조합에서는 {@code /js/**}, {@code /css/**}, {@code /favicon.ico}, {@code /webjars/**} 같은 정적
 * 리소스 요청도 인증 대상이 된다. 특히 로그인 세션(OIDC 쿠키)이 있는 사용자는 정적 리소스 요청마다
 * {@code KeycloakAuthenticationFilter}가 Keycloak Introspect/UserInfo 원격 호출을 수행하게 되어
 * 불필요한 지연·장애 전파 위험이 생긴다(운영 실측 500/302 사고 원인).
 * </p>
 * <p>
 * 이 설정이 활성화(기본값)되면 아래 두 곳에 동일한 패턴이 적용된다.
 * <ul>
 *   <li>{@code authorizeHttpRequests}/{@code authorizeExchange}에 permitAll로 등록</li>
 *   <li>{@code KeycloakAuthenticationFilter}(servlet)/{@code AuthenticationWebFilter}(webflux)의
 *       인증 처리 자체를 스킵 — permitAll만으로는 필터가 여전히 실행되어 원격 호출이 발생하므로,
 *       필터 단계에서도 함께 제외해야 근본 원인이 해소된다.</li>
 * </ul>
 * </p>
 * <p>
 * 기본 패턴은 Spring Boot {@code PathRequest.toStaticResources().atCommonLocations()}가 정의하는
 * 정적 리소스 위치({@code StaticResourceLocation}: CSS/JAVA_SCRIPT/IMAGES/WEBJARS/FAVICON)와 동일한
 * 4종을 그대로 채택했다 — 임의로 새 allowlist를 만들지 않고 Spring Boot 공식 정적 리소스 규약을
 * 따르므로 과도 허용 위험이 낮다.
 * </p>
 * <p>
 * application.yaml:
 * <pre>
 * keycloak:
 *   security:
 *     static-resources:
 *       enabled: true
 *       patterns:
 *         - /css/**
 *         - /js/**
 *         - /images/**
 *         - /webjars/**
 *         - /favicon.ico
 * </pre>
 * </p>
 */
@Getter
@Setter
public class KeycloakStaticResourceProperties {

    /**
     * 정적 리소스 기본 제외 기능 활성화 여부 (기본값: {@code true}).
     * <p>
     * 이 라이브러리의 기본 SecurityFilterChain이 이미 {@code /**}를 담당하는 환경(대부분의
     * 소비자)에서 즉시 효과가 있는 안전한 기본값이다. 정적 리소스 경로를 별도 SecurityFilterChain이나
     * 커스텀 정책으로 이미 직접 관리하는 소비자는 {@code false}로 끌 수 있다.
     * </p>
     */
    private boolean enabled = true;

    /**
     * 인증·인가에서 제외할 정적 리소스 경로(Ant 패턴).
     * 기본값: Spring Boot {@code StaticResourceLocation}의 CSS/JAVA_SCRIPT/IMAGES/WEBJARS/FAVICON.
     */
    private List<String> patterns = new ArrayList<>(List.of(
        "/css/**", "/js/**", "/images/**", "/webjars/**", "/favicon.ico"));
}
