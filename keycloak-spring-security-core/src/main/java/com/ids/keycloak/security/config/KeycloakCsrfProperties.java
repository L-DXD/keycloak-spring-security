package com.ids.keycloak.security.config;

import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.Setter;

/**
 * CSRF(Cross-Site Request Forgery) 보호 관련 설정을 담는 Properties 클래스입니다.
 * <p>
 * application.yaml:
 * <pre>
 * keycloak:
 *   security:
 *     csrf:
 *       enabled: true                     # 기본값: true (기존 동작 유지)
 *       ignore-paths:                     # 추가 CSRF 면제 경로
 *         - /api/**
 *         - /webhook/**
 * </pre>
 * </p>
 * <p>
 * CSRF는 보안상 기본 활성화(true)입니다.
 * 비활성화하려면 명시적으로 {@code enabled: false}를 설정해야 합니다.
 * </p>
 * <p>
 * {@code ignore-paths}는 기존 하드코딩된 면제 경로(로그아웃, 토큰 발급 등)에 추가로 적용됩니다.
 * Ant 패턴을 지원합니다 (예: {@code /api/**}).
 * </p>
 * <p>
 * <b>보안 경고 (Basic Auth와 CSRF):</b> {@code basic-auth.enabled=true}인 경우에도
 * {@code Authorization: Basic} 헤더 보유 여부만으로 CSRF가 자동 면제되지 않습니다.
 * HTTP Basic 자격증명은 브라우저가 origin 단위로 캐시하여 이후 요청(cross-origin 폼 제출 포함)에
 * 자동 재전송할 수 있는 ambient credential이므로, Authorization 헤더 존재는 "비-브라우저 요청"의
 * 증거로 사용할 수 없습니다(CWE-352). Basic Auth를 사용하는 머신 전용 API 경로에서 CSRF 면제가
 * 필요하다면 반드시 {@code ignore-paths}에 해당 경로를 명시적으로 등록하세요. 브라우저에서 접근
 * 가능한 경로는 Basic Auth 사용 여부와 무관하게 CSRF 보호를 유지해야 합니다.
 * </p>
 * <p>
 * <b>{@code keycloak.security.matcher.exclude}와 CSRF 토큰:</b> {@code matcher.exclude}로 제외한
 * 경로는 Keycloak {@code SecurityFilterChain} 자체가 적용되지 않아 {@code CsrfFilter}도 동작하지
 * 않습니다. 기본 저장소({@link CsrfTokenRepositoryMode#SESSION})는 토큰을 서버 세션에만 저장하므로
 * 그 경로에서는 CSRF 토큰을 읽거나 심을 수 없습니다. exclude된 경로에서도 CSRF 토큰이 필요하다면
 * {@code token-repository: COOKIE}로 전환하세요. 자세한 내용은 {@link CsrfTokenRepositoryMode} 참고.
 * </p>
 */
@Getter
@Setter
public class KeycloakCsrfProperties {

    /**
     * CSRF 보호 활성화 여부.
     * 기본값: true (보안상 기본 활성화, 다른 Properties의 기본값 false와 다름)
     */
    private boolean enabled = true;

    /**
     * 추가 CSRF 면제 경로 목록.
     * Ant 패턴을 지원합니다 (예: /api/**, /webhook/**).
     * 기존 하드코딩 면제 경로(로그아웃, 토큰 발급 등)에 추가로 적용됩니다.
     */
    private List<String> ignorePaths = new ArrayList<>();

    /**
     * CSRF 토큰 저장소 종류. 기본값: {@link CsrfTokenRepositoryMode#SESSION}(기존 동작 유지).
     * <p>
     * {@code keycloak.security.matcher.exclude} 경로에서도 CSRF 토큰이 필요하면
     * {@link CsrfTokenRepositoryMode#COOKIE}로 전환하세요. 자세한 배경은
     * {@link CsrfTokenRepositoryMode} Javadoc 참고.
     * </p>
     */
    private CsrfTokenRepositoryMode tokenRepository = CsrfTokenRepositoryMode.SESSION;
}
