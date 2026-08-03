package com.ids.keycloak.security.config;

import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.Setter;

/**
 * 정적 리소스(CSS/JS/이미지/webjars/favicon) 경로를 인증 필터·인가에서 제외하기 위한 설정입니다
 * (항목 3, C-2 보강, C-A 회귀 수정).
 * <p>
 * <b>배경:</b> {@code matcher.include} 기본값 {@code /**}와 {@code anyRequest().authenticated()}
 * 조합에서는 {@code /js/**}, {@code /css/**}, {@code /favicon.ico}, {@code /webjars/**} 같은 정적
 * 리소스 요청도 인증 대상이 된다. 특히 로그인 세션(OIDC 쿠키)이 있는 사용자는 정적 리소스 요청마다
 * {@code KeycloakAuthenticationFilter}가 Keycloak Introspect/UserInfo 원격 호출을 수행하게 되어
 * 불필요한 지연·장애 전파 위험이 생긴다(운영 실측 500/302 사고 원인).
 * </p>
 * <p>
 * <b>C-2 (인가 확대 방지):</b> 이 설정은 서로 다른 두 축으로 분리되어 있다.
 * <ul>
 *   <li>{@link #filterSkip} (기본값 {@code true}) — {@code KeycloakAuthenticationFilter}(servlet)/
 *       {@code AuthenticationWebFilter}(webflux)의 인증 처리 자체를 스킵한다(성능 목적).</li>
 *   <li>{@link #permitAll} (기본값 {@code false}) — {@code authorizeHttpRequests}/
 *       {@code authorizeExchange}에 permitAll로 등록해 인증 자체를 면제한다. <b>명시적 opt-in만
 *       허용</b>한다: 과거 이 값이 기본 on이었을 때, {@code /images/**} 등에 컨트롤러로 보호
 *       리소스를 서빙하는 소비자가 업그레이드만으로 그 경로를 공개해버리는 인가 확대 결함이
 *       있었다.</li>
 * </ul>
 * <b>이 경로에 실제로 인증 없이 서빙해야 하는 순수 정적 파일(CSS/JS/이미지 등)만 있다는 것을
 * 확인한 경우에만 {@link #permitAll}을 켜라.</b> 컨트롤러가 매핑된 보호 리소스가 하나라도 이
 * 패턴에 겹치면 permitAll을 켜지 않아야 한다.
 * </p>
 * <p>
 * <b>C-A (회귀 수정 — 정적 리소스 무한 리다이렉트 루프):</b> {@link #isFilterSkipEffective()}는
 * 더 이상 {@link #filterSkip} 단독으로 결정되지 않고 <b>{@link #permitAll}에 종속</b>된다
 * ({@code enabled && filterSkip && permitAll}). "인증 스킵"과 "인가 면제"는 독립적일 수 없기
 * 때문이다 — {@code permitAll=false}(기본값)인 상태에서 필터만 스킵하면, 이 경로는
 * {@code anyRequest().authenticated()}에 의해 여전히 보호되지만 {@code KeycloakAuthenticationFilter}
 * (servlet)/{@code AuthenticationWebFilter}(webflux)가 OIDC 쿠키를 아예 검사하지 않으므로 SecurityContext는
 * 항상 미인증 상태로 고정된다. 그 결과 (유효한 로그인 세션이 있는 사용자를 포함해) 모든 요청이
 * {@code KeycloakAuthenticationEntryPoint}의 OAuth2 로그인 리다이렉트로 보내지고, SSO 세션이 있으면
 * 즉시 콜백되어 다시 같은 정적 리소스로 리다이렉트되는 무한 루프가 발생한다(로그인 사용자의 CSS/JS/이미지가
 * 전부 깨지고, 병렬 정적 리소스 요청이 SavedRequest/authorization_request를 서로 덮어써
 * {@code authorization_request_not_found}까지 유발). {@code permitAll=true}(명시적 opt-in)일 때만
 * 필터 스킵의 성능 이점을 실제로 안전하게 누릴 수 있다 — 그 경우 인가 자체가 이 경로를 요구하지 않으므로
 * 필터가 인증을 계산하지 않아도 무한 루프가 생기지 않는다. 기본값({@code filterSkip=true,
 * permitAll=false}) 조합에서는 {@link #isFilterSkipEffective()}가 이제 {@code false}를 반환해,
 * 필터가 정적 리소스도 OIDC 쿠키로 정상적으로 재검증한다(로그인 사용자는 통과, 완전 미인증
 * 사용자는 SSO 로그인 플로우가 정상적으로 1회 완료된다 — 루프가 아닌 정상 종결).
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
 *       filter-skip: true    # permit-all=true일 때만 실제로 적용됨(C-A) — 성능 opt-in
 *       permit-all: false    # 인가까지 면제하려면 명시적으로 true (보호 리소스가 없을 때만!)
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
     * 정적 리소스 처리 기능 전체를 아우르는 마스터 스위치 (기본값: {@code true}).
     * <p>
     * {@code false}면 {@link #filterSkip}/{@link #permitAll} 설정과 무관하게 두 축 모두 비활성화된다
     * (필터 스킵도, permitAll도 적용되지 않음). 정적 리소스 경로를 별도 SecurityFilterChain이나
     * 커스텀 정책으로 이미 직접 관리하는 소비자는 {@code false}로 끌 수 있다.
     * </p>
     */
    private boolean enabled = true;

    /**
     * {@code KeycloakAuthenticationFilter}(servlet)/{@code AuthenticationWebFilter}(webflux)의
     * 인증 처리 자체를 스킵할지 여부 (기본값: {@code true}).
     * <p>
     * <b>C-A:</b> 이 값은 더 이상 단독으로 효력을 갖지 않는다. {@link #isFilterSkipEffective()}는
     * {@link #permitAll}이 함께 {@code true}일 때만 실제로 필터를 스킵한다 — {@code permitAll=false}
     * (인가는 여전히 이 경로를 보호)인 상태에서 필터만 스킵하면 SecurityContext가 영구적으로
     * 미인증 상태가 되어 무한 리다이렉트 루프를 유발하기 때문이다(클래스 Javadoc의 C-A 참고).
     * 성능 목적의 최적화이며, 실제 적용 여부는 {@link #permitAll}에 종속된다.
     * </p>
     */
    private boolean filterSkip = true;

    /**
     * {@code authorizeHttpRequests}/{@code authorizeExchange}에 permitAll로 등록할지 여부
     * (기본값: {@code false}, {@link #enabled}가 true일 때만 적용).
     * <p>
     * <b>명시적 opt-in만 허용한다(C-2).</b> 이 값을 켜면 {@link #patterns}에 매칭되는 모든 경로가
     * 인증 없이 접근 가능해진다. 해당 경로에 컨트롤러로 매핑된 보호 리소스가 없다는 것을 확인한
     * 경우에만 {@code true}로 설정하라. 순수 정적 파일(CSS/JS/이미지 등)만 서빙하는 일반적인
     * 소비자는 이 값을 켜야 정적 자산이 로그인 없이 로드된다.
     * </p>
     */
    private boolean permitAll = false;

    /**
     * 인증 필터·인가에서 제외할 정적 리소스 경로(Ant 패턴).
     * 기본값: Spring Boot {@code StaticResourceLocation}의 CSS/JAVA_SCRIPT/IMAGES/WEBJARS/FAVICON.
     */
    private List<String> patterns = new ArrayList<>(List.of(
        "/css/**", "/js/**", "/images/**", "/webjars/**", "/favicon.ico"));

    /**
     * {@link #enabled}, {@link #filterSkip}, {@link #permitAll}이 모두 {@code true}인지
     * 여부입니다 (C-A).
     * <p>
     * {@link #permitAll}을 의도적으로 포함시킨다 — "인증 스킵"과 "인가 면제"는 독립적으로 켤 수
     * 없다(클래스 Javadoc의 C-A 참고). {@code permitAll=false}인 상태에서 {@link #filterSkip}만
     * {@code true}로 설정했더라도, 이 메서드는 {@code false}를 반환해 필터가 정상적으로 OIDC
     * 쿠키 인증을 계산하도록 강제한다.
     * </p>
     */
    public boolean isFilterSkipEffective() {
        return enabled && filterSkip && permitAll;
    }

    /**
     * {@link #enabled}와 {@link #permitAll}이 모두 true인지 여부입니다.
     */
    public boolean isPermitAllEffective() {
        return enabled && permitAll;
    }
}
