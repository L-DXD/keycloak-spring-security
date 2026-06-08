package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

/**
 * Keycloak Security 로깅 관련 설정을 담는 Properties 클래스입니다.
 * <p>
 * 모든 필드는 개별적으로 활성화/비활성화가 가능합니다.
 * </p>
 */
@Getter
@Setter
public class KeycloakLoggingProperties {

    /** 요청 추적 ID 포함 여부 (기본값: true) */
    private boolean includeTraceId = true;

    /** HTTP 메서드 포함 여부 (기본값: true) */
    private boolean includeHttpMethod = true;

    /** 요청 URI 포함 여부 (기본값: true) */
    private boolean includeRequestUri = true;

    /** 쿼리 스트링 포함 여부 (기본값: false) */
    private boolean includeQueryString = false;

    /** 클라이언트 IP 포함 여부 (기본값: true) */
    private boolean includeClientIp = true;

    /** User-Agent 포함 여부 (기본값: true) — 마스킹 + 256자 제한 적용 */
    private boolean includeUserAgent = true;

    /** 쿼리 스트링 최대 길이 (초과 시 truncate, 기본값: 512) */
    private int maxQueryLength = 512;

    /** User-Agent 최대 길이 (초과 시 truncate, 기본값: 256) */
    private int maxUserAgentLength = 256;

    /** 응답 헤더 X-Request-Id 로 traceId 회신 여부 (기본값: true) */
    private boolean returnTraceIdHeader = true;

    /**
     * 응답 메트릭(status, durationMs) 포함 + "request completed" 종료 로그 발행 여부 (기본값: false).
     * <p>
     * Tomcat AccessLog와 정보가 중복되므로 기본 off. AccessLog 미사용/일원화 환경에서만 켭니다.
     * </p>
     */
    private boolean includeResponseMetrics = false;

    /**
     * MDC 필터를 적용하지 않을 경로 패턴 (Ant 패턴, 기본값: {@code ["/actuator/**"]}).
     * <p>
     * actuator 헬스/메트릭 스크랩(Prometheus 폴링)의 요청 로그 노이즈를 제거합니다.
     * </p>
     */
    private List<String> excludePatterns = new ArrayList<>(List.of("/actuator/**"));

    /** 사용자 ID 포함 여부 (기본값: true) */
    private boolean includeUserId = true;

    /** 사용자명 포함 여부 (기본값: true) */
    private boolean includeUsername = true;

    /** 세션 ID 포함 여부 (기본값: true) */
    private boolean includeSessionId = true;
}