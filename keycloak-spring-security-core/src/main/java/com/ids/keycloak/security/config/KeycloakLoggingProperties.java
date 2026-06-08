package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;

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

    /** 사용자 ID 포함 여부 (기본값: true) */
    private boolean includeUserId = true;

    /** 사용자명 포함 여부 (기본값: true) */
    private boolean includeUsername = true;

    /** 세션 ID 포함 여부 (기본값: true) */
    private boolean includeSessionId = true;
}