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

    /** 사용자 ID 포함 여부 (기본값: true) */
    private boolean includeUserId = true;

    /** 사용자명 포함 여부 (기본값: true) */
    private boolean includeUsername = true;

    /** 세션 ID 포함 여부 (기본값: true) */
    private boolean includeSessionId = true;
}