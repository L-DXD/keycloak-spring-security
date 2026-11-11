package com.ids.keycloak.security.config;

import java.util.List;
import java.util.Objects;

/**
 * MDC 로깅 설정 ({@code keycloak.security.logging.*}). 이름과 기본값은 v2와 같다.
 *
 * @param includeTraceId         {@code traceId} (기본 켬)
 * @param includeHttpMethod      {@code httpMethod} (기본 켬)
 * @param includeRequestUri      {@code requestUri} (기본 켬)
 * @param includeQueryString     {@code queryString} (기본 끔)
 * @param includeClientIp        {@code clientIp} (기본 켬)
 * @param includeUserAgent       {@code userAgent} (기본 켬)
 * @param maxQueryLength         쿼리 문자열 최대 길이 (기본 512)
 * @param maxUserAgentLength     User-Agent 최대 길이 (기본 256)
 * @param returnTraceIdHeader    응답 {@code X-Request-Id}로 traceId를 돌려주는가 (기본 켬)
 * @param includeResponseMetrics {@code status}·{@code durationMs}와 "request completed" 로그 (기본 끔. 접근 로그와 겹친다)
 * @param excludePatterns        MDC 필터를 쓰지 않는 경로 (기본 {@code /actuator/**})
 * @param includeUserId          {@code userId} (기본 켬)
 * @param includeUsername        {@code username} (기본 켬)
 * @param includeSessionId       {@code sessionId} (기본 켬)
 */
public record KeycloakLoggingSettings(boolean includeTraceId, boolean includeHttpMethod, boolean includeRequestUri,
                                      boolean includeQueryString, boolean includeClientIp, boolean includeUserAgent,
                                      int maxQueryLength, int maxUserAgentLength, boolean returnTraceIdHeader,
                                      boolean includeResponseMetrics, List<String> excludePatterns, boolean includeUserId,
                                      boolean includeUsername, boolean includeSessionId) {

    /** 길이 제한의 상한. */
    public static final int MAX_LENGTH = 8192;

    public KeycloakLoggingSettings {
        excludePatterns = List.copyOf(Objects.requireNonNull(excludePatterns, "excludePatterns"));
    }

    /** v2와 같은 기본값. */
    public static KeycloakLoggingSettings defaults() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    /** 이 값에서 하나만 바꿀 때. */
    public Builder toBuilder() {
        return new Builder().includeTraceId(includeTraceId).includeHttpMethod(includeHttpMethod).includeRequestUri(includeRequestUri)
            .includeQueryString(includeQueryString).includeClientIp(includeClientIp).includeUserAgent(includeUserAgent)
            .maxQueryLength(maxQueryLength).maxUserAgentLength(maxUserAgentLength).returnTraceIdHeader(returnTraceIdHeader)
            .includeResponseMetrics(includeResponseMetrics).excludePatterns(excludePatterns).includeUserId(includeUserId)
            .includeUsername(includeUsername).includeSessionId(includeSessionId);
    }

    public static class Builder {

        private boolean includeTraceId = true;
        private boolean includeHttpMethod = true;
        private boolean includeRequestUri = true;
        private boolean includeQueryString;
        private boolean includeClientIp = true;
        private boolean includeUserAgent = true;
        private int maxQueryLength = 512;
        private int maxUserAgentLength = 256;
        private boolean returnTraceIdHeader = true;
        private boolean includeResponseMetrics;
        private List<String> excludePatterns = List.of("/actuator/**");
        private boolean includeUserId = true;
        private boolean includeUsername = true;
        private boolean includeSessionId = true;

        protected Builder() {
        }

        public Builder includeTraceId(boolean value) {
            this.includeTraceId = value;
            return this;
        }

        public Builder includeHttpMethod(boolean value) {
            this.includeHttpMethod = value;
            return this;
        }

        public Builder includeRequestUri(boolean value) {
            this.includeRequestUri = value;
            return this;
        }

        public Builder includeQueryString(boolean value) {
            this.includeQueryString = value;
            return this;
        }

        public Builder includeClientIp(boolean value) {
            this.includeClientIp = value;
            return this;
        }

        public Builder includeUserAgent(boolean value) {
            this.includeUserAgent = value;
            return this;
        }

        public Builder maxQueryLength(int value) {
            this.maxQueryLength = value;
            return this;
        }

        public Builder maxUserAgentLength(int value) {
            this.maxUserAgentLength = value;
            return this;
        }

        public Builder returnTraceIdHeader(boolean value) {
            this.returnTraceIdHeader = value;
            return this;
        }

        public Builder includeResponseMetrics(boolean value) {
            this.includeResponseMetrics = value;
            return this;
        }

        public Builder excludePatterns(List<String> value) {
            this.excludePatterns = value == null ? List.of() : List.copyOf(value);
            return this;
        }

        public Builder includeUserId(boolean value) {
            this.includeUserId = value;
            return this;
        }

        public Builder includeUsername(boolean value) {
            this.includeUsername = value;
            return this;
        }

        public Builder includeSessionId(boolean value) {
            this.includeSessionId = value;
            return this;
        }

        /** 값 검사는 {@link KeycloakSecuritySettings.Builder#build()}가 다른 설정과 같이 한다. */
        public KeycloakLoggingSettings build() {
            return new KeycloakLoggingSettings(includeTraceId, includeHttpMethod, includeRequestUri, includeQueryString, includeClientIp,
                includeUserAgent, maxQueryLength, maxUserAgentLength, returnTraceIdHeader, includeResponseMetrics, excludePatterns,
                includeUserId, includeUsername, includeSessionId);
        }
    }
}
