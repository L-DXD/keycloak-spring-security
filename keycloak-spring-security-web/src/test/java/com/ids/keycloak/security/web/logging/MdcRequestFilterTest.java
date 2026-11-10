package com.ids.keycloak.security.web.logging;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import com.ids.keycloak.security.config.KeycloakLoggingSettings;
import com.ids.keycloak.security.logging.DefaultPiiMaskingSanitizer;
import com.ids.keycloak.security.logging.LoggingContextKeys;
import com.ids.keycloak.security.logging.LoggingValueSanitizer;
import com.ids.keycloak.security.logging.NoOpLoggingValueSanitizer;

import jakarta.servlet.ServletException;

/** EVT-03: v2 MdcRequestFilterTest를 Mockito 없이 옮겼다. 체인 안에서 MDC를 떠서 본다. v3에서 더한 것은 표시했다. */
class MdcRequestFilterTest {

    private final WebMdcContextAccessor accessor = new WebMdcContextAccessor();
    private MockHttpServletRequest request = request("/api/test");
    private final MockHttpServletResponse response = new MockHttpServletResponse();
    private Map<String, String> seen;

    @AfterEach
    void tearDown() {
        MDC.clear();
    }

    private static MockHttpServletRequest request(String uri) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", uri);
        request.setRemoteAddr("127.0.0.1");
        return request;
    }

    private MdcRequestFilter filter(KeycloakLoggingSettings settings) {
        return filter(settings, 0, new NoOpLoggingValueSanitizer());
    }

    private MdcRequestFilter filter(KeycloakLoggingSettings settings, int trustedProxyCount, LoggingValueSanitizer sanitizer) {
        return new MdcRequestFilter(accessor, settings, trustedProxyCount, sanitizer);
    }

    private Map<String, String> run(MdcRequestFilter filter) throws ServletException, IOException {
        filter.doFilter(request, response, (req, res) -> {
            Map<String, String> copy = MDC.getCopyOfContextMap();
            seen = copy == null ? new HashMap<>() : new HashMap<>(copy);
        });
        return seen;
    }

    private Map<String, String> run(KeycloakLoggingSettings settings) throws ServletException, IOException {
        return run(filter(settings));
    }

    private static KeycloakLoggingSettings.Builder settings() {
        return KeycloakLoggingSettings.builder();
    }

    @Nested
    @DisplayName("MDC 키")
    class Keys {

        @Test
        @DisplayName("기본 설정이면 traceId·httpMethod·requestUri·clientIp가 들어가고, 요청이 끝나면 지운다")
        void defaults() throws Exception {
            request.addHeader("X-Request-Id", "trace-123");

            Map<String, String> mdc = run(KeycloakLoggingSettings.defaults());

            assertThat(mdc).containsEntry(LoggingContextKeys.TRACE_ID, "trace-123")
                .containsEntry(LoggingContextKeys.HTTP_METHOD, "GET")
                .containsEntry(LoggingContextKeys.REQUEST_URI, "/api/test")
                .containsEntry(LoggingContextKeys.CLIENT_IP, "127.0.0.1")
                .doesNotContainKeys(LoggingContextKeys.QUERY_STRING, LoggingContextKeys.STATUS, LoggingContextKeys.DURATION_MS);
            assertThat(MDC.getCopyOfContextMap()).as("요청이 끝나면 비어 있다").isNullOrEmpty();
        }

        @Test
        @DisplayName("쿼리 문자열은 켰을 때만 넣는다")
        void queryString() throws Exception {
            request.setQueryString("param=value");

            assertThat(run(KeycloakLoggingSettings.defaults())).doesNotContainKey(LoggingContextKeys.QUERY_STRING);
            assertThat(run(settings().includeQueryString(true).build())).containsEntry(LoggingContextKeys.QUERY_STRING, "param=value");
        }

        @Test
        @DisplayName("clientIp를 끄면 넣지 않는다")
        void clientIpOff() throws Exception {
            assertThat(run(settings().includeClientIp(false).build())).doesNotContainKey(LoggingContextKeys.CLIENT_IP);
        }

        @Test
        @DisplayName("X-Request-Id가 없으면 새 UUID")
        void newTraceId() throws Exception {
            assertThat(run(KeycloakLoggingSettings.defaults()).get(LoggingContextKeys.TRACE_ID))
                .matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
        }

        @Test
        @DisplayName("(v3) X-Request-Id에 줄바꿈·공백·긴 값이 있으면 쓰지 않고 새 UUID (로그 끼워 넣기 방지)")
        void badTraceId() throws Exception {
            for (String bad : List.of("a\r\nFAKE log", "a b", "x".repeat(129), "<script>")) {
                request = request("/api/test");
                request.addHeader("X-Request-Id", bad);
                String traceId = run(KeycloakLoggingSettings.defaults()).get(LoggingContextKeys.TRACE_ID);
                assertThat(traceId).isNotEqualTo(bad).hasSize(36);
            }
        }

        @Test
        @DisplayName("trusted-proxy-count가 0이면 X-Forwarded-For를 보지 않는다")
        void xffIgnored() throws Exception {
            request.addHeader("X-Forwarded-For", "10.0.0.1, 10.0.0.2");
            request.setRemoteAddr("192.168.1.1");

            assertThat(run(KeycloakLoggingSettings.defaults())).containsEntry(LoggingContextKeys.CLIENT_IP, "192.168.1.1");
        }

        @Test
        @DisplayName("trusted-proxy-count가 1이면 믿는 프록시가 붙인 값(맨 오른쪽)")
        void xffTrusted() throws Exception {
            request.addHeader("X-Forwarded-For", "fake, 203.0.113.7");
            request.setRemoteAddr("172.16.0.1");

            assertThat(run(filter(KeycloakLoggingSettings.defaults(), 1, new NoOpLoggingValueSanitizer())))
                .containsEntry(LoggingContextKeys.CLIENT_IP, "203.0.113.7");
        }
    }

    @Nested
    @DisplayName("X-Request-Id 응답")
    class ResponseHeader {

        @Test
        @DisplayName("기본은 응답 헤더로 traceId를 돌려준다")
        void returned() throws Exception {
            request.addHeader("X-Request-Id", "trace-abc");
            run(KeycloakLoggingSettings.defaults());
            assertThat(response.getHeader("X-Request-Id")).isEqualTo("trace-abc");
        }

        @Test
        @DisplayName("return-trace-id-header=false면 돌려주지 않는다")
        void notReturned() throws Exception {
            request.addHeader("X-Request-Id", "trace-abc");
            run(settings().returnTraceIdHeader(false).build());
            assertThat(response.getHeader("X-Request-Id")).isNull();
        }
    }

    @Nested
    @DisplayName("userAgent")
    class UserAgent {

        @Test
        @DisplayName("기본으로 넣는다")
        void stored() throws Exception {
            request.addHeader("User-Agent", "Mozilla/5.0");
            assertThat(run(KeycloakLoggingSettings.defaults())).containsEntry(LoggingContextKeys.USER_AGENT, "Mozilla/5.0");
        }

        @Test
        @DisplayName("최대 길이(256)를 넘으면 자른다")
        void truncated() throws Exception {
            request.addHeader("User-Agent", "A".repeat(300));
            assertThat(run(KeycloakLoggingSettings.defaults()).get(LoggingContextKeys.USER_AGENT))
                .isEqualTo("A".repeat(256) + "...[truncated]");
        }

        @Test
        @DisplayName("끄면 넣지 않는다")
        void off() throws Exception {
            request.addHeader("User-Agent", "Mozilla/5.0");
            assertThat(run(settings().includeUserAgent(false).build())).doesNotContainKey(LoggingContextKeys.USER_AGENT);
        }
    }

    @Nested
    @DisplayName("queryString 정리")
    class QueryString {

        @Test
        @DisplayName("URL 인코딩을 풀어서 넣는다")
        void decoded() throws Exception {
            request.setQueryString("name%3DJohn%20Doe");
            assertThat(run(settings().includeQueryString(true).build())).containsEntry(LoggingContextKeys.QUERY_STRING, "name=John Doe");
        }

        @Test
        @DisplayName("가리기(기본 PII)를 거친다: 이메일, OAuth2 code·토큰")
        void masked() throws Exception {
            request.setQueryString("email=alice@example.com&code=abc123&access_token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig");
            String query = run(filter(settings().includeQueryString(true).build(), 0, new DefaultPiiMaskingSanitizer()))
                .get(LoggingContextKeys.QUERY_STRING);
            assertThat(query).contains("a***@example.com", "code=***", "access_token=***").doesNotContain("abc123", "eyJhbGci");
        }

        @Test
        @DisplayName("최대 길이(512)를 넘으면 자른다")
        void truncated() throws Exception {
            request.setQueryString("q=" + "x".repeat(600));
            assertThat(run(settings().includeQueryString(true).build()).get(LoggingContextKeys.QUERY_STRING))
                .hasSize(512 + "...[truncated]".length());
        }
    }

    @Nested
    @DisplayName("응답 지표")
    class ResponseMetrics {

        @Test
        @DisplayName("include-response-metrics=true면 status·durationMs를 넣는다 (끝날 때 지운다)")
        void stored() throws Exception {
            Map<String, String> atEnd = new HashMap<>();
            LoggingValueSanitizer noop = new NoOpLoggingValueSanitizer();
            WebMdcContextAccessor recording = new WebMdcContextAccessor() {
                @Override
                public void clear() {
                    Map<String, String> copy = MDC.getCopyOfContextMap();
                    if (copy != null) {
                        atEnd.putAll(copy);
                    }
                    super.clear();
                }
            };
            response.setStatus(201);
            new MdcRequestFilter(recording, settings().includeResponseMetrics(true).build(), 0, noop)
                .doFilter(request, response, (req, res) -> { });

            assertThat(atEnd).containsEntry(LoggingContextKeys.STATUS, "201").containsKey(LoggingContextKeys.DURATION_MS);
            assertThat(MDC.getCopyOfContextMap()).isNullOrEmpty();
        }

        @Test
        @DisplayName("기본(false)이면 넣지 않는다")
        void notStored() throws Exception {
            assertThat(run(KeycloakLoggingSettings.defaults())).doesNotContainKeys(LoggingContextKeys.STATUS, LoggingContextKeys.DURATION_MS);
        }
    }

    @Nested
    @DisplayName("제외 경로")
    class ExcludePatterns {

        @Test
        @DisplayName("기본 제외(/actuator/**)는 MDC를 넣지 않는다")
        void actuator() throws Exception {
            request = request("/actuator/health");
            assertThat(run(KeycloakLoggingSettings.defaults())).isEmpty();
        }

        @Test
        @DisplayName("다른 경로는 넣는다")
        void others() throws Exception {
            request = request("/api/users");
            assertThat(run(KeycloakLoggingSettings.defaults())).isNotEmpty();
        }

        @Test
        @DisplayName("exclude-patterns를 바꾸면 그 경로를 뺀다")
        void custom() throws Exception {
            request = request("/internal/ping");
            assertThat(run(settings().excludePatterns(List.of("/internal/**")).build())).isEmpty();
        }

        @Test
        @DisplayName("(v3) 컨텍스트 경로를 뺀 앱 안 경로로 맞춘다")
        void contextPath() throws Exception {
            request = request("/app/actuator/health");
            request.setContextPath("/app");
            assertThat(run(KeycloakLoggingSettings.defaults())).isEmpty();
        }
    }

    @Test
    @DisplayName("앱이 직접 넣은 MDC 키는 요청이 끝나도 남긴다")
    void keepsAppKeys() throws Exception {
        MDC.put("tenant", "t-1");
        run(KeycloakLoggingSettings.defaults());
        assertThat(MDC.get("tenant")).isEqualTo("t-1");
        assertThat(MDC.get(LoggingContextKeys.TRACE_ID)).isNull();
    }
}
