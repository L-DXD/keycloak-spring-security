package com.ids.keycloak.security.test.servlet;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class TestController {

    @GetMapping("/api/me")
    public ResponseEntity<String> getMyInfo(@AuthenticationPrincipal Authentication principal) {
        // MDC 값 확인 로그
        log.debug("===== MDC Context 확인 =====");
        log.debug("traceId: {}", MDC.get("traceId"));
        log.debug("httpMethod: {}", MDC.get("httpMethod"));
        log.debug("requestUri: {}", MDC.get("requestUri"));
        log.debug("clientIp: {}", MDC.get("clientIp"));
        log.debug("userId: {}", MDC.get("userId"));
        log.debug("username: {}", MDC.get("username"));
        log.debug("sessionId: {}", MDC.get("sessionId"));
        log.debug("queryString: {}", MDC.get("queryString"));
        log.debug("============================");

        if (principal != null) {
            log.debug("인증된 사용자: {}", principal.getName());
            log.debug("사용자 속성: {}", principal.getAttributes());
            log.debug("사용자 권한: {}", principal.getAuthorities());
            return ResponseEntity.ok("Hello, " + principal.getName());
        }

        return ResponseEntity.status(401).body("Unauthorized");
    }

    @GetMapping("/public/mdc-test")
    public ResponseEntity<String> mdcTest() {
        // 인증 없이 MDC 요청 메타데이터 확인
        log.debug("===== MDC 요청 메타데이터 (인증 전) =====");
        log.debug("traceId: {}", MDC.get(LoggingContextKeys.TRACE_ID));
        log.debug("httpMethod: {}", MDC.get(LoggingContextKeys.HTTP_METHOD));
        log.debug("requestUri: {}", MDC.get(LoggingContextKeys.REQUEST_URI));
        log.debug("clientIp: {}", MDC.get(LoggingContextKeys.CLIENT_IP));
        log.debug("userId (should be null): {}", MDC.get(LoggingContextKeys.USER_ID));
        log.debug("==========================================");

        return ResponseEntity.ok("MDC Test - traceId: " + MDC.get(LoggingContextKeys.TRACE_ID));
    }
}