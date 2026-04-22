package com.ids.keycloak.security.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/**
 * AuthenticationEventLogger 단위 테스트.
 * logSkipped / logNoSession 신규 메서드의 로그 포맷, 레벨, 내용을 검증합니다.
 * 기존 메서드(logSuccess/logFailure/logRateLimited)의 하위 호환도 확인합니다.
 */
class AuthenticationEventLoggerTest {

    private ListAppender<ILoggingEvent> listAppender;
    private Logger logger;

    @BeforeEach
    void setUp() {
        logger = (Logger) LoggerFactory.getLogger(AuthenticationEventLogger.class);
        listAppender = new ListAppender<>();
        listAppender.start();
        logger.addAppender(listAppender);
        // DEBUG까지 캡처하도록 설정
        logger.setLevel(Level.DEBUG);
    }

    @AfterEach
    void tearDown() {
        logger.detachAppender(listAppender);
        listAppender.stop();
    }

    // ======================================================================
    // 1. logSkipped - INFO 레벨, 포맷 검증
    // ======================================================================

    @Nested
    class logSkipped_신규_메서드 {

        @Test
        void logSkipped는_INFO_레벨로_기록된다() {
            AuthenticationEventLogger.logSkipped("BEARER", "10.0.0.1", "stateless 인증 경로");

            assertThat(listAppender.list).hasSize(1);
            assertThat(listAppender.list.get(0).getLevel()).isEqualTo(Level.INFO);
        }

        @Test
        void logSkipped는_SKIPPED_결과를_포함한다() {
            AuthenticationEventLogger.logSkipped("BEARER", "10.0.0.1", "stateless 인증 경로");

            String message = listAppender.list.get(0).getFormattedMessage();
            assertThat(message).contains("result=SKIPPED");
        }

        @Test
        void logSkipped는_method_ip_reason을_포함하는_구조화된_포맷으로_기록된다() {
            AuthenticationEventLogger.logSkipped("BEARER", "192.168.1.100", "stateless 인증 경로");

            String message = listAppender.list.get(0).getFormattedMessage();
            assertThat(message)
                .contains("[AUTH]")
                .contains("result=SKIPPED")
                .contains("method=BEARER")
                .contains("ip=192.168.1.100")
                .contains("reason=stateless 인증 경로");
        }

        @Test
        void logSkipped_BASIC_호출시_메서드명이_포함된다() {
            AuthenticationEventLogger.logSkipped("BASIC", "10.1.2.3", "stateless 인증 경로");

            String message = listAppender.list.get(0).getFormattedMessage();
            assertThat(message).contains("method=BASIC");
        }

        @Test
        void logSkipped_CREDENTIAL_LOGIN_호출시_메서드명이_포함된다() {
            AuthenticationEventLogger.logSkipped("CREDENTIAL_LOGIN", "10.1.2.3", "stateless 인증 경로");

            String message = listAppender.list.get(0).getFormattedMessage();
            assertThat(message).contains("method=CREDENTIAL_LOGIN");
        }
    }

    // ======================================================================
    // 2. logNoSession - DEBUG 레벨, 포맷 검증
    // ======================================================================

    @Nested
    class logNoSession_신규_메서드 {

        @Test
        void logNoSession은_DEBUG_레벨로_기록된다() {
            AuthenticationEventLogger.logNoSession("OIDC_COOKIE", "10.0.0.1");

            assertThat(listAppender.list).hasSize(1);
            assertThat(listAppender.list.get(0).getLevel()).isEqualTo(Level.DEBUG);
        }

        @Test
        void logNoSession은_NO_SESSION_결과를_포함한다() {
            AuthenticationEventLogger.logNoSession("OIDC_COOKIE", "10.0.0.1");

            String message = listAppender.list.get(0).getFormattedMessage();
            assertThat(message).contains("result=NO_SESSION");
        }

        @Test
        void logNoSession은_method_ip를_포함하는_구조화된_포맷으로_기록된다() {
            AuthenticationEventLogger.logNoSession("OIDC_COOKIE", "172.16.0.5");

            String message = listAppender.list.get(0).getFormattedMessage();
            assertThat(message)
                .contains("[AUTH]")
                .contains("result=NO_SESSION")
                .contains("method=OIDC_COOKIE")
                .contains("ip=172.16.0.5");
        }
    }

    // ======================================================================
    // 3. 기존 메서드 하위 호환 검증 (시그니처 변경 없음)
    // ======================================================================

    @Nested
    class 기존_메서드_하위_호환 {

        @Test
        void logSuccess는_INFO_레벨로_SUCCESS를_기록한다() {
            AuthenticationEventLogger.logSuccess("OIDC_COOKIE", "10.0.0.1", "testuser");

            assertThat(listAppender.list).hasSize(1);
            ILoggingEvent event = listAppender.list.get(0);
            assertThat(event.getLevel()).isEqualTo(Level.INFO);
            assertThat(event.getFormattedMessage()).contains("result=SUCCESS");
        }

        @Test
        void logFailure는_WARN_레벨로_FAILURE를_기록한다() {
            AuthenticationEventLogger.logFailure("OIDC_COOKIE", "10.0.0.1", "unknown", "token expired");

            assertThat(listAppender.list).hasSize(1);
            ILoggingEvent event = listAppender.list.get(0);
            assertThat(event.getLevel()).isEqualTo(Level.WARN);
            assertThat(event.getFormattedMessage()).contains("result=FAILURE");
        }

        @Test
        void logRateLimited는_WARN_레벨로_RATE_LIMITED를_기록한다() {
            AuthenticationEventLogger.logRateLimited("BASIC", "10.0.0.1", "admin");

            assertThat(listAppender.list).hasSize(1);
            ILoggingEvent event = listAppender.list.get(0);
            assertThat(event.getLevel()).isEqualTo(Level.WARN);
            assertThat(event.getFormattedMessage()).contains("result=RATE_LIMITED");
        }
    }

    // ======================================================================
    // 4. logSkipped/logNoSession은 FAILURE/RATE_LIMITED가 아님을 검증
    //    (rate-limit 오탐 방지 확인 — 로그 레벨이 아닌 포맷 기반)
    // ======================================================================

    @Nested
    class 오탐_방지_검증 {

        @Test
        void logSkipped는_FAILURE를_포함하지_않는다() {
            AuthenticationEventLogger.logSkipped("BEARER", "10.0.0.1", "stateless");

            String message = listAppender.list.get(0).getFormattedMessage();
            assertThat(message).doesNotContain("result=FAILURE");
        }

        @Test
        void logNoSession은_FAILURE를_포함하지_않는다() {
            AuthenticationEventLogger.logNoSession("OIDC_COOKIE", "10.0.0.1");

            String message = listAppender.list.get(0).getFormattedMessage();
            assertThat(message).doesNotContain("result=FAILURE");
        }

        @Test
        void logSkipped는_RATE_LIMITED를_포함하지_않는다() {
            AuthenticationEventLogger.logSkipped("BASIC", "10.0.0.1", "stateless");

            String message = listAppender.list.get(0).getFormattedMessage();
            assertThat(message).doesNotContain("result=RATE_LIMITED");
        }
    }
}
