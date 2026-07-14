package com.ids.keycloak.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.ids.keycloak.security.authentication.ReactiveOidcBackChannelLogoutHandler;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * {@link ReactiveBackChannelLogoutEndpointFilter} 로그 원문 미노출 검증.
 *
 * <p>Advisory 5 리뷰 대응: 이 필터는 {@code logout_token} 폼 파라미터를 추출하여
 * {@link ReactiveOidcBackChannelLogoutHandler}로 위임하는데, 처리 성공/실패 어느 경로에서도
 * logout_token 원문이 로그에 남지 않아야 함을 Logback {@link ListAppender}로 검증한다.</p>
 */
@ExtendWith(MockitoExtension.class)
class ReactiveBackChannelLogoutEndpointFilterTest {

  @Mock
  private ReactiveOidcBackChannelLogoutHandler logoutHandler;

  private ReactiveBackChannelLogoutEndpointFilter filter;

  private Logger filterLogger;
  private ListAppender<ILoggingEvent> logAppender;

  private static final String LOGOUT_TOKEN_JWT =
      "eyJhbGciOiJSUzI1NiJ9.super-secret-payload-should-not-leak.sig-part";

  @BeforeEach
  void setUp() {
    filter = new ReactiveBackChannelLogoutEndpointFilter(logoutHandler);

    filterLogger = (Logger) LoggerFactory.getLogger(ReactiveBackChannelLogoutEndpointFilter.class);
    logAppender = new ListAppender<>();
    logAppender.start();
    filterLogger.addAppender(logAppender);
    // 요구사항: DEBUG/TRACE 레벨까지 활성화한 상태에서도 원문 미출력을 검증
    filterLogger.setLevel(Level.ALL);
  }

  @AfterEach
  void tearDown() {
    filterLogger.detachAppender(logAppender);
    logAppender.stop();
  }

  private List<String> formattedMessages() {
    return logAppender.list.stream()
        .map(ILoggingEvent::getFormattedMessage)
        .collect(Collectors.toList());
  }

  private ServerWebExchange formExchange(String body) {
    MockServerHttpRequest request = MockServerHttpRequest
        .post(ReactiveBackChannelLogoutEndpointFilter.BACK_CHANNEL_LOGOUT_PATH)
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .body(body);
    return MockServerWebExchange.from(request);
  }

  @Nested
  class 로그_원문_미노출_검증 {

    @Test
    void 정상_처리_시_로그에_logout_token_원문이_노출되지_않는다() {
      // Given
      when(logoutHandler.logout(any(), any())).thenReturn(Mono.empty());
      ServerWebExchange exchange = formExchange("logout_token=" + LOGOUT_TOKEN_JWT);

      // When
      StepVerifier.create(filter.filter(exchange, ex -> Mono.empty()))
          .verifyComplete();

      // Then
      List<String> messages = formattedMessages();
      assertThat(messages).isNotEmpty();
      assertThat(messages).noneMatch(m -> m.contains(LOGOUT_TOKEN_JWT));
      // 정상 흐름 로그 자체는 남아야 함 (positive control)
      assertThat(messages).anyMatch(m -> m.contains("logout_token 수신"));
    }

    @Test
    void 처리_중_예외가_발생해도_로그에_logout_token_원문이_노출되지_않는다() {
      // Given — 핸들러 위임 중 알 수 없는 오류 발생
      when(logoutHandler.logout(any(), any()))
          .thenReturn(Mono.error(new RuntimeException("session store unavailable")));
      ServerWebExchange exchange = formExchange("logout_token=" + LOGOUT_TOKEN_JWT);

      // When
      StepVerifier.create(filter.filter(exchange, ex -> Mono.empty()))
          .verifyComplete();

      // Then
      List<String> messages = formattedMessages();
      assertThat(messages).noneMatch(m -> m.contains(LOGOUT_TOKEN_JWT));
      // 에러 로그 자체는 남아야 함 (positive control — 로그 부재로 인한 거짓 통과 방지)
      assertThat(messages).anyMatch(m -> m.contains("Back-Channel 로그아웃 처리 중 오류"));
      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void logout_token_파라미터가_없는_요청도_원문_노출_없이_경고만_남긴다() {
      // Given — logout_token 파라미터 자체가 없음
      ServerWebExchange exchange = formExchange("other_param=value");

      // When
      StepVerifier.create(filter.filter(exchange, ex -> Mono.empty()))
          .verifyComplete();

      // Then
      List<String> messages = formattedMessages();
      assertThat(messages).anyMatch(m -> m.contains("logout_token 파라미터 없음"));
      assertThat(messages).noneMatch(m -> m.contains(LOGOUT_TOKEN_JWT));
      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
  }
}
