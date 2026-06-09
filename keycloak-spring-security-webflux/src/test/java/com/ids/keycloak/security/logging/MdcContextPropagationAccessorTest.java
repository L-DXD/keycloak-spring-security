package com.ids.keycloak.security.logging;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

/**
 * {@link MdcContextPropagationAccessor} 단위 테스트.
 *
 * <p>Reactor Context ↔ MDC 브릿지가 올바르게 동작하는지 검증합니다.
 * MDC 전파는 {@code Hooks.enableAutomaticContextPropagation()} 전역 훅이 필요하므로
 * 직접 accessor 메서드를 호출하여 검증합니다.</p>
 */
class MdcContextPropagationAccessorTest {

  private final MdcContextPropagationAccessor accessor = new MdcContextPropagationAccessor();

  @AfterEach
  void clearMdc() {
    MDC.clear();
  }

  // ==========================================================================
  // key() 검증
  // ==========================================================================

  @Test
  void key_returns_KEYCLOAK_LOGGING_CONTEXT() {
    assertThat(accessor.key()).isEqualTo(ReactiveLoggingContextAccessor.CONTEXT_KEY);
  }

  // ==========================================================================
  // getValue() — 현재 MDC에서 로깅 컨텍스트 추출
  // ==========================================================================

  @Nested
  class getValue {

    @Test
    void MDC_비어있으면_빈_맵_반환() {
      Map<String, String> result = accessor.getValue();
      assertThat(result).isEmpty();
    }

    @Test
    void MDC에_traceId_있으면_포함하여_반환() {
      MDC.put(LoggingContextKeys.TRACE_ID, "trace-123");

      Map<String, String> result = accessor.getValue();

      assertThat(result).containsEntry(LoggingContextKeys.TRACE_ID, "trace-123");
    }

    @Test
    void MDC에_여러_로깅키_있으면_모두_반환() {
      MDC.put(LoggingContextKeys.TRACE_ID, "t1");
      MDC.put(LoggingContextKeys.USER_ID, "user1");
      MDC.put(LoggingContextKeys.HTTP_METHOD, "GET");
      MDC.put("unrelated-key", "should-not-be-included");

      Map<String, String> result = accessor.getValue();

      assertThat(result).containsEntry(LoggingContextKeys.TRACE_ID, "t1");
      assertThat(result).containsEntry(LoggingContextKeys.USER_ID, "user1");
      assertThat(result).containsEntry(LoggingContextKeys.HTTP_METHOD, "GET");
      // 관리 키가 아닌 값은 포함되지 않음
      assertThat(result).doesNotContainKey("unrelated-key");
    }
  }

  // ==========================================================================
  // restore() — Reactor Context → MDC 복원
  // ==========================================================================

  @Nested
  class restore {

    @Test
    void null_전달시_MDC_변경_없음() {
      accessor.restore(null);
      assertThat(MDC.getCopyOfContextMap()).isNullOrEmpty();
    }

    @Test
    void 빈_맵_전달시_MDC_변경_없음() {
      accessor.restore(new HashMap<>());
      assertThat(MDC.getCopyOfContextMap()).isNullOrEmpty();
    }

    @Test
    void 로깅컨텍스트_맵_전달시_MDC에_설정됨() {
      Map<String, String> context = new HashMap<>();
      context.put(LoggingContextKeys.TRACE_ID, "restored-trace");
      context.put(LoggingContextKeys.USER_ID, "restored-user");

      accessor.restore(context);

      assertThat(MDC.get(LoggingContextKeys.TRACE_ID)).isEqualTo("restored-trace");
      assertThat(MDC.get(LoggingContextKeys.USER_ID)).isEqualTo("restored-user");
    }
  }

  // ==========================================================================
  // setValue() — MDC 설정 (restore와 동일)
  // ==========================================================================

  @Nested
  class setValue {

    @Test
    void setValue_호출시_MDC에_설정됨() {
      Map<String, String> context = new HashMap<>();
      context.put(LoggingContextKeys.TRACE_ID, "set-trace");

      accessor.setValue(context);

      assertThat(MDC.get(LoggingContextKeys.TRACE_ID)).isEqualTo("set-trace");
    }
  }

  // ==========================================================================
  // reset() — MDC 정리
  // ==========================================================================

  @Nested
  class reset {

    @Test
    void reset_호출시_로깅키_MDC에서_제거됨() {
      MDC.put(LoggingContextKeys.TRACE_ID, "trace");
      MDC.put(LoggingContextKeys.USER_ID, "user");
      MDC.put("unrelated-key", "keep");

      accessor.reset();

      assertThat(MDC.get(LoggingContextKeys.TRACE_ID)).isNull();
      assertThat(MDC.get(LoggingContextKeys.USER_ID)).isNull();
      // 관리하지 않는 키는 유지
      assertThat(MDC.get("unrelated-key")).isEqualTo("keep");
    }
  }

  // ==========================================================================
  // Reactor Context ↔ MDC 브릿지 통합 검증
  // ==========================================================================

  @Nested
  class Reactor_Context_MDC_브릿지 {

    /**
     * ReactiveLoggingContextAccessor.putValue로 Reactor Context에 저장된 값이
     * bridgeToMdc 호출 시 MDC에 복사되는지 검증합니다.
     */
    @Test
    void Reactor_Context에서_bridgeToMdc_호출시_MDC에_설정됨() {
      Context ctx = ReactiveLoggingContextAccessor.putValue(
          Context.empty(), LoggingContextKeys.TRACE_ID, "ctx-trace");

      Mono<String> mono = Mono.deferContextual(contextView -> {
        ReactiveLoggingContextAccessor.bridgeToMdc(contextView);
        String mdcValue = MDC.get(LoggingContextKeys.TRACE_ID);
        ReactiveLoggingContextAccessor.clearMdc(contextView);
        return Mono.just(mdcValue != null ? mdcValue : "null");
      }).contextWrite(ctx);

      StepVerifier.create(mono)
          .expectNext("ctx-trace")
          .verifyComplete();
    }

    @Test
    void Reactor_Context_에_없는_키는_MDC에_없음() {
      Context ctx = Context.empty();

      Mono<String> mono = Mono.deferContextual(contextView -> {
        ReactiveLoggingContextAccessor.bridgeToMdc(contextView);
        String mdcValue = MDC.get(LoggingContextKeys.TRACE_ID);
        return Mono.just(mdcValue != null ? mdcValue : "null");
      }).contextWrite(ctx);

      StepVerifier.create(mono)
          .expectNext("null")
          .verifyComplete();
    }
  }
}
