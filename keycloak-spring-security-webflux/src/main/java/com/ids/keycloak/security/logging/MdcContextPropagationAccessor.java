package com.ids.keycloak.security.logging;

import io.micrometer.context.ThreadLocalAccessor;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.MDC;

/**
 * Reactor Context에 저장된 로깅 컨텍스트(KEYCLOAK_LOGGING_CONTEXT)를
 * MDC(Mapped Diagnostic Context)로 자동 전파하는 {@link ThreadLocalAccessor} 구현체입니다.
 *
 * <p>Micrometer Context Propagation SPI({@code io.micrometer:context-propagation})를 통해
 * {@link reactor.core.publisher.Hooks#enableAutomaticContextPropagation()} 활성화 시
 * Reactor 연산자 전환 시점마다 이 Accessor가 자동으로 호출되어 MDC를 설정/복원합니다.</p>
 *
 * <p><b>작동 원리:</b>
 * <ol>
 *   <li>{@link ReactiveLoggingFilter}가 요청마다 Reactor Context에
 *       {@code KEYCLOAK_LOGGING_CONTEXT} 키로 {@code Map<String,String>}을 적재</li>
 *   <li>Hooks 활성화 시 {@link ThreadLocalAccessor#restore(Object)} 가 스레드 전환 시마다 호출됨</li>
 *   <li>해당 스레드의 MDC에 loggingContext 맵이 설정되어 Logback/Log4j 패턴에서 참조 가능</li>
 *   <li>연산자 종료 시 {@link ThreadLocalAccessor#reset()} 으로 MDC가 정리됨</li>
 * </ol>
 * </p>
 *
 * <p><b>전역 Hooks 부작용 처리:</b>
 * {@code Hooks.enableAutomaticContextPropagation()}은 JVM 전역에 영향을 미칩니다.
 * 라이브러리에서 전역 훅을 설정하는 것은 사용자 코드에 부작용을 줄 수 있습니다.
 * 이를 최소화하기 위해:
 * <ul>
 *   <li>AutoConfiguration의 {@code @PostConstruct}에서 1회만 설정합니다</li>
 *   <li>멱등성 보장: 이미 활성화되어 있어도 중복 호출은 무해합니다</li>
 *   <li>opt-out: {@code keycloak.security.logging.mdc-propagation-enabled=false}로 비활성화 가능</li>
 *   <li>이 Accessor는 {@code KEYCLOAK_LOGGING_CONTEXT} 키에만 동작하므로 다른 컨텍스트에 영향 없음</li>
 * </ul>
 * </p>
 *
 * @see ReactiveLoggingContextAccessor
 * @see reactor.core.publisher.Hooks#enableAutomaticContextPropagation()
 */
public class MdcContextPropagationAccessor implements ThreadLocalAccessor<Map<String, String>> {

  /**
   * Reactor Context 키 — {@link ReactiveLoggingContextAccessor#CONTEXT_KEY}와 동일.
   */
  public static final String KEY = ReactiveLoggingContextAccessor.CONTEXT_KEY;

  /**
   * 이 Accessor가 관리하는 MDC 키 목록.
   * core 모듈의 {@link LoggingContextKeys} 상수들을 열거합니다.
   * core 모듈 수정 없이 webflux 모듈에서만 관리하기 위해 여기서 정의합니다.
   */
  private static final List<String> LOGGING_KEYS = Arrays.asList(
      LoggingContextKeys.TRACE_ID,
      LoggingContextKeys.HTTP_METHOD,
      LoggingContextKeys.REQUEST_URI,
      LoggingContextKeys.QUERY_STRING,
      LoggingContextKeys.CLIENT_IP,
      LoggingContextKeys.USER_AGENT,
      LoggingContextKeys.STATUS,
      LoggingContextKeys.DURATION_MS,
      LoggingContextKeys.USER_ID,
      LoggingContextKeys.USERNAME,
      LoggingContextKeys.SESSION_ID
  );

  /**
   * ThreadLocalAccessor SPI가 이 accessor를 식별하는 키를 반환합니다.
   *
   * @return {@code KEYCLOAK_LOGGING_CONTEXT}
   */
  @Override
  public Object key() {
    return KEY;
  }

  /**
   * 현재 MDC에서 로깅 컨텍스트 맵의 키에 해당하는 항목을 스냅샷으로 캡처합니다.
   *
   * <p>이 메서드는 구독자가 다른 스레드로 이동할 때 Reactor가 호출합니다.
   * MDC에서 로깅 관련 키만 수집하여 반환합니다.</p>
   *
   * @return 현재 MDC의 로깅 컨텍스트 스냅샷 (없으면 빈 맵)
   */
  @Override
  public Map<String, String> getValue() {
    Map<String, String> mdcCopy = MDC.getCopyOfContextMap();
    if (mdcCopy == null) {
      return new HashMap<>();
    }
    // 라이브러리 로깅 컨텍스트 키에 해당하는 항목만 반환
    Map<String, String> result = new HashMap<>();
    for (String key : LOGGING_KEYS) {
      String value = mdcCopy.get(key);
      if (value != null) {
        result.put(key, value);
      }
    }
    return result;
  }

  /**
   * Reactor Context에서 가져온 로깅 컨텍스트를 현재 스레드의 MDC에 설정합니다.
   *
   * <p>스레드 전환 후 구독자가 실행되기 직전 Reactor가 호출합니다.</p>
   *
   * @param value Reactor Context에서 전달된 로깅 컨텍스트 맵
   */
  @Override
  public void restore(Map<String, String> value) {
    if (value == null || value.isEmpty()) {
      return;
    }
    value.forEach(MDC::put);
  }

  /**
   * 주어진 값으로 현재 스레드의 MDC를 설정합니다.
   *
   * <p>Context Propagation SPI의 {@code setValue(T)} 추상 메서드 구현입니다.
   * Reactor가 스냅샷에서 값을 복원할 때 {@link #restore(Map)}와 유사하게 호출됩니다.</p>
   *
   * @param value 설정할 로깅 컨텍스트 맵
   */
  @Override
  public void setValue(Map<String, String> value) {
    restore(value);
  }

  /**
   * 현재 스레드의 MDC에서 로깅 컨텍스트 키들을 제거합니다.
   *
   * <p>연산자 종료 후 Reactor가 호출하여 MDC 누수를 방지합니다.</p>
   */
  @Override
  public void reset() {
    for (String key : LOGGING_KEYS) {
      MDC.remove(key);
    }
  }
}
