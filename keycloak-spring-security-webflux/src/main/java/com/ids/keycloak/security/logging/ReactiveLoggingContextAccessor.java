package com.ids.keycloak.security.logging;

import java.util.Map;
import reactor.util.context.Context;
import reactor.util.context.ContextView;

/**
 * WebFlux(Reactive) 환경에서 로깅 컨텍스트를 Reactor Context에 저장/조회하는 구현체입니다.
 *
 * <p>Reactor는 스레드-로컬 MDC를 직접 사용할 수 없으므로, {@link Context}를 1차 저장소로 사용합니다.
 * 로그 출력 직전에 contextView에서 값을 읽어 MDC를 일시적으로 복원하는 패턴을 지원합니다.
 * ({@link #bridgeToMdc(ContextView)} 참고)</p>
 *
 * <p>이 클래스는 {@link LoggingContextAccessor} 인터페이스를 구현하나,
 * put/get/remove/clear 는 직접 MDC를 사용하지 않고 Reactor Context에서만 동작합니다.
 * WebFlux 필터에서 직접 사용하기보다는 {@code contextWrite}와 함께 사용합니다.</p>
 */
public class ReactiveLoggingContextAccessor implements LoggingContextAccessor {

  /**
   * Reactor Context 키로 사용되는 로깅 컨텍스트 맵의 키입니다.
   */
  public static final String CONTEXT_KEY = "KEYCLOAK_LOGGING_CONTEXT";

  /**
   * ContextView에서 로깅 컨텍스트 맵을 추출합니다.
   */
  @SuppressWarnings("unchecked")
  public static Map<String, String> getLoggingContext(ContextView contextView) {
    return contextView.getOrDefault(CONTEXT_KEY, new java.util.HashMap<>());
  }

  /**
   * 기존 Context에 로깅 컨텍스트 값을 추가한 새 Context를 반환합니다.
   */
  public static Context putValue(Context context, String key, String value) {
    Map<String, String> existing = context.getOrDefault(CONTEXT_KEY, new java.util.HashMap<>());
    Map<String, String> updated = new java.util.HashMap<>(existing);
    updated.put(key, value);
    return context.put(CONTEXT_KEY, updated);
  }

  /**
   * Reactor ContextView의 로깅 컨텍스트를 MDC로 브릿지합니다.
   *
   * <p>단일 연산자 단위에서 직전에 호출하면, Reactor 스레드에 관계없이
   * 해당 스코프에서만 MDC 값이 설정됩니다.</p>
   *
   * @param contextView 현재 Reactor ContextView
   */
  public static void bridgeToMdc(ContextView contextView) {
    Map<String, String> loggingCtx = getLoggingContext(contextView);
    loggingCtx.forEach(org.slf4j.MDC::put);
  }

  /**
   * MDC에서 로깅 컨텍스트 키들을 제거합니다.
   *
   * @param contextView 현재 Reactor ContextView
   */
  public static void clearMdc(ContextView contextView) {
    Map<String, String> loggingCtx = getLoggingContext(contextView);
    loggingCtx.keySet().forEach(org.slf4j.MDC::remove);
  }

  // ===== LoggingContextAccessor 구현 (ThreadLocal MDC 직접 사용 — 폴백용) =====
  // Reactor 파이프라인 안에서는 contextWrite 패턴을 우선합니다.

  @Override
  public void put(String key, String value) {
    if (key != null && value != null) {
      org.slf4j.MDC.put(key, value);
    }
  }

  @Override
  public String get(String key) {
    return key != null ? org.slf4j.MDC.get(key) : null;
  }

  @Override
  public void remove(String key) {
    if (key != null) {
      org.slf4j.MDC.remove(key);
    }
  }

  @Override
  public void clear() {
    org.slf4j.MDC.clear();
  }
}
