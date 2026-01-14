package com.ids.keycloak.security.logging;

import org.slf4j.MDC;
import reactor.util.context.Context;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * WebFlux 환경용 Reactor Context 기반 어댑터.
 * <p>
 * Reactor의 Context API를 통해 컨텍스트를 전파합니다.
 * WebFlux에서는 스레드 전환이 빈번하게 발생하므로 ThreadLocal 기반의 MDC를
 * 직접 사용하면 컨텍스트가 유실됩니다. 대신 Reactor Context를 사용하고,
 * 로깅 시점에 MDC로 동기화합니다.
 *
 * @author LeeBongSeung
 * @since 1.0.0
 */
public final class WebFluxContextAccessor {

    /**
     * Reactor Context에 저장되는 로깅 컨텍스트 키.
     */
    public static final String LOGGING_CONTEXT_KEY = "KEYCLOAK_LOGGING_CONTEXT";

    private WebFluxContextAccessor() {
        // 유틸리티 클래스
    }

    /**
     * Reactor Context에 로깅 데이터를 추가합니다.
     *
     * @param context 기존 Reactor Context
     * @param key     저장할 키
     * @param value   저장할 값
     * @return 로깅 데이터가 추가된 새 Context
     */
    public static Context put(Context context, String key, String value) {
        if (key == null || value == null) {
            return context;
        }

        Map<String, String> loggingContext = context.getOrDefault(LOGGING_CONTEXT_KEY, new HashMap<>());
        Map<String, String> newContext = new HashMap<>(loggingContext);
        newContext.put(key, value);
        return context.put(LOGGING_CONTEXT_KEY, newContext);
    }

    /**
     * Reactor Context에서 로깅 데이터를 조회합니다.
     *
     * @param context Reactor Context
     * @param key     조회할 키
     * @return 저장된 값, 없으면 null
     */
    public static String get(Context context, String key) {
        if (key == null) {
            return null;
        }

        Map<String, String> loggingContext = context.getOrDefault(LOGGING_CONTEXT_KEY, Collections.emptyMap());
        return loggingContext.get(key);
    }

    /**
     * Reactor Context에서 모든 로깅 데이터를 조회합니다.
     *
     * @param context Reactor Context
     * @return 로깅 컨텍스트 Map (불변)
     */
    public static Map<String, String> getAll(Context context) {
        Map<String, String> loggingContext = context.getOrDefault(LOGGING_CONTEXT_KEY, Collections.emptyMap());
        return Collections.unmodifiableMap(loggingContext);
    }

    /**
     * Reactor Context의 로깅 데이터를 MDC에 동기화합니다.
     * <p>
     * 실제 로깅이 발생하는 시점에 호출되어야 합니다.
     *
     * @param context Reactor Context
     */
    public static void syncToMdc(Context context) {
        Map<String, String> loggingContext = context.getOrDefault(LOGGING_CONTEXT_KEY, Collections.emptyMap());
        loggingContext.forEach(MDC::put);
    }

    /**
     * MDC의 모든 데이터를 정리합니다.
     */
    public static void clearMdc() {
        MDC.clear();
    }
}
