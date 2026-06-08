package com.ids.keycloak.security.logging;

import org.slf4j.MDC;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Web 환경용 MDC 직접 연동 어댑터.
 * <p>
 * ThreadLocal 기반 MDC를 그대로 활용합니다.
 * Web(Servlet) 환경에서는 요청당 하나의 스레드가 점유되므로, MDC를 직접 사용해도 안전합니다.
 * <p>
 * <b>키 누수 방지 (1.6.0+)</b>: 이 어댑터를 통해 put한 키만 추적하여 {@link #clear()} 시 그 키들만
 * 제거합니다. 따라서 사용자 코드/타 라이브러리가 직접 {@code MDC.put}한 키(도메인 컨텍스트 등)는
 * {@code clear()}가 건드리지 않아 보존됩니다. (이전에는 {@code MDC.clear()}로 전부 비워 누수가 있었음)
 *
 * @author LeeBongSeung
 * @since 1.0.0
 */
public class WebMdcContextAccessor implements LoggingContextAccessor, LoggingContextPropagator {

    /** 이 어댑터가 put한 키 목록. clear() 시 이 키들만 MDC에서 제거한다. */
    private static final ThreadLocal<Set<String>> OWNED_KEYS = ThreadLocal.withInitial(HashSet::new);

    @Override
    public void put(String key, String value) {
        if (key != null && value != null) {
            MDC.put(key, value);
            OWNED_KEYS.get().add(key);
        }
    }

    @Override
    public String get(String key) {
        return key != null ? MDC.get(key) : null;
    }

    @Override
    public void remove(String key) {
        if (key != null) {
            MDC.remove(key);
            OWNED_KEYS.get().remove(key);
        }
    }

    @Override
    public void clear() {
        Set<String> owned = OWNED_KEYS.get();
        for (String key : owned) {
            MDC.remove(key);
        }
        // ThreadLocal 자체도 정리하여 스레드풀 재사용 시 누수를 방지한다.
        OWNED_KEYS.remove();
    }

    @Override
    public Map<String, String> capture() {
        Map<String, String> contextMap = MDC.getCopyOfContextMap();
        return contextMap != null ? new HashMap<>(contextMap) : Collections.emptyMap();
    }

    @Override
    public void restore(Map<String, String> snapshot) {
        if (snapshot != null) {
            snapshot.forEach(this::put);
        }
    }
}
