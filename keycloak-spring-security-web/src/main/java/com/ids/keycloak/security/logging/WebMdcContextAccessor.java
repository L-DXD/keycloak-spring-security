package com.ids.keycloak.security.logging;

import org.slf4j.MDC;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Web 환경용 MDC 직접 연동 어댑터.
 * <p>
 * ThreadLocal 기반 MDC를 그대로 활용합니다.
 * Web(Servlet) 환경에서는 요청당 하나의 스레드가 점유되므로, MDC를 직접 사용해도 안전합니다.
 *
 * @author LeeBongSeung
 * @since 1.0.0
 */
public class WebMdcContextAccessor implements LoggingContextAccessor, LoggingContextPropagator {

    @Override
    public void put(String key, String value) {
        if (key != null && value != null) {
            MDC.put(key, value);
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
        }
    }

    @Override
    public void clear() {
        MDC.clear();
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
