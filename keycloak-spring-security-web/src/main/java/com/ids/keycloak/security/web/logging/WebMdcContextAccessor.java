package com.ids.keycloak.security.web.logging;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.slf4j.MDC;

import com.ids.keycloak.security.logging.LoggingContextAccessor;
import com.ids.keycloak.security.logging.LoggingContextPropagator;

/**
 * Servlet용 MDC 접근자. 요청 하나를 스레드 하나가 처리하므로 SLF4J MDC를 그대로 쓴다.
 * <p>
 * 이 접근자로 넣은 키만 기억했다가 {@link #clear()}에서 그 키만 지운다. 앱이나 다른 라이브러리가 직접 {@code MDC.put}한 키는
 * 남는다(v2 1.6.0과 같다).
 */
public class WebMdcContextAccessor implements LoggingContextAccessor, LoggingContextPropagator {

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
        return key == null ? null : MDC.get(key);
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
        OWNED_KEYS.get().forEach(MDC::remove);
        OWNED_KEYS.remove();
    }

    @Override
    public Map<String, String> capture() {
        Map<String, String> copy = MDC.getCopyOfContextMap();
        return copy == null ? Collections.emptyMap() : new HashMap<>(copy);
    }

    @Override
    public void restore(Map<String, String> snapshot) {
        if (snapshot != null) {
            snapshot.forEach(this::put);
        }
    }
}
