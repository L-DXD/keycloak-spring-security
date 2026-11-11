package com.ids.keycloak.security.logging;

/** 로깅 컨텍스트(MDC 등)에 값을 넣고 뺀다. Servlet은 {@code WebMdcContextAccessor}. */
public interface LoggingContextAccessor {

    /** 값을 넣는다. 키나 값이 {@code null}이면 넣지 않는다. */
    void put(String key, String value);

    String get(String key);

    void remove(String key);

    /** 이 접근자로 넣은 키만 지운다 (앱이 직접 넣은 키는 남긴다). */
    void clear();
}
