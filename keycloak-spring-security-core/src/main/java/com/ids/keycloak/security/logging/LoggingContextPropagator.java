package com.ids.keycloak.security.logging;

import java.util.Map;

/** 로깅 컨텍스트를 다른 스레드로 옮길 때 쓴다 (스냅샷을 떠서 다시 넣는다). */
public interface LoggingContextPropagator {

    /** 지금 컨텍스트의 스냅샷. */
    Map<String, String> capture();

    /** 스냅샷을 지금 컨텍스트에 넣는다. */
    void restore(Map<String, String> snapshot);
}
