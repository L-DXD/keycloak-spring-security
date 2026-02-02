package com.ids.keycloak.security.logging;

import java.util.Map;

/**
 * 컨텍스트 데이터를 스냅샷으로 캡처하고 복원하는 유틸리티.
 * 비동기 경계를 넘을 때 컨텍스트 전파에 사용됩니다.
 */
public interface LoggingContextPropagator {

    /**
     * 현재 컨텍스트의 스냅샷을 캡처합니다.
     */
    Map<String, String> capture();

    /**
     * 캡처된 스냅샷을 현재 컨텍스트에 복원합니다.
     */
    void restore(Map<String, String> snapshot);
}