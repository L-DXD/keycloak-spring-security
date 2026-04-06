package com.ids.keycloak.security.logging;

/**
 * 로깅 컨텍스트에 데이터를 읽고 쓰는 추상화 인터페이스.
 * Web과 WebFlux 환경에서 각각 다르게 구현됩니다.
 */
public interface LoggingContextAccessor {

    /**
     * 컨텍스트에 키-값 쌍을 저장합니다.
     */
    void put(String key, String value);

    /**
     * 컨텍스트에서 값을 조회합니다.
     */
    String get(String key);

    /**
     * 컨텍스트에서 특정 키를 제거합니다.
     */
    void remove(String key);

    /**
     * 컨텍스트를 초기화합니다.
     */
    void clear();
}