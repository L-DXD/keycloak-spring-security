package com.ids.keycloak.security.config;

/**
 * 세션 저장소 유형을 정의하는 Enum.
 * <p>
 * application.yml에서 keycloak.session.store-type 프로퍼티로 설정합니다.
 * </p>
 */
public enum SessionStoreType {

    /**
     * In-Memory 세션 저장소 (기본값)
     * 단일 인스턴스 환경에 적합
     */
    MEMORY,

    /**
     * Redis 세션 저장소
     * 다중 인스턴스 환경 및 세션 영속성이 필요한 경우 사용
     */
    REDIS
}
