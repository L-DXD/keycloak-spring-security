package com.ids.keycloak.security.config;

/**
 * 세션 행을 어디에 두는가 ({@code keycloak.security.session.store}).
 */
public enum SessionStoreType {

    /** DB 테이블({@code auth_session}). 기본값. 서버 여러 대에서 같이 쓴다. */
    JDBC,

    /** 서버 메모리. 한 대짜리 개발·테스트용. 재시작하면 모두 로그아웃된다. */
    MEMORY
}
