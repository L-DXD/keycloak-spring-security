package com.ids.keycloak.security.token;

import java.io.IOException;

/**
 * Keycloak의 JWKS(서명 공개 키 묶음)를 받아 온다. 프록시·타임아웃을 바꿀 때 이 빈을 바꾼다.
 */
@FunctionalInterface
public interface JwkSetFetcher {

    /**
     * @return JWKS JSON 문자열
     * @throws IOException 받지 못했을 때
     */
    String fetch() throws IOException;
}
