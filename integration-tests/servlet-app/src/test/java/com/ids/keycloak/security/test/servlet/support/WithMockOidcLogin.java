package com.ids.keycloak.security.test.servlet.support;

import org.springframework.security.test.context.support.WithSecurityContext;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * 테스트에서 OIDC 로그인을 모의하기 위한 커스텀 어노테이션입니다.
 * {@link WithMockOidcLoginSecurityContextFactory}를 통해 가짜 {@link org.springframework.security.oauth2.core.oidc.user.OidcUser}를
 * SecurityContext에 설정합니다.
 */
@Retention(RetentionPolicy.RUNTIME)
@WithSecurityContext(factory = WithMockOidcLoginSecurityContextFactory.class)
public @interface WithMockOidcLogin {
    /**
     * OIDC 사용자의 subject 클레임 값입니다.
     */
    String subject() default "user";

    /**
     * OIDC 사용자의 email 클레임 값입니다.
     */
    String email() default "user@example.com";
}
