package com.ids.keycloak.security.test.servlet.support;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * {@link WithMockOidcLogin} 어노테이션을 처리하여 테스트용 SecurityContext를 생성하는 팩토리 클래스입니다.
 * 가짜 OIDC 사용자 정보와 토큰을 사용하여 {@link OAuth2AuthenticationToken}을 생성하고
 * SecurityContext에 설정합니다.
 */
public class WithMockOidcLoginSecurityContextFactory implements WithSecurityContextFactory<WithMockOidcLogin> {

    @Override
    public SecurityContext createSecurityContext(WithMockOidcLogin annotation) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", annotation.subject());
        claims.put("email", annotation.email());
        claims.put("name", "Test User");

        OidcIdToken idToken = new OidcIdToken(
                "mock-id-token",
                Instant.now(),
                Instant.now().plusSeconds(60),
                claims
        );

        OidcUser principal = new DefaultOidcUser(
                Collections.emptyList(), idToken, "name"
        );

        OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(
                principal,
                principal.getAuthorities(),
                "keycloak" // application.yml에 정의된 클라이언트 등록 ID
        );

        context.setAuthentication(token);
        return context;
    }
}
