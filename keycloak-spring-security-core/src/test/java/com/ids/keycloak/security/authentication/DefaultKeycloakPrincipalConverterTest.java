package com.ids.keycloak.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;

class DefaultKeycloakPrincipalConverterTest {

    static Jwt jwt() {
        return Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .subject("8f2c1a7e-0000-4000-8000-000000000001")
            .claim("sid", "kc-sid-1")
            .claim("azp", "demo")
            .claim("preferred_username", "alice")
            .claim("email", "alice@example.com")
            .issuedAt(Instant.parse("2026-11-10T00:00:00Z"))
            .expiresAt(Instant.parse("2026-11-10T00:01:00Z"))
            .build();
    }

    @Test
    @DisplayName("기본 변환: principal은 sub·sid·azp, 이름은 sub, 권한 없음")
    void defaultConversion() {
        Authentication authentication = new DefaultKeycloakPrincipalConverter().convert(jwt());

        assertThat(authentication).isInstanceOf(KeycloakAuthenticationToken.class);
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getName()).isEqualTo("8f2c1a7e-0000-4000-8000-000000000001");
        assertThat(authentication.getAuthorities()).isEmpty();
        KeycloakPrincipal principal = (KeycloakPrincipal) authentication.getPrincipal();
        assertThat(principal.sessionId()).isEqualTo("kc-sid-1");
        assertThat(principal.authorizedParty()).isEqualTo("demo");
        assertThat(principal.username()).isEqualTo("alice");
        assertThat(((KeycloakAuthenticationToken) authentication).getToken().getTokenValue()).isEqualTo("token");
    }

    @Test
    @DisplayName("toString에 클레임(이메일 같은 개인 정보)이 나오지 않는다")
    void toStringHasNoClaims() {
        KeycloakPrincipal principal = KeycloakPrincipal.from(jwt());

        assertThat(principal.toString()).contains("8f2c1a7e").doesNotContain("alice").doesNotContain("@example.com");
        assertThat(principal.claims()).containsKey("email");
    }

    @Test
    @DisplayName("권한을 덮어써 붙일 수 있다")
    void authoritiesCanBeOverridden() {
        DefaultKeycloakPrincipalConverter converter = new DefaultKeycloakPrincipalConverter() {
            @Override
            protected java.util.Collection<org.springframework.security.core.GrantedAuthority> authorities(Jwt accessToken) {
                return List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN"));
            }
        };

        assertThat(converter.convert(jwt()).getAuthorities()).extracting(Object::toString).containsExactly("ROLE_ADMIN");
    }

    @Test
    @DisplayName("인증 결과를 직렬화할 수 있다 (앱이 세션·캐시에 둘 때)")
    void serializable() throws Exception {
        KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) new DefaultKeycloakPrincipalConverter().convert(jwt());
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(token);
        }
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            KeycloakAuthenticationToken copy = (KeycloakAuthenticationToken) in.readObject();
            assertThat(copy.getPrincipal()).isEqualTo(token.getPrincipal());
        }
    }
}
