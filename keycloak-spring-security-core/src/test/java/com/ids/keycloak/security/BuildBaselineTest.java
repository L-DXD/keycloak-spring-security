package com.ids.keycloak.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.SpringVersion;
import org.springframework.security.core.SpringSecurityCoreVersion;

/**
 * BUILD-01: Boot 4.x BOM이 고른 Spring 판으로 빌드·테스트가 돈다.
 */
class BuildBaselineTest {

    @Test
    @DisplayName("BUILD-01 Spring Security 7.x와 Spring Framework 7.x로 돈다")
    void runsOnSpringSecurity7AndFramework7() {
        assertThat(SpringSecurityCoreVersion.getVersion()).startsWith("7.");
        assertThat(SpringVersion.getVersion()).startsWith("7.");
    }

    @Test
    @DisplayName("BUILD-01 클래스 파일은 Java 17 바이트코드다 (D12)")
    void compiledForJava17() throws Exception {
        try (var in = KeycloakSecurityVersion.class.getResourceAsStream("KeycloakSecurityVersion.class")) {
            byte[] header = in.readNBytes(8);
            int major = ((header[6] & 0xff) << 8) | (header[7] & 0xff);
            assertThat(major).isEqualTo(61); // Java 17
        }
    }

    @Test
    @DisplayName("BUILD-01 jar 밖에서는 판을 unknown으로 돌려준다")
    void versionIsUnknownOutsideJar() {
        assertThat(KeycloakSecurityVersion.current()).isEqualTo(KeycloakSecurityVersion.UNKNOWN);
    }
}
