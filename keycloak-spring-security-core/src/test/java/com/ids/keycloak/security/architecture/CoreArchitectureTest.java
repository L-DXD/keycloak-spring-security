package com.ids.keycloak.security.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;

/** V3-14 (#125): core는 Servlet·Spring Web을 모른다. JDBC 저장소를 WebFlux(3.1.0)와 같이 쓰려고 (D16). */
class CoreArchitectureTest {

    private static final JavaClasses CORE = new ClassFileImporter()
        .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
        .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_JARS)
        .importPackages("com.ids.keycloak.security");

    @Test
    @DisplayName("EXT-04 core 모듈에는 jakarta.servlet, org.springframework.web import가 없다")
    void noServletOrSpringWeb() {
        assertThat(CORE).as("core 클래스를 읽었다").hasSizeGreaterThan(30);
        noClasses().should().dependOnClassesThat().resideInAnyPackage("jakarta.servlet..", "org.springframework.web..")
            .because("core는 Servlet·WebFlux가 같이 쓰는 모듈이다 (01 설계 4-1)")
            .check(CORE);
    }
}
