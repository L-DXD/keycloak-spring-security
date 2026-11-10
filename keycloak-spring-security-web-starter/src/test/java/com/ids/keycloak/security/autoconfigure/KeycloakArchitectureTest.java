package com.ids.keycloak.security.autoconfigure;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaModifier;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;

/** V3-14 (#90): 커스텀을 열어 둔다. core·web·starter의 공개 클래스를 한 번에 읽는다. */
class KeycloakArchitectureTest {

    private static final JavaClasses ALL = new ClassFileImporter()
        .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
        .importPackages("com.ids.keycloak.security");

    /** 밖에서 만들 수 있는(public·protected 생성자가 있는) 보통 클래스. record·enum·인터페이스는 뺀다. */
    private static final DescribedPredicate<JavaClass> EXTENSIBLE = DescribedPredicate.describe(
        "public·protected 생성자가 있는 클래스 (record·enum·인터페이스 제외)",
        c -> !c.isInterface() && !c.isEnum() && !c.isRecord() && !c.isAnnotation()
            && c.getConstructors().stream().anyMatch(k -> k.getModifiers().contains(JavaModifier.PUBLIC)
                || k.getModifiers().contains(JavaModifier.PROTECTED)));

    @Test
    @DisplayName("EXT-03 공개 클래스에 final이 없다. 예외는 record·enum과 암호 도구(sid 해시 SessionIds, HKDF)뿐")
    void noFinalPublicClasses() {
        assertThat(ALL.stream().map(JavaClass::getPackageName).distinct())
            .as("core·web·starter를 모두 읽었다")
            .contains("com.ids.keycloak.security.session", "com.ids.keycloak.security.web.refresh", "com.ids.keycloak.security.autoconfigure");

        classes().that().arePublic().and(EXTENSIBLE).should().notHaveModifier(JavaModifier.FINAL)
            .because("확장 지점은 상속해서 메서드 하나만 바꿔 쓸 수 있어야 한다 (01 설계 4-3)")
            .check(ALL);

        List<String> finalClasses = ALL.stream()
            .filter(c -> c.getModifiers().contains(JavaModifier.PUBLIC) && c.getModifiers().contains(JavaModifier.FINAL))
            .filter(c -> !c.isRecord() && !c.isEnum())
            .map(JavaClass::getSimpleName).sorted().toList();
        assertThat(finalClasses).as("final인 공개 클래스는 암호 도구뿐 (01 설계 1절 컨셉 3)").containsExactly("Hkdf", "SessionIds");
    }
}
