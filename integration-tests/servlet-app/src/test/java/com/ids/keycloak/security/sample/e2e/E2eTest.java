package com.ids.keycloak.security.sample.e2e;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.api.Tag;

/**
 * E2E 테스트 표시. {@code ./gradlew test}에서는 빠지고 {@code e2eTest}에서만 돈다.
 * <p>
 * 실제 Keycloak·PostgreSQL·샘플 앱이 필요하다 ({@link E2eEnvironment}).
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Tag("e2e")
public @interface E2eTest {
}
