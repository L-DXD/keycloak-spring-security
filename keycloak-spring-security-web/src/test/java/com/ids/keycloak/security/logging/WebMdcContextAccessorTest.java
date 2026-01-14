package com.ids.keycloak.security.logging;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class WebMdcContextAccessorTest {

    private final WebMdcContextAccessor contextAccessor = new WebMdcContextAccessor();

    @AfterEach
    void tearDown() {
        MDC.clear();
    }

    @Nested
    class 정상_케이스 {

        @Test
        void 데이터를_저장하고_조회할_수_있다() {
            // Given
            String key = "testKey";
            String value = "testValue";

            // When
            contextAccessor.put(key, value);

            // Then
            assertThat(contextAccessor.get(key)).isEqualTo(value);
            assertThat(MDC.get(key)).isEqualTo(value);
        }

        @Test
        void 데이터를_삭제할_수_있다() {
            // Given
            contextAccessor.put("key", "value");

            // When
            contextAccessor.remove("key");

            // Then
            assertThat(contextAccessor.get("key")).isNull();
        }

        @Test
        void 컨텍스트를_캡처하고_복원할_수_있다() {
            // Given
            contextAccessor.put("k1", "v1");
            Map<String, String> snapshot = contextAccessor.capture();
            contextAccessor.clear();

            // When
            contextAccessor.restore(snapshot);

            // Then
            assertThat(contextAccessor.get("k1")).isEqualTo("v1");
        }
    }

    @Nested
    class 실패_케이스 {

        @Test
        void 존재하지_않는_키를_조회하면_null을_반환한다() {
            // When
            String value = contextAccessor.get("nonExistent");

            // Then
            assertThat(value).isNull();
        }
    }
}