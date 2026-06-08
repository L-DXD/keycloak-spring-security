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

    @Nested
    @org.junit.jupiter.api.DisplayName("clear() 키 누수 방지 (R1)")
    class 키_누수_방지 {

        @Test
        @org.junit.jupiter.api.DisplayName("clear()는 어댑터가 put한 키만 제거하고 외부 키는 보존한다")
        void clear는_어댑터가_put한_키만_제거한다() {
            // Given: 어댑터로 넣은 키 + 외부에서 직접 넣은 키(도메인 컨텍스트 등)
            contextAccessor.put("libKey", "libValue");
            MDC.put("externalKey", "externalValue");

            // When
            contextAccessor.clear();

            // Then: 라이브러리 키만 제거, 외부 키는 보존
            assertThat(MDC.get("libKey")).isNull();
            assertThat(MDC.get("externalKey")).isEqualTo("externalValue");
        }

        @Test
        @org.junit.jupiter.api.DisplayName("remove한 키는 이후 clear 대상에서 빠진다")
        void remove된_키는_추적에서_제거된다() {
            contextAccessor.put("k1", "v1");
            contextAccessor.put("k2", "v2");
            contextAccessor.remove("k1");
            MDC.put("k1", "외부재설정"); // remove 후 외부가 같은 키를 재사용한 상황

            contextAccessor.clear();

            // clear는 추적 중인 k2만 제거, remove된 k1(외부 재설정분)은 보존
            assertThat(MDC.get("k2")).isNull();
            assertThat(MDC.get("k1")).isEqualTo("외부재설정");
        }

        @Test
        @org.junit.jupiter.api.DisplayName("clear 후 같은 스레드를 재사용해도 키가 누수되지 않는다")
        void clear_후_스레드_재사용시_누수없음() {
            // 1차 사용
            contextAccessor.put("first", "1");
            contextAccessor.clear();
            // 같은 스레드 재사용 (스레드풀 시나리오)
            contextAccessor.put("second", "2");
            contextAccessor.clear();

            assertThat(MDC.get("first")).isNull();
            assertThat(MDC.get("second")).isNull();
        }
    }
}