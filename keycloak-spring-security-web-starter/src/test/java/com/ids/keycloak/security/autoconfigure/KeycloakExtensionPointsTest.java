package com.ids.keycloak.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.security.web.SecurityFilterChain;

import com.ids.keycloak.security.session.InMemoryKeycloakSessionStore;
import com.ids.keycloak.security.session.KeycloakSessionCleaner;

/**
 * V3-14 자동 설정의 확장 지점 (#125). 자동 설정의 {@code @Bean}을 리플렉션으로 모두 찾아, 빈마다 사용자 빈을 올렸을 때 라이브러리 빈이
 * 빠지고 그 빈만 남는지 본다 (EXT-01). 라이브러리는 빈을 타입(또는 이름)으로 찾으므로, 하나만 남으면 그것을 쓴다. 바꿔 끼운 빈이 실제로
 * 쓰이는지는 기능별 테스트가 본다(REQ-06 변환기, EVT-03 MDC 접근자, CORS 이름, 토큰 클라이언트 등). 보안 체인은 EXT-02
 * ({@link KeycloakUserChainTest}).
 */
class KeycloakExtensionPointsTest {

    /** 자동 설정 빈 하나: 이름, 사용자 빈이 있으면 빠지는 조건의 타입, 이름으로 거는 조건인가. */
    record LibraryBean(String name, Class<?> type, boolean byName) {

        @Override
        public String toString() {
            return name;
        }
    }

    /** 세션 저장소는 메모리로 (사용자 빈으로 옮겨 끼운 저장소가 닫힌 DB를 보지 않게). */
    static final WebApplicationContextRunner RUNNER = KeycloakSecurityAutoConfigurationTest
        .baseRunner(KeycloakSecurityAutoConfigurationTest.registration(KeycloakSecurityAutoConfigurationTest.ISSUER))
        .withPropertyValues("keycloak.security.session.store=memory");

    /** 기본 컨텍스트에서 꺼낸 라이브러리 빈. 사용자 빈으로 쓴다. */
    static final Map<String, Object> DEFAULTS = new HashMap<>();

    @BeforeAll
    static void captureDefaults() {
        RUNNER.run(context -> {
            assertThat(context).hasNotFailed();
            for (LibraryBean bean : libraryBeans().toList()) {
                DEFAULTS.put(bean.name(), context.getBean(bean.name()));
            }
        });
    }

    /** 자동 설정 클래스(와 안쪽 설정 클래스)의 {@code @Bean} 메서드. */
    static List<Method> beanMethods() {
        List<Method> methods = new ArrayList<>(Arrays.asList(KeycloakSecurityAutoConfiguration.class.getDeclaredMethods()));
        for (Class<?> nested : KeycloakSecurityAutoConfiguration.class.getDeclaredClasses()) {
            methods.addAll(Arrays.asList(nested.getDeclaredMethods()));
        }
        return methods.stream().filter(m -> m.isAnnotationPresent(Bean.class)).sorted(Comparator.comparing(Method::getName)).toList();
    }

    static String beanName(Method method) {
        Bean bean = method.getAnnotation(Bean.class);
        return bean.name().length > 0 ? bean.name()[0] : bean.value().length > 0 ? bean.value()[0] : method.getName();
    }

    /** 보안 체인은 EXT-02가 본다. */
    static Stream<LibraryBean> libraryBeans() {
        return beanMethods().stream().filter(m -> m.getReturnType() != SecurityFilterChain.class).map(m -> {
            ConditionalOnMissingBean condition = m.getAnnotation(ConditionalOnMissingBean.class);
            boolean byName = condition.name().length > 0;
            Class<?> type = condition.value().length > 0 ? condition.value()[0] : m.getReturnType();
            return new LibraryBean(beanName(m), type, byName);
        });
    }

    static Stream<Arguments> points() {
        return libraryBeans().map(Arguments::of);
    }

    /** 사용자 빈. 기본 컨텍스트의 같은 빈을 쓰고, 시작·멈춤이 있는 정리 작업만 새로 만든다. */
    static Object userBean(LibraryBean bean) {
        if (bean.type() == KeycloakSessionCleaner.class) {
            return new KeycloakSessionCleaner(new InMemoryKeycloakSessionStore(), event -> { }, Clock.systemUTC(), Duration.ofHours(1));
        }
        return DEFAULTS.get(bean.name());
    }

    @Test
    @DisplayName("EXT-01 자동 설정 빈을 빠짐없이 센다 (01 설계 4-3 표 + 설정·Keycloak 정보·서명기 등)")
    void allBeansCounted() {
        assertThat(libraryBeans().map(LibraryBean::name)).hasSizeGreaterThanOrEqualTo(30)
            .contains("keycloakSessionStore", "keycloakAccessTokenValidator", "keycloakPrincipalConverter", "keycloakTokenClient",
                "keycloakCookieWriter", "keycloakCsrfTokenRepository", "keycloakCorsConfigurationSource", "keycloakLoginSuccessHandler",
                "keycloakLogoutHandler", "keycloakBackChannelLogoutHandler", "keycloakSessionAuditLogger", "keycloakLoggingContextAccessor",
                "keycloakLoggingValueSanitizer", "keycloakSecurityClock");
    }

    @ParameterizedTest(name = "EXT-01 {0}: 사용자 빈을 올리면 라이브러리 빈이 빠지고 그 빈을 쓴다")
    @MethodSource("points")
    @SuppressWarnings({"unchecked", "rawtypes"})
    void userBeanReplacesLibraryBean(LibraryBean bean) {
        Object user = userBean(bean);
        assertThat(user).as("기본 컨텍스트에 %s가 있다", bean.name()).isNotNull();
        String userBeanName = bean.byName() ? bean.name() : "userBean";
        RUNNER.withBean(userBeanName, (Class) bean.type(), () -> user).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(userBeanName)).isSameAs(user);
            if (!bean.byName()) {
                assertThat(context.getBeanNamesForType(bean.type())).as("%s 타입 빈은 사용자 것 하나", bean.type().getSimpleName())
                    .containsExactly("userBean");
                assertThat(context.containsBean(bean.name())).isFalse();
            }
        });
    }

    @Test
    @DisplayName("EXT-05 자동 설정의 @Bean 메서드는 모두 @ConditionalOnMissingBean이 있다 (메서드에, 또는 그 메서드를 담은 설정 클래스에)")
    void everyBeanIsConditional() {
        assertThat(beanMethods()).isNotEmpty().allSatisfy(m -> assertThat(
                m.isAnnotationPresent(ConditionalOnMissingBean.class)
                    || m.getDeclaringClass().isAnnotationPresent(ConditionalOnMissingBean.class))
            .as("%s", m.getName()).isTrue());
    }
}
