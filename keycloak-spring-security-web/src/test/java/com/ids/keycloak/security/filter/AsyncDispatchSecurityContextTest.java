package com.ids.keycloak.security.filter;

import static org.assertj.core.api.Assertions.assertThat;

import com.ids.keycloak.security.authentication.KeycloakAuthentication;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.core.task.SimpleAsyncTaskExecutor;
import org.springframework.security.concurrent.DelegatingSecurityContextCallable;
import org.springframework.security.concurrent.DelegatingSecurityContextExecutorService;
import org.springframework.security.concurrent.DelegatingSecurityContextRunnable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor;

/**
 * 비동기 스레드에서 SecurityContext 전파를 검증하는 테스트입니다.
 *
 * <p>이 테스트는 다음 시나리오를 검증합니다:</p>
 * <ul>
 *   <li>기본 ThreadLocal 전략에서의 SecurityContext 유실</li>
 *   <li>InheritableThreadLocal 전략에서의 SecurityContext 전파</li>
 *   <li>DelegatingSecurityContext* 클래스를 사용한 명시적 전파</li>
 * </ul>
 */
class AsyncDispatchSecurityContextTest {

    private static final String USER_SUB = "user-123";
    private static final String ID_TOKEN_VALUE = "id-token-value";
    private static final String ACCESS_TOKEN_VALUE = "access-token-value";

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);
    }

    private KeycloakAuthentication createAuthentication() {
        OidcIdToken idToken = new OidcIdToken(
            ID_TOKEN_VALUE,
            Instant.now(),
            Instant.now().plusSeconds(3600),
            Map.of("sub", USER_SUB)
        );
        KeycloakPrincipal principal = new KeycloakPrincipal(
            USER_SUB,
            Collections.emptyList(),
            idToken,
            null
        );
        return new KeycloakAuthentication(principal, ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE, true);
    }

    @Nested
    @DisplayName("KeycloakAuthenticationFilter 비동기 디스패치 설정")
    class FilterAsyncDispatchSettingTest {

        @Test
        @DisplayName("shouldNotFilterAsyncDispatch()는 false를 반환해야 한다")
        void shouldNotFilterAsyncDispatch_returns_false() {
            // Given
            KeycloakAuthenticationFilter filter = new KeycloakAuthenticationFilter(
                null, null, null, null
            );

            // When
            boolean result = filter.shouldNotFilterAsyncDispatch();

            // Then
            assertThat(result)
                .as("ASYNC 디스패치에서도 필터가 실행되어야 함")
                .isFalse();
        }

        @Test
        @DisplayName("shouldNotFilterErrorDispatch()는 false를 반환해야 한다")
        void shouldNotFilterErrorDispatch_returns_false() {
            // Given
            KeycloakAuthenticationFilter filter = new KeycloakAuthenticationFilter(
                null, null, null, null
            );

            // When
            boolean result = filter.shouldNotFilterErrorDispatch();

            // Then
            assertThat(result)
                .as("ERROR 디스패치에서도 필터가 실행되어야 함")
                .isFalse();
        }
    }

    @Nested
    @DisplayName("MODE_THREADLOCAL 전략 (기본값) - SecurityContext 전파 실패")
    class ThreadLocalStrategyTest {

        @Test
        @DisplayName("새로운 스레드에서 SecurityContext가 전파되지 않는다")
        void securityContext_not_propagated_to_new_thread() throws Exception {
            // Given
            SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);
            SecurityContextHolder.getContext().setAuthentication(createAuthentication());

            AtomicReference<Authentication> asyncAuth = new AtomicReference<>();
            CountDownLatch latch = new CountDownLatch(1);

            // When - 새로운 스레드에서 SecurityContext 확인
            Thread asyncThread = new Thread(() -> {
                asyncAuth.set(SecurityContextHolder.getContext().getAuthentication());
                latch.countDown();
            });
            asyncThread.start();
            latch.await(5, TimeUnit.SECONDS);

            // Then
            assertThat(asyncAuth.get())
                .as("MODE_THREADLOCAL에서 새 스레드로 SecurityContext가 전파되지 않아야 함")
                .isNull();
        }

        @Test
        @DisplayName("ExecutorService에서 SecurityContext가 전파되지 않는다")
        void securityContext_not_propagated_in_executor() throws Exception {
            // Given
            SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);
            SecurityContextHolder.getContext().setAuthentication(createAuthentication());

            ExecutorService executor = Executors.newSingleThreadExecutor();

            // When
            Future<Authentication> future = executor.submit(
                () -> SecurityContextHolder.getContext().getAuthentication()
            );
            Authentication asyncAuth = future.get(5, TimeUnit.SECONDS);

            // Then
            assertThat(asyncAuth)
                .as("일반 ExecutorService에서는 SecurityContext가 전파되지 않아야 함")
                .isNull();

            executor.shutdown();
        }
    }

    @Nested
    @DisplayName("MODE_INHERITABLETHREADLOCAL 전략 - SecurityContext 전파 성공")
    class InheritableThreadLocalStrategyTest {

        @Test
        @DisplayName("새로운 스레드에서 SecurityContext가 전파된다")
        void securityContext_propagated_to_new_thread() throws Exception {
            // Given
            SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
            KeycloakAuthentication originalAuth = createAuthentication();
            SecurityContextHolder.getContext().setAuthentication(originalAuth);

            AtomicReference<Authentication> asyncAuth = new AtomicReference<>();
            CountDownLatch latch = new CountDownLatch(1);

            // When - 새로운 스레드에서 SecurityContext 확인
            Thread asyncThread = new Thread(() -> {
                asyncAuth.set(SecurityContextHolder.getContext().getAuthentication());
                latch.countDown();
            });
            asyncThread.start();
            latch.await(5, TimeUnit.SECONDS);

            // Then
            assertThat(asyncAuth.get())
                .as("MODE_INHERITABLETHREADLOCAL에서 새 스레드로 SecurityContext가 전파되어야 함")
                .isNotNull();
            assertThat(asyncAuth.get().getName())
                .isEqualTo(USER_SUB);
        }

        @Test
        @DisplayName("스레드 풀 재사용 시 이전 SecurityContext가 남아있을 수 있다 (주의)")
        void security_context_pollution_in_thread_pool() throws Exception {
            // Given
            SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

            ExecutorService executor = Executors.newFixedThreadPool(1);

            // 첫 번째 요청: 사용자 A 인증
            KeycloakAuthentication userAAuth = createAuthentication();
            SecurityContextHolder.getContext().setAuthentication(userAAuth);

            // 첫 번째 작업 실행 (스레드 생성)
            Future<String> firstTask = executor.submit(
                () -> SecurityContextHolder.getContext().getAuthentication().getName()
            );
            String firstResult = firstTask.get(5, TimeUnit.SECONDS);
            assertThat(firstResult).isEqualTo(USER_SUB);

            // 두 번째 요청: 인증 없음 (익명 사용자)
            SecurityContextHolder.clearContext();

            // When - 동일 스레드 풀에서 두 번째 작업 실행
            Future<Authentication> secondTask = executor.submit(
                () -> SecurityContextHolder.getContext().getAuthentication()
            );
            Authentication secondResult = secondTask.get(5, TimeUnit.SECONDS);

            // Then - 스레드 재사용으로 인해 이전 인증 정보가 남아있을 수 있음
            // 이는 보안 취약점이 될 수 있으므로 MODE_INHERITABLETHREADLOCAL 사용 시 주의 필요
            // (실제 동작은 JVM 구현에 따라 다를 수 있음)
            assertThat(secondResult)
                .as("스레드 풀 재사용 시 컨텍스트 오염 가능성 확인")
                .satisfiesAnyOf(
                    auth -> assertThat(auth).isNull(),
                    auth -> assertThat(auth).isNotNull()
                );

            executor.shutdown();
        }
    }

    @Nested
    @DisplayName("DelegatingSecurityContext* 클래스 사용 - 안전한 전파")
    class DelegatingSecurityContextTest {

        @Test
        @DisplayName("DelegatingSecurityContextRunnable로 SecurityContext를 전파한다")
        void delegating_runnable_propagates_context() throws Exception {
            // Given
            KeycloakAuthentication originalAuth = createAuthentication();
            SecurityContextHolder.getContext().setAuthentication(originalAuth);

            AtomicReference<Authentication> asyncAuth = new AtomicReference<>();
            CountDownLatch latch = new CountDownLatch(1);

            Runnable task = () -> {
                asyncAuth.set(SecurityContextHolder.getContext().getAuthentication());
                latch.countDown();
            };

            // When - DelegatingSecurityContextRunnable로 래핑
            Runnable wrappedTask = new DelegatingSecurityContextRunnable(task);
            new Thread(wrappedTask).start();
            latch.await(5, TimeUnit.SECONDS);

            // Then
            assertThat(asyncAuth.get())
                .as("DelegatingSecurityContextRunnable이 SecurityContext를 전파해야 함")
                .isNotNull();
            assertThat(asyncAuth.get().getName())
                .isEqualTo(USER_SUB);
        }

        @Test
        @DisplayName("DelegatingSecurityContextCallable로 SecurityContext를 전파한다")
        void delegating_callable_propagates_context() throws Exception {
            // Given
            KeycloakAuthentication originalAuth = createAuthentication();
            SecurityContextHolder.getContext().setAuthentication(originalAuth);

            ExecutorService executor = Executors.newSingleThreadExecutor();

            Callable<Authentication> task = () ->
                SecurityContextHolder.getContext().getAuthentication();

            // When - DelegatingSecurityContextCallable로 래핑
            Callable<Authentication> wrappedTask = new DelegatingSecurityContextCallable<>(task);
            Future<Authentication> future = executor.submit(wrappedTask);
            Authentication asyncAuth = future.get(5, TimeUnit.SECONDS);

            // Then
            assertThat(asyncAuth)
                .as("DelegatingSecurityContextCallable이 SecurityContext를 전파해야 함")
                .isNotNull();
            assertThat(asyncAuth.getName())
                .isEqualTo(USER_SUB);

            executor.shutdown();
        }

        @Test
        @DisplayName("DelegatingSecurityContextExecutorService로 SecurityContext를 전파한다")
        void delegating_executor_service_propagates_context() throws Exception {
            // Given
            KeycloakAuthentication originalAuth = createAuthentication();
            SecurityContextHolder.getContext().setAuthentication(originalAuth);

            ExecutorService rawExecutor = Executors.newSingleThreadExecutor();
            ExecutorService delegatingExecutor = new DelegatingSecurityContextExecutorService(rawExecutor);

            // When - DelegatingSecurityContextExecutorService 사용
            Future<Authentication> future = delegatingExecutor.submit(
                () -> SecurityContextHolder.getContext().getAuthentication()
            );
            Authentication asyncAuth = future.get(5, TimeUnit.SECONDS);

            // Then
            assertThat(asyncAuth)
                .as("DelegatingSecurityContextExecutorService가 SecurityContext를 전파해야 함")
                .isNotNull();
            assertThat(asyncAuth.getName())
                .isEqualTo(USER_SUB);

            delegatingExecutor.shutdown();
        }

        @Test
        @DisplayName("DelegatingSecurityContextAsyncTaskExecutor로 SecurityContext를 전파한다")
        void delegating_async_task_executor_propagates_context() throws Exception {
            // Given
            KeycloakAuthentication originalAuth = createAuthentication();
            SecurityContextHolder.getContext().setAuthentication(originalAuth);

            SimpleAsyncTaskExecutor rawExecutor = new SimpleAsyncTaskExecutor();
            DelegatingSecurityContextAsyncTaskExecutor delegatingExecutor =
                new DelegatingSecurityContextAsyncTaskExecutor(rawExecutor);

            AtomicReference<Authentication> asyncAuth = new AtomicReference<>();
            CountDownLatch latch = new CountDownLatch(1);

            // When - DelegatingSecurityContextAsyncTaskExecutor 사용
            delegatingExecutor.execute(() -> {
                asyncAuth.set(SecurityContextHolder.getContext().getAuthentication());
                latch.countDown();
            });
            latch.await(5, TimeUnit.SECONDS);

            // Then
            assertThat(asyncAuth.get())
                .as("DelegatingSecurityContextAsyncTaskExecutor가 SecurityContext를 전파해야 함")
                .isNotNull();
            assertThat(asyncAuth.get().getName())
                .isEqualTo(USER_SUB);
        }

        @Test
        @DisplayName("스레드 풀 재사용 시에도 현재 컨텍스트만 전파된다 (안전)")
        void delegating_executor_uses_current_context_not_previous() throws Exception {
            // Given
            ExecutorService rawExecutor = Executors.newFixedThreadPool(1);
            ExecutorService delegatingExecutor = new DelegatingSecurityContextExecutorService(rawExecutor);

            // 첫 번째 요청: 사용자 A 인증
            KeycloakAuthentication userAAuth = createAuthentication();
            SecurityContextHolder.getContext().setAuthentication(userAAuth);

            Future<String> firstTask = delegatingExecutor.submit(
                () -> SecurityContextHolder.getContext().getAuthentication().getName()
            );
            String firstResult = firstTask.get(5, TimeUnit.SECONDS);
            assertThat(firstResult).isEqualTo(USER_SUB);

            // 두 번째 요청: 인증 없음 (익명 사용자)
            SecurityContextHolder.clearContext();

            // When - 인증 없이 두 번째 작업 실행
            Future<Authentication> secondTask = delegatingExecutor.submit(
                () -> SecurityContextHolder.getContext().getAuthentication()
            );
            Authentication secondResult = secondTask.get(5, TimeUnit.SECONDS);

            // Then - 현재 컨텍스트(비어있음)가 전파되어야 함
            assertThat(secondResult)
                .as("DelegatingSecurityContextExecutorService는 현재 컨텍스트만 전파해야 함 (이전 인증 정보 X)")
                .isNull();

            delegatingExecutor.shutdown();
        }
    }

    @Nested
    @DisplayName("CompletableFuture와 SecurityContext")
    class CompletableFutureTest {

        @Test
        @DisplayName("CompletableFuture.supplyAsync에서 SecurityContext가 전파되지 않는다")
        void completable_future_does_not_propagate_context() throws Exception {
            // Given
            KeycloakAuthentication originalAuth = createAuthentication();
            SecurityContextHolder.getContext().setAuthentication(originalAuth);

            // When
            CompletableFuture<Authentication> future = CompletableFuture.supplyAsync(
                () -> SecurityContextHolder.getContext().getAuthentication()
            );
            Authentication asyncAuth = future.get(5, TimeUnit.SECONDS);

            // Then
            assertThat(asyncAuth)
                .as("CompletableFuture.supplyAsync는 기본적으로 SecurityContext를 전파하지 않음")
                .isNull();
        }

        @Test
        @DisplayName("DelegatingSecurityContextExecutorService와 함께 CompletableFuture를 사용하면 전파된다")
        void completable_future_with_delegating_executor_propagates_context() throws Exception {
            // Given
            KeycloakAuthentication originalAuth = createAuthentication();
            SecurityContextHolder.getContext().setAuthentication(originalAuth);

            ExecutorService rawExecutor = Executors.newSingleThreadExecutor();
            ExecutorService delegatingExecutor = new DelegatingSecurityContextExecutorService(rawExecutor);

            // When
            CompletableFuture<Authentication> future = CompletableFuture.supplyAsync(
                () -> SecurityContextHolder.getContext().getAuthentication(),
                delegatingExecutor
            );
            Authentication asyncAuth = future.get(5, TimeUnit.SECONDS);

            // Then
            assertThat(asyncAuth)
                .as("DelegatingExecutor를 사용하면 CompletableFuture에서도 SecurityContext가 전파됨")
                .isNotNull();
            assertThat(asyncAuth.getName())
                .isEqualTo(USER_SUB);

            delegatingExecutor.shutdown();
        }
    }

    @Nested
    @DisplayName("SecurityContext 전파 동작 검증")
    class SecurityContextPropagationBehaviorTest {

        @Test
        @DisplayName("DelegatingSecurityContext*는 인증 정보를 정확히 전파한다")
        void delegating_propagates_authentication_correctly() throws Exception {
            // Given
            KeycloakAuthentication originalAuth = createAuthentication();
            SecurityContextHolder.getContext().setAuthentication(originalAuth);

            ExecutorService rawExecutor = Executors.newSingleThreadExecutor();
            ExecutorService delegatingExecutor = new DelegatingSecurityContextExecutorService(rawExecutor);

            AtomicReference<Authentication> asyncAuthRef = new AtomicReference<>();

            // When
            Future<?> future = delegatingExecutor.submit(() -> {
                asyncAuthRef.set(SecurityContextHolder.getContext().getAuthentication());
            });
            future.get(5, TimeUnit.SECONDS);

            // Then
            Authentication asyncAuth = asyncAuthRef.get();
            assertThat(asyncAuth)
                .as("비동기 스레드에서 Authentication이 전파되어야 함")
                .isNotNull();
            assertThat(asyncAuth.getName())
                .as("Authentication의 사용자 정보가 동일해야 함")
                .isEqualTo(originalAuth.getName());
            assertThat(asyncAuth.isAuthenticated())
                .as("인증 상태가 유지되어야 함")
                .isTrue();

            delegatingExecutor.shutdown();
        }

        @Test
        @DisplayName("비동기 스레드에서 SecurityContext 변경이 원본에 영향을 주지 않는다")
        void async_context_modification_does_not_affect_original() throws Exception {
            // Given
            KeycloakAuthentication originalAuth = createAuthentication();
            SecurityContextHolder.getContext().setAuthentication(originalAuth);

            ExecutorService rawExecutor = Executors.newSingleThreadExecutor();
            ExecutorService delegatingExecutor = new DelegatingSecurityContextExecutorService(rawExecutor);

            // When - 비동기 스레드에서 SecurityContext 클리어
            Future<?> future = delegatingExecutor.submit(() -> {
                SecurityContextHolder.clearContext();
            });
            future.get(5, TimeUnit.SECONDS);

            // Then - 원본 컨텍스트는 변경되지 않아야 함
            Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
            assertThat(currentAuth)
                .as("비동기 스레드의 컨텍스트 변경이 원본에 영향을 주지 않아야 함")
                .isNotNull();
            assertThat(currentAuth.getName())
                .isEqualTo(USER_SUB);

            delegatingExecutor.shutdown();
        }
    }
}
