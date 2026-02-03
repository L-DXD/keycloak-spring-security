package com.ids.keycloak.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * OncePerRequestFilter의 ASYNC 디스패치 동작을 검증하는 테스트입니다.
 *
 * <p>이 테스트는 shouldNotFilterAsyncDispatch() = false 설정만으로는
 * ASYNC 디스패치에서 필터가 재실행되지 않음을 증명합니다.</p>
 */
class OncePerRequestFilterAsyncBehaviorTest {

    /**
     * Request 속성을 저장하는 맵을 사용하여 Mock Request를 생성합니다.
     */
    private HttpServletRequest createMockRequest(Map<String, Object> attributes, DispatcherType dispatcherType) {
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getDispatcherType()).thenReturn(dispatcherType);
        when(request.getAttribute(org.mockito.ArgumentMatchers.anyString()))
            .thenAnswer(inv -> attributes.get(inv.getArgument(0)));
        org.mockito.Mockito.doAnswer(inv -> {
            attributes.put(inv.getArgument(0), inv.getArgument(1));
            return null;
        }).when(request).setAttribute(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any());
        org.mockito.Mockito.doAnswer(inv -> {
            attributes.remove(inv.getArgument(0));
            return null;
        }).when(request).removeAttribute(org.mockito.ArgumentMatchers.anyString());

        return request;
    }

    @Test
    @DisplayName("shouldNotFilterAsyncDispatch=false면 ASYNC 디스패치에서도 필터가 재실행됨")
    void async_dispatch_with_shouldNotFilterAsyncDispatch_false_executes_filter() throws Exception {
        // Given
        AtomicInteger filterExecutionCount = new AtomicInteger(0);

        OncePerRequestFilter filter = new OncePerRequestFilter() {
            @Override
            protected boolean shouldNotFilterAsyncDispatch() {
                return false; // ASYNC에서도 필터 실행하도록 설정
            }

            @Override
            protected void doFilterInternal(HttpServletRequest request,
                    HttpServletResponse response, FilterChain chain)
                    throws ServletException, IOException {
                filterExecutionCount.incrementAndGet();
                chain.doFilter(request, response);
            }
        };

        // 같은 속성 맵을 공유하는 request (같은 request 객체 시뮬레이션)
        Map<String, Object> sharedAttributes = new HashMap<>();
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        // When - REQUEST 디스패치
        HttpServletRequest requestForRequest = createMockRequest(sharedAttributes, DispatcherType.REQUEST);
        filter.doFilter(requestForRequest, response, chain);

        // Then - 필터 1번 실행
        assertThat(filterExecutionCount.get()).isEqualTo(1);

        // When - ASYNC 디스패치
        // OncePerRequestFilter는 finally 블록에서 ALREADY_FILTERED 속성을 제거하므로
        // shouldNotFilterAsyncDispatch()=false일 때 ASYNC에서도 필터가 재실행됨
        HttpServletRequest requestForAsync = createMockRequest(sharedAttributes, DispatcherType.ASYNC);
        filter.doFilter(requestForAsync, response, chain);

        // Then - 필터가 재실행됨! (shouldNotFilterAsyncDispatch=false이고 속성이 제거됐으므로)
        assertThat(filterExecutionCount.get())
            .as("shouldNotFilterAsyncDispatch=false면 ASYNC에서 필터가 재실행됨")
            .isEqualTo(2);
    }

    @Test
    @DisplayName("shouldNotFilterAsyncDispatch=true(기본값)면 ASYNC 디스패치에서 필터가 건너뛰어짐")
    void async_dispatch_with_shouldNotFilterAsyncDispatch_true_skips_filter() throws Exception {
        // Given
        AtomicInteger filterExecutionCount = new AtomicInteger(0);

        OncePerRequestFilter filter = new OncePerRequestFilter() {
            @Override
            protected boolean shouldNotFilterAsyncDispatch() {
                return true; // 기본값: ASYNC에서 필터 건너뜀
            }

            @Override
            protected void doFilterInternal(HttpServletRequest request,
                    HttpServletResponse response, FilterChain chain)
                    throws ServletException, IOException {
                filterExecutionCount.incrementAndGet();
                chain.doFilter(request, response);
            }
        };

        Map<String, Object> sharedAttributes = new HashMap<>();
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        // When - REQUEST 디스패치
        HttpServletRequest requestForRequest = createMockRequest(sharedAttributes, DispatcherType.REQUEST);
        filter.doFilter(requestForRequest, response, chain);

        assertThat(filterExecutionCount.get()).isEqualTo(1);

        // When - ASYNC 디스패치
        HttpServletRequest requestForAsync = createMockRequest(sharedAttributes, DispatcherType.ASYNC);
        filter.doFilter(requestForAsync, response, chain);

        // Then - 필터가 건너뛰어짐 (shouldNotFilterAsyncDispatch=true)
        assertThat(filterExecutionCount.get())
            .as("shouldNotFilterAsyncDispatch=true면 ASYNC에서 필터가 건너뛰어짐")
            .isEqualTo(1);
    }

    @Test
    @DisplayName("새로운 request 객체(다른 속성)면 ASYNC 디스패치에서도 필터가 실행됨")
    void async_dispatch_with_new_request_executes_filter() throws Exception {
        // Given
        AtomicInteger filterExecutionCount = new AtomicInteger(0);

        OncePerRequestFilter filter = new OncePerRequestFilter() {
            @Override
            protected boolean shouldNotFilterAsyncDispatch() {
                return false;
            }

            @Override
            protected void doFilterInternal(HttpServletRequest request,
                    HttpServletResponse response, FilterChain chain)
                    throws ServletException, IOException {
                filterExecutionCount.incrementAndGet();
                chain.doFilter(request, response);
            }
        };

        FilterChain chain = mock(FilterChain.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        // When - REQUEST 디스패치
        HttpServletRequest request1 = createMockRequest(new HashMap<>(), DispatcherType.REQUEST);
        filter.doFilter(request1, response, chain);

        assertThat(filterExecutionCount.get()).isEqualTo(1);

        // When - 새로운 속성 맵을 사용하는 ASYNC 디스패치 (다른 request)
        HttpServletRequest request2 = createMockRequest(new HashMap<>(), DispatcherType.ASYNC);
        filter.doFilter(request2, response, chain);

        // Then - 필터가 실행됨
        assertThat(filterExecutionCount.get())
            .as("새로운 request 객체면 필터가 실행됨")
            .isEqualTo(2);
    }

    @Test
    @DisplayName("ALREADY_FILTERED 속성을 제거하면 ASYNC에서 필터가 재실행됨")
    void removing_already_filtered_attribute_allows_reexecution() throws Exception {
        // Given
        AtomicInteger filterExecutionCount = new AtomicInteger(0);
        String filterName = "testFilter";

        OncePerRequestFilter filter = new OncePerRequestFilter() {
            @Override
            protected boolean shouldNotFilterAsyncDispatch() {
                return false;
            }

            @Override
            protected String getFilterName() {
                return filterName;
            }

            @Override
            protected void doFilterInternal(HttpServletRequest request,
                    HttpServletResponse response, FilterChain chain)
                    throws ServletException, IOException {
                filterExecutionCount.incrementAndGet();
                chain.doFilter(request, response);
            }
        };

        Map<String, Object> sharedAttributes = new HashMap<>();
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        // When - REQUEST 디스패치
        HttpServletRequest requestForRequest = createMockRequest(sharedAttributes, DispatcherType.REQUEST);
        filter.doFilter(requestForRequest, response, chain);

        assertThat(filterExecutionCount.get()).isEqualTo(1);

        // ALREADY_FILTERED 속성 제거
        String alreadyFilteredAttr = filterName + OncePerRequestFilter.ALREADY_FILTERED_SUFFIX;
        sharedAttributes.remove(alreadyFilteredAttr);

        // When - ASYNC 디스패치
        HttpServletRequest requestForAsync = createMockRequest(sharedAttributes, DispatcherType.ASYNC);
        filter.doFilter(requestForAsync, response, chain);

        // Then - 필터가 재실행됨
        assertThat(filterExecutionCount.get())
            .as("ALREADY_FILTERED 속성을 제거하면 필터가 재실행됨")
            .isEqualTo(2);
    }
}
