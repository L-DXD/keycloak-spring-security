//package com.ids.keycloak.security.web.reactive;
//
//import com.ids.keycloak.security.logging.LoggingContextKeys;
//import com.ids.keycloak.security.logging.WebFluxContextAccessor;
//import org.springframework.http.server.reactive.ServerHttpRequest;
//import org.springframework.web.server.ServerWebExchange;
//import org.springframework.web.server.WebFilter;
//import org.springframework.web.server.WebFilterChain;
//import reactor.core.publisher.Mono;
//import reactor.util.context.Context;
//
//import java.net.InetSocketAddress;
//import java.util.Optional;
//import java.util.UUID;
//
///**
// * 요청 시작 시 기본 메타데이터를 Reactor Context에 주입하는 WebFilter.
// * <p>
// * SecurityWebFilterChain 최상단에 위치하여 인증 실패 요청도 추적 가능하게 합니다.
// * <ul>
// *   <li>{@code traceId}: X-Request-Id 헤더 또는 자동 생성 UUID</li>
// *   <li>{@code httpMethod}: HTTP 메서드 (GET, POST 등)</li>
// *   <li>{@code requestUri}: 요청 경로</li>
// *   <li>{@code clientIp}: 클라이언트 IP 주소</li>
// * </ul>
// * <p>
// * 요청이 완료되면 doFinally에서 MDC를 정리합니다.
// *
// * @author LeeBongSeung
// * @since 1.0.0
// * @see MdcAuthenticationWebFilter
// */
//public class MdcRequestWebFilter implements WebFilter {
//
//    private static final String X_REQUEST_ID_HEADER = "X-Request-Id";
//    private static final String X_FORWARDED_FOR_HEADER = "X-Forwarded-For";
//
//    @Override
//    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
//        return chain.filter(exchange)
//                .contextWrite(context -> populateRequestContext(context, exchange))
//                .transformDeferredContextual((mono, context) ->
//                        mono.doOnEach(signal -> {
//                            if (!signal.isOnComplete()) {
//                                WebFluxContextAccessor.syncToMdc(context);
//                            }
//                        }).doFinally(signalType -> WebFluxContextAccessor.clearMdc())
//                );
//    }
//
//    private Context populateRequestContext(Context context, ServerWebExchange exchange) {
//        ServerHttpRequest request = exchange.getRequest();
//
//        // traceId 설정 (헤더 우선, 없으면 자동 생성)
//        String traceId = Optional.ofNullable(request.getHeaders().getFirst(X_REQUEST_ID_HEADER))
//                .filter(s -> !s.isBlank())
//                .orElseGet(() -> UUID.randomUUID().toString());
//        context = WebFluxContextAccessor.put(context, LoggingContextKeys.TRACE_ID, traceId);
//
//        // 요청 메타데이터
//        if (request.getMethod() != null) {
//            context = WebFluxContextAccessor.put(context, LoggingContextKeys.HTTP_METHOD,
//                    request.getMethod().name());
//        }
//        context = WebFluxContextAccessor.put(context, LoggingContextKeys.REQUEST_URI,
//                request.getPath().value());
//        context = WebFluxContextAccessor.put(context, LoggingContextKeys.QUERY_STRING,
//                request.getURI().getRawQuery());
//        context = WebFluxContextAccessor.put(context, LoggingContextKeys.CLIENT_IP,
//                getClientIp(request));
//
//        return context;
//    }
//
//    private String getClientIp(ServerHttpRequest request) {
//        String xff = request.getHeaders().getFirst(X_FORWARDED_FOR_HEADER);
//        if (xff != null && !xff.isBlank()) {
//            // X-Forwarded-For의 첫 번째 IP가 실제 클라이언트 IP
//            return xff.split(",")[0].trim();
//        }
//
//        InetSocketAddress remoteAddress = request.getRemoteAddress();
//        if (remoteAddress != null && remoteAddress.getAddress() != null) {
//            return remoteAddress.getAddress().getHostAddress();
//        }
//
//        return "unknown";
//    }
//}
