# 09. [Core] MDC 로깅 컨텍스트 추상화 설계

## 🎯 목표

**Web(Spring MVC)과 WebFlux 환경을 동시에 지원**하기 위해, MDC(Mapped Diagnostic Context)를 직접 컨텍스트 저장소로 사용하지 않고 **Context를 추상화**합니다.
MDC는 추상화된 Context의 **어댑터(Adapter)**로 격리하여, 각 환경에 맞는 컨텍스트 전파 메커니즘을 독립적으로 구현할 수 있도록 합니다.

---

## 📋 문제 정의: MDC의 한계

### ThreadLocal 기반 MDC의 근본적 문제

SLF4J의 MDC는 내부적으로 `ThreadLocal`을 사용합니다. 이는 **Web(Blocking)** 환경에서는 잘 동작하지만, **WebFlux(Non-blocking)** 환경에서는 심각한 문제를 야기합니다.

| 환경 | 스레드 모델 | MDC 동작 |
| :--- | :--- | :--- |
| **Web (Spring MVC)** | 요청당 1개 스레드 점유 | 정상 동작 |
| **WebFlux** | 이벤트 루프, 스레드 전환 빈번 | 컨텍스트 유실 |

### WebFlux 환경에서의 컨텍스트 유실 시나리오

```
[요청 시작] Thread-1: MDC.put("traceId", "abc123")
     │
     ▼
[비동기 연산] Mono.fromCallable(...).subscribeOn(Schedulers.boundedElastic())
     │
     ▼
[연산 실행] Thread-2: MDC.get("traceId") → null ❌ (컨텍스트 유실)
```

WebFlux에서는 `Schedulers`를 통해 스레드가 전환되면 `ThreadLocal`에 저장된 MDC 데이터가 새 스레드로 전파되지 않습니다.

---

## 📐 설계 원칙: Context 추상화

### 핵심 전략

```
┌─────────────────────────────────────────────────────────────┐
│                      Application Code                        │
│                  (Context 추상화 인터페이스 사용)              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  SecurityContext (추상화)                    │
│         interface SecurityContextAccessor                    │
│         interface SecurityContextHolder                      │
└─────────────────────────────────────────────────────────────┘
                              │
            ┌─────────────────┴─────────────────┐
            ▼                                   ▼
┌─────────────────────┐             ┌─────────────────────┐
│     Web Adapter     │             │   WebFlux Adapter   │
│   (ThreadLocal +    │             │  (Reactor Context   │
│    MDC 직접 사용)    │             │   + MDC Hook)       │
└─────────────────────┘             └─────────────────────┘
```

### 계층 분리 원칙

| 계층 | 모듈 | 책임 |
| :--- | :--- | :--- |
| **추상화 계층** | `core` | 컨텍스트 접근 인터페이스 정의 |
| **Web 구현** | `servlet` | ThreadLocal + MDC 직접 연동 |
| **WebFlux 구현** | `reactive` | Reactor Context + MDC Hook 연동 |

---

## 📦 Core 모듈 설계

### 1. 로깅 컨텍스트 인터페이스

```java
package com.ids.keycloak.security.logging;

/**
 * 로깅 컨텍스트에 데이터를 읽고 쓰는 추상화 인터페이스.
 * Web과 WebFlux 환경에서 각각 다르게 구현됩니다.
 */
public interface LoggingContextAccessor {

    /**
     * 컨텍스트에 키-값 쌍을 저장합니다.
     */
    void put(String key, String value);

    /**
     * 컨텍스트에서 값을 조회합니다.
     */
    String get(String key);

    /**
     * 컨텍스트에서 특정 키를 제거합니다.
     */
    void remove(String key);

    /**
     * 컨텍스트를 초기화합니다.
     */
    void clear();
}
```

### 2. 표준 컨텍스트 키 정의

```java
package com.ids.keycloak.security.logging;

/**
 * 라이브러리 전반에서 사용하는 표준 MDC 키를 정의합니다.
 */
public final class LoggingContextKeys {

    private LoggingContextKeys() {}

    // ===== 요청 메타데이터 (인증 전 설정) =====

    /** 요청 추적 ID (X-Request-Id 또는 자동 생성) */
    public static final String TRACE_ID = "traceId";

    /** HTTP 메서드 (GET, POST, PUT, DELETE 등) */
    public static final String HTTP_METHOD = "httpMethod";

    /** 요청 URI */
    public static final String REQUEST_URI = "requestUri";

    /** 클라이언트 IP 주소 */
    public static final String CLIENT_IP = "clientIp";

    // ===== 인증 정보 (인증 후 설정) =====

    /** 인증된 사용자 ID (Keycloak sub claim) */
    public static final String USER_ID = "userId";

    /** 인증된 사용자 이름 (preferred_username) */
    public static final String USERNAME = "username";

    /** Keycloak 세션 ID (sid claim) */
    public static final String SESSION_ID = "sessionId";
}
```

### 필수 키 요약 (8개)

| 키 | 설정 시점 | 설명 |
|:---|:---|:---|
| `traceId` | 인증 전 | 요청 추적 ID |
| `httpMethod` | 인증 전 | HTTP 메서드 |
| `requestUri` | 인증 전 | 요청 경로 (쿼리스트링 제외) |
| `queryString` | 인증 전 | 쿼리스트링 (? 제외) |
| `clientIp` | 인증 전 | 클라이언트 IP |
| `userId` | 인증 후 | Keycloak sub claim |
| `username` | 인증 후 | preferred_username |
| `sessionId` | 인증 후 | Keycloak sid claim |

> ⚠️ **보안 주의**: `queryString`에는 민감한 정보(토큰, 비밀번호 등)가 포함될 수 있습니다.
> 운영 환경에서는 민감한 파라미터 마스킹 처리를 고려하세요.

### 3. 컨텍스트 전파 유틸리티

```java
package com.ids.keycloak.security.logging;

import java.util.Map;

/**
 * 컨텍스트 데이터를 스냅샷으로 캡처하고 복원하는 유틸리티.
 * 비동기 경계를 넘을 때 컨텍스트 전파에 사용됩니다.
 */
public interface LoggingContextPropagator {

    /**
     * 현재 컨텍스트의 스냅샷을 캡처합니다.
     */
    Map<String, String> capture();

    /**
     * 캡처된 스냅샷을 현재 컨텍스트에 복원합니다.
     */
    void restore(Map<String, String> snapshot);
}
```

---

## 📦 Web 모듈 설계

### 필터 구조: 2단계 설정

인증 실패 요청도 추적할 수 있도록, **2개의 필터**로 역할을 분리합니다.

```
[요청 시작]
    │
    ▼
┌─────────────────────────────────────────┐
│ MdcRequestFilter (인증 전, 최상단)       │
│ - traceId, httpMethod, requestUri,      │
│   clientIp 설정                         │
│ - finally: MDC.clear()                  │
└─────────────────────────────────────────┘
    │
    ▼
[Spring Security 인증 필터들...]
    │
    ▼
┌─────────────────────────────────────────┐
│ MdcAuthenticationFilter (인증 후)       │
│ - userId, username, sessionId 설정      │
└─────────────────────────────────────────┘
    │
    ▼
[Controller]
```

### MDC 직접 연동 어댑터

Web 환경에서는 요청당 하나의 스레드가 점유되므로, MDC를 직접 사용해도 안전합니다.

```java
package com.ids.keycloak.security.logging;

import org.slf4j.MDC;

/**
 * Web 환경용 MDC 직접 연동 어댑터.
 * ThreadLocal 기반 MDC를 그대로 활용합니다.
 */
public class WebMdcContextAccessor implements LoggingContextAccessor, LoggingContextPropagator {

    @Override
    public void put(String key, String value) {
        if (value != null) {
            MDC.put(key, value);
        }
    }

    @Override
    public String get(String key) {
        return MDC.get(key);
    }

    @Override
    public void remove(String key) {
        MDC.remove(key);
    }

    @Override
    public void clear() {
        MDC.clear();
    }
    
    // ... capture/restore 구현
}
```

### 1단계: 요청 메타데이터 필터 (인증 전)

```java
package com.ids.keycloak.security.servlet.filter;

/**
 * 요청 시작 시 기본 메타데이터를 MDC에 주입하는 필터.
 * SecurityFilterChain 최상단에 위치하여 인증 실패 요청도 추적 가능하게 합니다.
 */
public class MdcRequestFilter extends OncePerRequestFilter {

    private final LoggingContextAccessor contextAccessor;
    private final KeycloakSecurityProperties securityProperties;

    public MdcRequestFilter(LoggingContextAccessor contextAccessor, KeycloakSecurityProperties securityProperties) {
        this.contextAccessor = contextAccessor;
        this.securityProperties = securityProperties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) {
        try {
            populateRequestContext(request);
            chain.doFilter(request, response);
        } finally {
            contextAccessor.clear(); // 요청 완료 후 반드시 정리
        }
    }

    private void populateRequestContext(HttpServletRequest request) {
        // traceId 설정 (헤더 우선, 없으면 자동 생성)
        String traceId = Optional.ofNullable(request.getHeader("X-Request-Id"))
                                 .orElse(UUID.randomUUID().toString());
        contextAccessor.put(LoggingContextKeys.TRACE_ID, traceId);

        // 요청 메타데이터
        contextAccessor.put(LoggingContextKeys.HTTP_METHOD, request.getMethod());
        contextAccessor.put(LoggingContextKeys.REQUEST_URI, request.getRequestURI());
        contextAccessor.put(LoggingContextKeys.CLIENT_IP, getClientIp(request));

        // 쿼리 스트링 (설정에 따라 선택적 포함)
        if (securityProperties.getLogging().isIncludeQueryString()) {
            contextAccessor.put(LoggingContextKeys.QUERY_STRING, request.getQueryString());
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isEmpty()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
```

### 2단계: 인증 정보 필터 (인증 후)

```java
package com.ids.keycloak.security.servlet.filter;

/**
 * 인증 완료 후 사용자 정보를 MDC에 추가하는 필터.
 * SecurityFilterChain에서 인증 필터 이후에 위치해야 합니다.
 */
public class MdcAuthenticationFilter extends OncePerRequestFilter {

    private final LoggingContextAccessor contextAccessor;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) {
        populateAuthenticationContext();
        chain.doFilter(request, response);
        // clear는 MdcRequestFilter에서 담당
    }

    private void populateAuthenticationContext() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated()) {
            return;
        }

        if (auth instanceof AnonymousAuthenticationToken) {
            return;
        }

        // 인증 정보 설정
        contextAccessor.put(LoggingContextKeys.USER_ID, extractUserId(auth));
        contextAccessor.put(LoggingContextKeys.USERNAME, extractUsername(auth));
        contextAccessor.put(LoggingContextKeys.SESSION_ID, extractSessionId(auth));
    }

    private String extractUserId(Authentication auth) {
        // Keycloak sub claim 추출 로직
        if (auth.getPrincipal() instanceof OidcUser oidcUser) {
            return oidcUser.getSubject();
        }
        return null;
    }

    private String extractUsername(Authentication auth) {
        if (auth.getPrincipal() instanceof OidcUser oidcUser) {
            return oidcUser.getPreferredUsername();
        }
        return auth.getName();
    }

    private String extractSessionId(Authentication auth) {
        // Keycloak sid claim 추출 로직
        if (auth.getPrincipal() instanceof OidcUser oidcUser) {
            return oidcUser.getClaimAsString("sid");
        }
        return null;
    }
}
```

---

## 📦 WebFlux 모듈 설계

### 필터 구조: 2단계 설정

Web 모듈과 동일하게 **2개의 WebFilter**로 역할을 분리합니다.

```
[요청 시작]
    │
    ▼
┌─────────────────────────────────────────┐
│ MdcRequestWebFilter (인증 전, 최상단)    │
│ - traceId, httpMethod, requestUri,      │
│   clientIp를 Reactor Context에 설정     │
│ - doFinally: MDC.clear()                │
└─────────────────────────────────────────┘
    │
    ▼
[Spring Security WebFilter들...]
    │
    ▼
┌─────────────────────────────────────────┐
│ MdcAuthenticationWebFilter (인증 후)    │
│ - userId, username, sessionId를         │
│   Reactor Context에 추가                │
└─────────────────────────────────────────┘
    │
    ▼
[Controller]
```

### Reactor Context 기반 어댑터

WebFlux에서는 `Reactor Context`를 사용하여 비동기 경계를 넘어 컨텍스트를 전파합니다.

```java
package com.ids.keycloak.security.reactive.logging;

import reactor.util.context.Context;

/**
 * WebFlux 환경용 Reactor Context 기반 어댑터.
 * Reactor의 Context API를 통해 컨텍스트를 전파합니다.
 */
public class ReactiveContextAccessor {

    private static final String LOGGING_CONTEXT_KEY = "KEYCLOAK_LOGGING_CONTEXT";

    /**
     * Reactor Context에 로깅 데이터를 추가합니다.
     */
    public static Context put(Context context, String key, String value) {
        Map<String, String> loggingContext = context.getOrDefault(LOGGING_CONTEXT_KEY, new HashMap<>());
        Map<String, String> newContext = new HashMap<>(loggingContext);
        newContext.put(key, value);
        return context.put(LOGGING_CONTEXT_KEY, newContext);
    }

    /**
     * Reactor Context에서 로깅 데이터를 조회합니다.
     */
    public static String get(Context context, String key) {
        Map<String, String> loggingContext = context.getOrDefault(LOGGING_CONTEXT_KEY, Collections.emptyMap());
        return loggingContext.get(key);
    }

    /**
     * Reactor Context의 로깅 데이터를 MDC에 동기화합니다.
     * 실제 로깅 시점에 호출되어야 합니다.
     */
    public static void syncToMdc(Context context) {
        Map<String, String> loggingContext = context.getOrDefault(LOGGING_CONTEXT_KEY, Collections.emptyMap());
        loggingContext.forEach(MDC::put);
    }

    /**
     * MDC를 정리합니다.
     */
    public static void clearMdc() {
        MDC.clear();
    }
}
```

### Reactor Context Hook 설정

```java
package com.ids.keycloak.security.reactive.logging;

import reactor.core.publisher.Hooks;
import reactor.core.publisher.Operators;

/**
 * Reactor의 Context를 MDC에 자동으로 동기화하는 Hook 설정.
 * 애플리케이션 시작 시 한 번 호출되어야 합니다.
 */
public class ReactorMdcContextHook {

    private static final String HOOK_KEY = "keycloak-mdc-context-hook";

    /**
     * MDC 동기화 Hook을 등록합니다.
     */
    public static void register() {
        Hooks.onEachOperator(HOOK_KEY,
            Operators.lift((scannable, subscriber) ->
                new MdcContextSubscriber<>(subscriber)));
    }

    /**
     * Hook을 해제합니다.
     */
    public static void unregister() {
        Hooks.resetOnEachOperator(HOOK_KEY);
    }
}
```

### 1단계: 요청 메타데이터 WebFilter (인증 전)

```java
package com.ids.keycloak.security.reactive.filter;

/**
 * 요청 시작 시 기본 메타데이터를 Reactor Context에 주입하는 WebFilter.
 * SecurityWebFilterChain 최상단에 위치하여 인증 실패 요청도 추적 가능하게 합니다.
 */
public class MdcRequestWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return chain.filter(exchange)
            .contextWrite(context -> populateRequestContext(context, exchange))
            .transformDeferredContextual((mono, context) ->
                mono.doOnEach(signal -> {
                    if (!signal.isOnComplete()) {
                        ReactiveContextAccessor.syncToMdc(context);
                    }
                }).doFinally(signalType -> ReactiveContextAccessor.clearMdc())
            );
    }

    private Context populateRequestContext(Context context, ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();

        // traceId 설정 (헤더 우선, 없으면 자동 생성)
        String traceId = Optional.ofNullable(request.getHeaders().getFirst("X-Request-Id"))
                                 .orElse(UUID.randomUUID().toString());
        context = ReactiveContextAccessor.put(context, LoggingContextKeys.TRACE_ID, traceId);

        // 요청 메타데이터
        context = ReactiveContextAccessor.put(context, LoggingContextKeys.HTTP_METHOD,
            request.getMethod().name());
        context = ReactiveContextAccessor.put(context, LoggingContextKeys.REQUEST_URI,
            request.getPath().value());
        context = ReactiveContextAccessor.put(context, LoggingContextKeys.CLIENT_IP,
            getClientIp(request));

        return context;
    }

    private String getClientIp(ServerHttpRequest request) {
        String xff = request.getHeaders().getFirst("X-Forwarded-For");
        if (xff != null && !xff.isEmpty()) {
            return xff.split(",")[0].trim();
        }
        InetSocketAddress remoteAddress = request.getRemoteAddress();
        return remoteAddress != null ? remoteAddress.getAddress().getHostAddress() : "unknown";
    }
}
```

### 2단계: 인증 정보 WebFilter (인증 후)

```java
package com.ids.keycloak.security.reactive.filter;

/**
 * 인증 완료 후 사용자 정보를 Reactor Context에 추가하는 WebFilter.
 * SecurityWebFilterChain에서 인증 필터 이후에 위치해야 합니다.
 */
public class MdcAuthenticationWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
            .map(SecurityContext::getAuthentication)
            .filter(auth -> auth != null && auth.isAuthenticated())
            .filter(auth -> !(auth instanceof AnonymousAuthenticationToken))
            .flatMap(auth -> chain.filter(exchange)
                .contextWrite(context -> populateAuthenticationContext(context, auth)))
            .switchIfEmpty(chain.filter(exchange));
    }

    private Context populateAuthenticationContext(Context context, Authentication auth) {
        context = ReactiveContextAccessor.put(context, LoggingContextKeys.USER_ID,
            extractUserId(auth));
        context = ReactiveContextAccessor.put(context, LoggingContextKeys.USERNAME,
            extractUsername(auth));
        context = ReactiveContextAccessor.put(context, LoggingContextKeys.SESSION_ID,
            extractSessionId(auth));
        return context;
    }

    private String extractUserId(Authentication auth) {
        if (auth.getPrincipal() instanceof OidcUser oidcUser) {
            return oidcUser.getSubject();
        }
        return null;
    }

    private String extractUsername(Authentication auth) {
        if (auth.getPrincipal() instanceof OidcUser oidcUser) {
            return oidcUser.getPreferredUsername();
        }
        return auth.getName();
    }

    private String extractSessionId(Authentication auth) {
        if (auth.getPrincipal() instanceof OidcUser oidcUser) {
            return oidcUser.getClaimAsString("sid");
        }
        return null;
    }
}
```

---

## 📊 동작 비교

### Web 환경 흐름

```
[HTTP 요청]
    │
    ▼
[MdcRequestFilter] ─────────────────────────────────────┐
    │ MDC.put("traceId", "abc123")                      │
    │ MDC.put("httpMethod", "POST")                     │
    │ MDC.put("requestUri", "/api/users")               │
    │ MDC.put("clientIp", "192.168.1.1")                │
    ▼                                                   │
[Spring Security 인증 필터들...]                         │
    │                                                   │
    ▼                                                   │
[MdcAuthenticationFilter]                               │
    │ MDC.put("userId", "550e8400-...")                 │
    │ MDC.put("username", "hong.gildong")               │
    │ MDC.put("sessionId", "sess-abc-123")              │
    ▼                                                   │
[Controller/Service]                                    │
    │ log.info("Processing...")                         │
    │ → traceId=abc123, userId=550e8400-...,            │
    │   username=hong.gildong ✅                        │
    ▼                                                   │
[MdcRequestFilter.finally] ← MDC.clear() ───────────────┘
    │
    ▼
[응답 반환]
```

### 인증 실패 시 흐름

```
[HTTP 요청 (잘못된 토큰)]
    │
    ▼
[MdcRequestFilter]
    │ MDC.put("traceId", "abc123") ✅
    │ MDC.put("httpMethod", "GET") ✅
    ▼
[Spring Security 인증 필터]
    │ → 401 Unauthorized 반환
    │ → log.warn("Authentication failed")
    │   → traceId=abc123, clientIp=192.168.1.1 ✅ (추적 가능!)
    ▼
[MdcRequestFilter.finally] ← MDC.clear()
```

### WebFlux 환경 흐름

```
[HTTP 요청]
    │
    ▼
[MdcRequestWebFilter] ──────────────────────────────────┐
    │ Context.put("traceId", "abc123")                  │
    │ Context.put("httpMethod", "POST")                 │
    │ Context.put("requestUri", "/api/users")           │
    │ Context.put("clientIp", "192.168.1.1")            │
    ▼                                                   │
[Spring Security WebFilter들...]                        │
    │                                                   │
    ▼                                                   │
[MdcAuthenticationWebFilter]                            │
    │ Context.put("userId", "550e8400-...")             │
    │ Context.put("username", "hong.gildong")           │
    │ Context.put("sessionId", "sess-abc-123")          │
    ▼                                                   │
[Controller] Mono<Response>                             │
    │                                                   │
    ▼                                                   │
[Service] .flatMap(...) (스레드 전환 발생 가능)           │
    │ Reactor Context 전파 ✅                           │
    ▼                                                   │
[로깅 시점] syncToMdc(context)                          │
    │ → traceId=abc123, username=hong.gildong ✅        │
    ▼                                                   │
[doFinally] MDC.clear() ────────────────────────────────┘
```

---

## 🗂️ 모듈별 패키지 구조

```
keycloak-spring-security-core
└── com.ids.keycloak.security
    └── logging
        ├── LoggingContextAccessor.java      // 추상화 인터페이스
        ├── LoggingContextKeys.java          // 표준 키 상수 (7개)
        └── LoggingContextPropagator.java    // 전파 유틸리티

keycloak-spring-security-servlet
└── com.ids.keycloak.security.servlet
    ├── logging
    │   └── ServletMdcContextAccessor.java   // MDC 직접 어댑터
    └── filter
        ├── MdcRequestFilter.java            // 1단계: 요청 메타데이터 (인증 전)
        └── MdcAuthenticationFilter.java     // 2단계: 인증 정보 (인증 후)

keycloak-spring-security-reactive
└── com.ids.keycloak.security.reactive
    ├── logging
    │   ├── ReactiveContextAccessor.java     // Reactor Context 어댑터
    │   └── ReactorMdcContextHook.java       // Hook 설정
    └── filter
        ├── MdcRequestWebFilter.java         // 1단계: 요청 메타데이터 (인증 전)
        └── MdcAuthenticationWebFilter.java  // 2단계: 인증 정보 (인증 후)
```

---

## ✅ 인수 조건

### Core Module
- [ ] `LoggingContextAccessor` 인터페이스가 `core` 모듈에 정의되어야 한다.
- [ ] `LoggingContextKeys`에 7개 필수 키가 정의되어야 한다.
  - 요청 메타데이터: `traceId`, `httpMethod`, `requestUri`, `clientIp`
  - 인증 정보: `userId`, `username`, `sessionId`
- [ ] `LoggingContextPropagator` 인터페이스가 `core` 모듈에 정의되어야 한다.

### Web Module
- [ ] `ServletMdcContextAccessor`가 `LoggingContextAccessor`를 구현해야 한다.
- [ ] `MdcRequestFilter`가 인증 전(최상단)에 위치하여 요청 메타데이터를 설정해야 한다.
- [ ] `MdcAuthenticationFilter`가 인증 후에 위치하여 사용자 정보를 설정해야 한다.
- [ ] `MdcRequestFilter`의 finally 블록에서 MDC를 정리해야 한다.

### WebFlux Module
- [ ] `ReactiveContextAccessor`가 Reactor Context와 MDC 간 동기화를 지원해야 한다.
- [ ] `MdcRequestWebFilter`가 인증 전(최상단)에 위치하여 요청 메타데이터를 설정해야 한다.
- [ ] `MdcAuthenticationWebFilter`가 인증 후에 위치하여 사용자 정보를 설정해야 한다.
- [ ] 스레드 전환 후에도 Reactor Context를 통해 로깅 컨텍스트가 유지되어야 한다.

### 공통 테스트
- [ ] 인증 성공 시 7개 필수 키가 모두 로그에 출력되어야 한다.
- [ ] **인증 실패 시에도** traceId, httpMethod, requestUri, clientIp가 로그에 출력되어야 한다.
- [ ] WebFlux 환경에서 `Schedulers.boundedElastic()` 전환 후에도 컨텍스트가 유지되어야 한다.
- [ ] 요청 완료 후 MDC가 정리되어 다음 요청에 영향을 주지 않아야 한다.

---

## 📚 참고 자료

- [Reactor Context Documentation](https://projectreactor.io/docs/core/release/reference/#context)
- [Spring WebFlux Logging Context Propagation](https://spring.io/blog/2023/03/28/context-propagation-with-project-reactor-1-part-1)
- [SLF4J MDC Documentation](https://www.slf4j.org/api/org/slf4j/MDC.html)
