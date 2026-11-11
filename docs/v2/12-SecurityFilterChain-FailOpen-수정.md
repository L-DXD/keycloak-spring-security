# 12. SecurityFilterChain Fail-Open 수정 (v1.5.0)

> **보안 수정 (Security Fix)** — CVSS v3.1 **8.1 High** (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`)
> CWE-1188 (Insecure Default Initialization of Resource), CWE-863 (Incorrect Authorization)

## 1. 배경 — 무엇이 문제였나

`KeycloakServletAutoConfiguration`이 등록하는 `keycloakSecurityFilterChain` Bean은
과거 다음 조건으로 등록되었습니다.

```java
@Bean
@ConditionalOnMissingBean(SecurityFilterChain.class)   // ⚠️ Fail-Open
public SecurityFilterChain keycloakSecurityFilterChain(...) { ... }
```

`@ConditionalOnMissingBean(SecurityFilterChain.class)`는 **컨텍스트에 `SecurityFilterChain` 타입 Bean이
하나도 없을 때만** Keycloak 체인을 등록합니다. 따라서 사용자가 actuator 분리, 관리 API, SSO 전용 등의 목적으로
**자체 `SecurityFilterChain`을 단 하나라도 추가하는 순간** Keycloak의 전체 필터 체인(인증 필터·Bearer
Introspect·AuthorizationManager·CSRF 설정 등)이 **통째로 비활성화**되었습니다.

Spring Boot 환경에서 `/actuator/**` 경로 분리는 매우 흔한 패턴이라, 이 조건은 현실적으로 도달 가능하며
도달 시 **비즈니스 API가 인증 없이 노출**됩니다(Fail-Open).

### 재현 시나리오 (수정 전)
1. 앱이 `spring-boot-starter-actuator` 추가.
2. 사용자가 `/actuator/**`를 별도 정책으로 묶기 위해 `@Bean SecurityFilterChain actuatorChain(...)` 등록.
3. `@ConditionalOnMissingBean(SecurityFilterChain.class)` 조건 실패 → Keycloak 체인 **미등록**.
4. 비즈니스 API가 인증 필터 없이 노출.

## 2. 수정 내용 (v1.5.0)

```java
@Bean("keycloakSecurityFilterChain")
@ConditionalOnMissingBean(name = "keycloakSecurityFilterChain")
@ConditionalOnProperty(prefix = "keycloak.security", name = "auto-filter-chain",
                       havingValue = "true", matchIfMissing = true)
@Order(Ordered.LOWEST_PRECEDENCE)
public SecurityFilterChain keycloakSecurityFilterChain(...) throws Exception {
    http.securityMatcher(KeycloakSecurityMatcherFactory.from(securityProperties.getMatcher()));
    ...
}
```

| 변경 | 효과 |
|------|------|
| **Bean 이름 기반 조건** `@ConditionalOnMissingBean(name = "keycloakSecurityFilterChain")` | 사용자가 다른 `SecurityFilterChain`을 추가해도 Keycloak 체인이 **함께 등록**되어 공존합니다. (타입 충돌로 꺼지지 않음) |
| **`securityMatcher` 경로 분리** | Keycloak 체인이 담당할 경로를 명시적으로 선언합니다(기본 `/**`). 사용자가 더 구체적인 matcher(예: `/actuator/**`)를 가진 체인을 등록하면 그 경로는 사용자 체인이 담당합니다. |
| **`@Order(LOWEST_PRECEDENCE)`** | catch-all 체인이므로 가장 낮은 우선순위로 두어, 사용자의 구체적 체인이 먼저 평가되도록 합니다. |
| **`@ConditionalOnProperty(matchIfMissing = true)`** | 이중 안전망. `keycloak.security.auto-filter-chain=false`로 **명시적으로 끈 경우에만** 미등록됩니다(기본은 등록). |

> ⚠️ **`@Order` 방향에 주의**: Spring Security의 다중 `SecurityFilterChain`은 `@Order` **오름차순**으로 평가하고
> **첫 번째로 매칭되는 체인**이 요청을 처리합니다. Keycloak 체인은 `/**`(catch-all)이므로 반드시
> `LOWEST_PRECEDENCE`(맨 뒤)여야 사용자의 구체적 체인이 우선합니다. `LOWEST_PRECEDENCE - 100` 같은 값을 쓰면
> Keycloak이 먼저 매칭해버려 경로 분리가 깨집니다.

## 3. 신규 설정 프로퍼티

```yaml
keycloak:
  security:
    # Keycloak 기본 SecurityFilterChain 자동 등록 여부 (기본: true)
    # false면 Keycloak 기본 체인을 등록하지 않고 사용자가 전체 구성을 책임진다.
    auto-filter-chain: true

    # Keycloak 체인이 담당할 경로 (기본: 전체 /**)
    matcher:
      include:
        - /**
      exclude:
        - /actuator/**     # 이 경로는 사용자가 등록한 다른 체인이 담당
        - /public/**
```

| 프로퍼티 | 기본값 | 설명 |
|----------|--------|------|
| `keycloak.security.auto-filter-chain` | `true` | Keycloak 기본 체인 자동 등록 여부 |
| `keycloak.security.matcher.include` | `["/**"]` | Keycloak 체인 담당 포함 경로(Ant) |
| `keycloak.security.matcher.exclude` | `[]` | Keycloak 체인에서 제외할 경로(Ant) — 다른 체인이 담당 |

## 4. Migration 가이드 (v1.4.x → v1.5.0)

### 기존 사용자 (커스텀 SecurityFilterChain 없음)
**조치 불필요.** 기본값(`auto-filter-chain=true`, `matcher.include=/**`)으로 기존과 **동일하게 동작**합니다.

### actuator 등 별도 체인을 쓰던 사용자
이전에는 사용자 체인을 추가하면 Keycloak이 (의도치 않게) 꺼졌습니다. v1.5.0부터는 **Keycloak 체인이 함께 살아납니다.**

1. **권장 (경로 분리)**: 사용자 체인에 `securityMatcher("/actuator/**")`를 명시하고, Keycloak이 그 경로를 건드리지
   않도록 `keycloak.security.matcher.exclude: [/actuator/**]`를 설정합니다.

   ```java
   @Bean
   @Order(0)   // Keycloak(LOWEST_PRECEDENCE)보다 앞
   SecurityFilterChain actuatorChain(HttpSecurity http) throws Exception {
       http.securityMatcher("/actuator/**")
           .authorizeHttpRequests(a -> a.anyRequest().permitAll());
       return http.build();
   }
   ```

2. **호환 모드 (opt-out)**: 이전처럼 Keycloak 기본 체인을 끄고 전체를 직접 구성하려면:

   ```yaml
   keycloak:
     security:
       auto-filter-chain: false
   ```

> ⚠️ **Breaking change 주의**: 기존에 "사용자 체인 추가 → Keycloak 자동 비활성화"라는 **숨은 동작에 의존**하던
> 앱은, v1.5.0에서 Keycloak 체인이 활성화되어 보호 경로에서 401/403이 증가할 수 있습니다. 이 경우
> 위 1(경로 분리) 또는 2(opt-out)로 대응하세요. minor bump(1.4.x → 1.5.0)인 이유입니다.

## 5. 검증 (테스트)

| 테스트 | 검증 내용 |
|--------|-----------|
| `KeycloakSecurityMatcherFactoryTest` | include/exclude → RequestMatcher 매칭 동작 (경로 분리 핵심 로직) |
| `KeycloakSecurityFilterChainConditionsTest` | Bean 조건/순서 어노테이션 고정 — (a) 기본 등록, (b) 사용자 체인 공존, (c) opt-out, `@Order` 맨 뒤 |
