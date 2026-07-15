# Architecture & Development Guidelines

**English** | [한국어](README.ko.md)

**Guide for Adopting Developers**

- **[User Guide](docs/GUIDE.md)** — Quick start · Configuration reference · Feature guides · Migration · Troubleshooting
- **[Changelog](CHANGELOG.md)** — Added / Fixed / Deprecated / Security by version
- **[Security / Recommended Versions](SECURITY.md)** — Supported version matrix · Vulnerability reporting

> The document below covers **library contributor** architecture/development guidelines.

This document defines the architecture principles, project structure, deployment strategy, and configuration guide for the **Keycloak Spring Security Open Source Library**.
This project follows the **structure of the official Spring Security GitHub repository**, and aims to support both the **Servlet (Blocking)** and **Reactive (Non-blocking)** stacks.

---

## 1. Artifact Naming & Deployment

To prevent library identification conflicts during Maven Central deployment and to keep things clearly readable, the following rules are **strictly enforced**.
Using a plain noun (e.g., `core`, `servlet`) as an ArtifactId is prohibited.

### Coordinates
* **GroupId**: `com.ids.keycloak`
* **Version**: Semantic Versioning (ex: `1.0.0-SNAPSHOT`)

### ArtifactId Policy
Every module's ArtifactId must include the **`keycloak-spring-security-`** prefix.

| Module Role | Folder Name | **ArtifactId (Maven/Gradle)** | Description |
| :--- | :--- | :--- | :--- |
| **Root** | `root` | `keycloak-spring-security` | Manages the BOM and common build configuration |
| **Core** | `*-core` | **`keycloak-spring-security-core`** | Pure logic (POJO) with no external framework dependencies |
| **Servlet** | `*-servlet` | **`keycloak-spring-security-servlet`** | Implementation based on Spring MVC (Tomcat) |
| **Reactive** | `*-reactive` | **`keycloak-spring-security-reactive`** | Implementation based on Spring WebFlux (Netty) |
| **Servlet Starter** | `*-servlet-starter` | **`keycloak-spring-security-servlet-starter`** | Starter for Servlet (Spring MVC) environments |
| **Reactive Starter**| `*-reactive-starter`| **`keycloak-spring-security-reactive-starter`**| Starter for Reactive (WebFlux) environments |

> **Bad Practice (do not use):**
> * `com.ids.keycloak:servlet:1.0.0` (X) -> Can be confused with other libraries (e.g., Jakarta Servlet)
> * `com.ids.keycloak:core:1.0.0` (X) -> Not identifiable

---

## 2. Module Structure & Responsibility

We adopt a **Multi-Module** strategy, with each module's responsibility strictly separated.

### Core Module (`...-core`)
* **Role:** The heart of the business logic. Pure Java code with no dependency on Spring Web/Servlet/Reactive.
* **Key Features:** Token parsing, verification, authority mapping, domain models.
* **Constraint:** Importing `javax.servlet` or `org.springframework.web` packages is prohibited.

### Servlet Module (`...-servlet`)
* **Role:** Supports Blocking I/O based Spring MVC applications.
* **Dependencies:** `core`, `spring-security-web`, `jakarta.servlet-api`
* **Key Features:** `OncePerRequestFilter`, `AuthenticationProvider`, `AbstractHttpConfigurer`.

### Reactive Module (`...-reactive`)
* **Role:** Supports Non-blocking I/O based Spring WebFlux applications.
* **Dependencies:** `core`, `spring-security-webflux`, `reactor-core`
* **Key Features:** `ReactiveAuthenticationManager`, `ServerAuthenticationConverter`.

### Starter Modules (`...-servlet-starter`, `...-reactive-starter`)
* **Role:** Environment-specific entry points that let users adopt the library's functionality by adding a single dependency matching their own environment.
* **Structure:**
    * **`servlet-starter`:** Contains the `servlet` implementation module and its auto-configuration logic. Used in Servlet-based Spring MVC environments.
    * **`reactive-starter`:** Contains the `reactive` implementation module and its auto-configuration logic. Used in Reactive-based Spring WebFlux environments.
* **Note:** The former unified `starter` has been split into two environment-specific `starter` modules.

---

## 3. Package Structure Strategy

The package name is rooted at **`com.ids.keycloak.security`**, and is organized by **feature**, not by **layer**.

### Common Pattern
```text
com.ids.keycloak.security
  ├── config          // Configuration support (Configurer, Customizer)
  ├── authentication  // Authentication handling (Provider, Manager, Token)
  ├── authorization   // Authorization handling (Provider, Manager)
  ├── filter          // (Servlet only) Filter chain related
  ├── web             // (Reactive only) Web exchange handling
  ├── exception       // Exception handling
  └── util            // Utilities
```

### Core Module Detail
```text
├── token           // TokenVerifier, TokenParser
├── authority       // GrantedAuthoritiesMapper
└── model           // KeycloakUserDetails, KeycloakPrincipal
```

---

## 4. Development Principles

As an open-source library, **extensibility** is our top priority.

### Extension Points
1.  **Use `@ConditionalOnMissingBean`:**
   * Every Bean registration in a Starter carries this annotation, leaving room for users to override it.
2.  **Customizer Pattern:**
   * Configuration classes take a `Customizer<T>` argument, letting users add settings via lambda expressions.
3.  **Allow Inheritance:**
   * Avoid `final` classes except where required for security reasons.

### Coding Convention
1.  **Logging:**
   * `System.out.println` is strictly forbidden.
   * Use the `slf4j` interface (`@Slf4j` recommended).
2.  **Exception:**
   * Avoid checked exceptions; use custom `RuntimeException`-based exceptions (`KeycloakSecurityException`) instead.

---

## 5. Configuration Strategy

We aim to give users both convenience and control, while encouraging **explicit dependency management via environment-specific Starters**.

### Strategy A: Explicit Environment Selection
Users must clearly recognize their application's environment (Spring MVC or WebFlux) and explicitly select and add the matching `starter` dependency. This prevents unnecessary `reactive` or `servlet` dependencies from ending up in the project.
 
* **Mechanism:** Gradle/Maven dependency management
* **Implementation:**
    * **Servlet environment:** Add the `keycloak-spring-security-servlet-starter` dependency.
    * **Reactive environment:** Add the `keycloak-spring-security-reactive-starter` dependency.

### Strategy B: Zero-Configuration (Auto Config)
Provides a default `SecurityFilterChain` that works out of the box without any initial setup.
However, it **always uses `@ConditionalOnMissingBean`** so as not to interfere with a user's custom configuration.

```java
// Servlet AutoConfiguration Example
@Bean
@ConditionalOnMissingBean(SecurityFilterChain.class)
public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) {
    return http.with(KeycloakHttpConfigurer.keycloak(), Customizer.withDefaults()).build();
}
```
### Strategy C: Modular Configuration (Configurer Pattern)
Provides a Configurer that encapsulates the internal logic, for cases where users want to build their own configuration.

```java
// User Usage Example
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) {
    return http
        .authorizeHttpRequests(...) 
        .addFilterBefore(new MyCustomFilter(), ...) 
        .with(KeycloakHttpConfigurer.keycloak(), Customizer.withDefaults()) // Apply the feature in a single line
        .build();
}

```

---

## 6. Build Configuration (Gradle)

* **Build Tool:** Gradle
* **Java Version:** JDK 17 or higher
* **Supported Versions:**
    *   Spring Boot 3.5.9 (Stable)
    *   Spring Security 6.5.7 (Stable)
* **Usage:** Users only need a single dependency below, regardless of their environment.

```build.gradle
// for MVC and Servlet environment
implementation("com.ids.keycloak:keycloak-spring-security-web-starter:1.0.0")

// for WebFlux and Reactive environment
implementation("com.ids.keycloak:keycloak-spring-security-webflux-starter:1.0.0")
```

---

## 7. Feature Toggle Configuration

Every feature is controlled via yaml configuration under the `keycloak.security.*` namespace.

### CSRF Protection

CSRF (Cross-Site Request Forgery) protection settings. The default is **enabled (true)**, and the logout and token issuance endpoints are automatically exempted.

```yaml
keycloak:
  security:
    csrf:
      enabled: true                     # Default: true (CSRF protection enabled)
      ignore-paths:                     # Additional CSRF-exempt paths (Ant pattern)
        - /api/**
        - /webhook/**
```

| Property | Type | Default | Description |
|------|------|--------|------|
| `enabled` | boolean | `true` | Whether CSRF protection is enabled. Fully disabled when `false` |
| `ignore-paths` | List&lt;String&gt; | `[]` | Additional CSRF-exempt paths. Supports Ant patterns (e.g., `/api/**`) |

**Default exempt paths (hardcoded):**
- `/logout` (Front-Channel logout)
- `/logout/connect/back-channel/**` (Back-Channel logout)
- When Bearer Token is enabled: `/auth/token`, `/auth/refresh`, `/auth/logout`

**Basic Auth and CSRF (security warning):**
Even when `basic-auth.enabled: true` is set, simply presenting an `Authorization: Basic` header does **not** automatically exempt a request from CSRF. HTTP Basic credentials are an ambient credential — browsers cache them per origin and will automatically resend them on subsequent requests, including a cross-origin form submission from an attacker — so the mere presence of the header cannot be treated as proof of a "non-browser request" (CWE-352). Reserve Basic Auth for machine clients where no browser is involved (curl, server-to-server calls, etc.), and explicitly register any path that needs a CSRF exemption in `ignore-paths`.

### Basic Authentication

```yaml
keycloak:
  security:
    basic-auth:
      enabled: false                    # Default: false (opt-in)
```

### Bearer Token

```yaml
keycloak:
  security:
    bearer-token:
      enabled: false                    # Default: false (opt-in)
      token-endpoint:
        prefix: /auth                   # Default: /auth
```

### Rate Limiting

```yaml
keycloak:
  security:
    rate-limit:
      enabled: false                    # Default: false (opt-in)
      max-requests: 5                   # Max requests allowed within the time window
      window-seconds: 60               # Time window (seconds)
      block-duration-seconds: 300      # Block duration (seconds)
      key-strategy: IP_AND_USERNAME    # IP, USERNAME, IP_AND_USERNAME
      include-basic-auth: true         # Also applies to Basic Auth
      max-tracked-keys: 100000         # Max number of tracked keys in the in-memory counter map (prevents cardinality attacks; fails closed when exceeded)
```

The client IP is determined by `ClientIpResolver` based on `trusted-proxy-count` (the number of trusted proxies, default `0`). Behind a reverse proxy, you must set `keycloak.security.trusted-proxy-count` to match the number of proxies in front of the app, or rate limiting can be bypassed via `X-Forwarded-For` spoofing.

### Role Mapping (Realm/Client Role Namespace)

```yaml
keycloak:
  security:
    role-mapping:
      mode: SEPARATE_NAMESPACE          # Default. REALM_ONLY / CLIENT_ONLY / LEGACY_MERGED
      realm-role-prefix: ROLE_REALM_    # Realm role prefix when mode=SEPARATE_NAMESPACE
      client-role-prefix: ROLE_CLIENT_  # Client role prefix when mode=SEPARATE_NAMESPACE
```

**Security warning (Breaking):** Previously, `realm_access.roles` and `resource_access.{clientId}.roles` were both merged into the same `ROLE_<name>` authority, making it impossible to distinguish between a realm role and a client role that share the same name (CWE-863 — a holder of a realm role could unintentionally pass a client-only `hasRole(...)` check). The default has been changed to `SEPARATE_NAMESPACE`, which separates realm and client roles with distinct prefixes (`ROLE_REALM_*`/`ROLE_CLIENT_<CLIENT>_*`), so update any existing `hasRole(...)`/`hasAuthority(...)` references to match the new authority strings. If you need the previous behavior purely as a transitional measure, you can explicitly set `mode: LEGACY_MERGED` (not recommended, re-exposes CWE-863).
