# keycloak-spring-security

**English** | [한국어](README.ko.md)

A library that adds Keycloak login to a Spring Boot app. One starter and a few lines of configuration give a browser front end login, request authentication, token refresh and logout.

- **3.x**: Java 17+, Spring Boot 4.1, Spring Security 7.1, Servlet (Spring MVC). WebFlux comes in 3.1.0
- **Model**: a BFF where the app holds the tokens. The browser carries only `__Host-` cookies, the access token is validated inside the app (no Keycloak or database call per request), and the refresh token is stored encrypted in the app database
- **2.x** (Spring Boot 3.5) lives in [docs/v2](docs/v2/GUIDE.md) and the `2.x` branch

## Documentation

| Document | Contents |
|---|---|
| [User Guide](docs/GUIDE.md) | Quick start, how it works, configuration, features, extension, troubleshooting |
| [Migrating from v2 to v3](docs/MIGRATION-v3.md) | Changed keys, removed features and alternatives, database schema, Keycloak client settings |
| [CHANGELOG](CHANGELOG.md) | Changes per version |
| [SECURITY](SECURITY.md) | Supported versions, reporting vulnerabilities |
| [docs/v3](docs/v3/README.md) | Design, acceptance scenarios, test environment, decision log (for contributors, Korean) |

## Quick start

> The 3.x release on Maven Central is currently the preview `3.0.0-RC1`. Setting names and defaults may change before the final 3.0.0. Use [2.0.3](https://github.com/L-DXD/keycloak-spring-security/tree/2.x) in production.

```gradle
implementation("io.github.l-dxd:keycloak-spring-security-web-starter:3.0.0")
```

```yaml
spring.security.oauth2.client:
  registration.keycloak: { client-id: myapp, client-secret: ${KEYCLOAK_CLIENT_SECRET}, scope: openid }
  provider.keycloak.issuer-uri: https://sso.example.com/realms/my-realm

keycloak:
  security:
    frontend:
      base-url: https://app.example.com
    crypto:
      active-key-id: k1
      keys:
        k1: ${KSS_KEY_K1}            # openssl rand -base64 32
```

For the session table (`auth_session`) and the Keycloak client settings, follow [section 1 of the User Guide](docs/GUIDE.md#1-quick-start).

## Principles

1. **Open for customization.** Every auto-configured bean is `@ConditionalOnMissingBean`; register a bean of the same type and the library uses yours.
2. **Add with `Customizer<T>`.** `KeycloakHttpConfigurer` calls your login, CSRF, CORS and logout `Customizer`s after its own settings.
3. **No `final`.** Only the crypto helpers (`SessionIds`, `Hkdf`) are final. Handlers are changed by overriding protected methods.
4. **Core, implementation and starter are separate.** Core knows nothing about Servlet or Spring Web (checked with ArchUnit).
5. **One starter, a few settings.** A default security chain comes with it and stays when the app adds other chains.

## Modules

| Module (artifactId) | Contents |
|---|---|
| `keycloak-spring-security-core` | Settings, session store (JDBC, memory, schema SQL), crypto, token validation rules, error codes, session events, MDC keys |
| `keycloak-spring-security-web` | Servlet filters and handlers, `KeycloakHttpConfigurer` |
| `keycloak-spring-security-web-starter` | Auto-configuration, `keycloak.security.*` binding, startup checks |

The groupId is `io.github.l-dxd` and the package root is `com.ids.keycloak.security`.

## Build and verification

```bash
./gradlew build                                   # unit and integration tests, forbidden dependency check, ArchUnit
./gradlew :integration-tests:servlet-app:e2eTest  # sample app + real Keycloak + PostgreSQL (Docker or KSS_E2E_*)
```

The E2E suite runs the sample Spring Boot app in `integration-tests/servlet-app` against a real Keycloak and PostgreSQL and drives it like a browser, from login to back-channel logout. How to run it is in the [test environment](docs/v3/03-검증-환경.md) document (Korean).

To try the sample app by hand, start a local Keycloak, PostgreSQL and a small front-end page with Docker (test values only, bound to 127.0.0.1), then run the app:

```bash
integration-tests/local-stack.sh up                       # Keycloak :8180, PostgreSQL :5432, front https://app.kss.test
./gradlew :integration-tests:servlet-app:bootRun          # sample app https://api.kss.test:8443
./gradlew :integration-tests:servlet-app:bootRun --args=--spring.profiles.active=demo2   # second app :8444 (SSO, back-channel logout)
integration-tests/local-stack.sh down                     # remove everything (realm and DB start fresh next time)
```

With both apps running, `integration-tests/browser/feature-walkthrough.mjs` checks every feature in a real Chromium (Playwright). The commands and the results are in section 4-2 of the [test environment](docs/v3/03-검증-환경.md) document.

## Contributing

One issue, one PR. The acceptance scenarios in the issue become the test names, and an issue closes only when all of them pass as automated tests. The process is in [docs/v3/README](docs/v3/README.md).

## License

[LICENSE](LICENSE.md)
