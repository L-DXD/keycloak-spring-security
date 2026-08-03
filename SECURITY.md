# Security Policy

**English** | [한국어](SECURITY.ko.md)

## Supported Versions

| Version | Support | Notes |
|------|------|------|
| **2.0.3+** | **Recommended** | The `error.*` properties never took effect (EntryPoint/AccessDeniedHandler overwritten by `oauth2Login`) is fixed, along with Basic Auth clearing an authentication established by an earlier filter, an Introspect/UserInfo remote call per static resource request, HTTP 500 on corrupted Redis sessions, missing authentication-failure audit logs, and back-channel logout silently doing nothing. Includes everything from 2.0.2. Recommended for production |
| 2.0.2 | Upgrade recommended | The Fixed items of 2.0.3 are not applied — `error.*` settings are silently ignored (common to 1.9.0–2.0.2), and static resources trigger a remote call per request. Includes all 4 external security review items (from 2.0.1) + all 8 full security review items (from 2.0.0), but upgrading to 2.0.3 is recommended. Note that 2.0.3 has 3 breaking changes (see [CHANGELOG.md](CHANGELOG.md)) |
| 2.0.1 | **Deprecated (do not use)** | With Redis + Jackson sessions, every authenticated request returns 500 (`SecurityContext` deserialization failure) — fixed in 2.0.2. Upgrade to 2.0.2 immediately |
| 2.0.0 | **Deprecated (do not use)** | Same session deserialization 500 regression as 2.0.1 + the 4 external review items not applied — upgrade to 2.0.2 immediately |
| 1.10.2 | Upgrade recommended | Advisory 1/2/3/5/6/7/8 not applied — OIDC token combined validation, session fixation prevention, removal of blanket CSRF exemption, etc. (see "Resolved Advisories" below) |
| 1.10.1 | Upgrade recommended | [#54](https://github.com/L-DXD/keycloak-spring-security/issues/54) (500 after back-channel logout) not fixed; Advisory 1/2/3/5/6/7/8 also not applied |
| 1.10.0 | Upgrade recommended | #52 / #54 not fixed; Advisory 1/2/3/5/6/7/8 also not applied |
| 1.6.0 – 1.9.x | Upgrade recommended | Full security review (1.10.0) not applied — reactive back-channel JWKS validation, cookie `secure` default, X-Forwarded-For trust, Redis JSON serialization, etc.; Advisory 1/2/3/5/6/7/8 also not applied |
| < 1.5.0 | Unsupported | **SecurityFilterChain Fail-Open** (CVSS 8.1) — upgrade immediately |

> In production, **always use 2.0.3 or higher**. **2.0.0 / 2.0.1 must not be used due to the Redis + Jackson session deserialization regression (500 on every authenticated request)**, which was fixed in 2.0.2. For detailed per-version changes, see [CHANGELOG.md](CHANGELOG.md).

## Resolved Advisories

| Version | Content | Severity |
|------|------|--------|
| **2.0.3** | Fixed the bug where the `keycloak.security.error.*` properties never took effect (EntryPoint/AccessDeniedHandler were registered in `configure()` and overwritten by the default EntryPoint installed by `oauth2Login` → moved to `init()`; common to 1.9.0–2.0.2), Basic Auth failure clearing an authentication established by an earlier filter (conditional clear), an Introspect/UserInfo remote call on every static resource request, HTTP 500 on corrupted Redis sessions (now treated as unauthenticated, guiding a normal re-login), missing authentication-failure reasons in logs (structured `ErrorCode`-based audit log, webflux audit log added), and back-channel logout silently doing nothing without an indexed session repository (startup warning) | Mixed (availability / operational visibility) |
| **2.0.2** | Fixed a regression where, with Redis + Jackson (`GenericJackson2JsonRedisSerializer`) sessions, `SecurityContext` deserialization failed and every authenticated request returned 500 (affecting 2.0.0/2.0.1; availability). Cause: misdetection of setterless getters in OIDC token claims and corruption of value types (iss=URL · iat/exp=Instant · nested objects) → fixed with a field-based mixin + generic unwrap + JavaTimeModule | Medium (availability) |
| **2.0.1** | Directly compares the OIDC Access Token subject with the ID Token subject to block combining tokens from different users when the UserInfo lookup fails (external review High #1; Opaque Access Token has a residual limitation — `require-user-info` recommended), fixed the missing WebFlux CSRF matcher safe-method exception (Medium #3), blocked browser Front-Channel `/logout` forced-logout CSRF bypass (Medium #4, CWE-352), Bearer prefix validation, aligned authentication validation order, log cleanup, and subject masking (Low #1–#4) — 4 external security review items | Mixed |
| **2.0.0** | Stronger OIDC ID/Access Token combined validation (Advisory 1), login session fixation prevention (Advisory 2), unified Rate Limit IP determination (Advisory 2), removal of blanket Basic Auth CSRF exemption (Advisory 3, CWE-352), back-channel logout log masking (Advisory 5), in-memory session store capacity cap (Advisory 6, CWE-400/CWE-770), Realm/Client Role namespace separation (Advisory 7, CWE-863), stronger WebFlux back-channel decoder validation (Advisory 8) — 8 full security review items | Mixed |
| **1.10.2** | After webflux token invalidation, re-issuance failure returned 500 (instead of a login redirect) — DoS-like (#54) | Medium |
| **1.10.0** | The reactive back-channel logout `logout_token` signature was not validated → arbitrary sessions could be forcibly terminated (CVSS 8.2) | **High** |
| **1.10.0** | Cookie `secure` default false, unverified X-Forwarded-For trust, Redis JDK serialization (Gadget), token response caching, and other issues — 13 full security review items | Mixed |
| **1.5.0** | SecurityFilterChain Fail-Open — authentication bypass when the user adds their own chain (CVSS 8.1) | **High** |

## Reporting a Vulnerability

If you discover a security vulnerability, **please do not open a public issue**; report it privately via the channels below.

- **Email**: **yui5227@gmail.com** (private report)
- Or **GitHub Security Advisory**: this repository's **Security → Advisories → Report a vulnerability** (private)

When reporting, please include: affected versions, reproduction steps, impact scope (authentication bypass / session / token exposure, etc.), and a PoC if possible.

After receipt, we go through confirmation, fix, and release, and disclose the advisory together with the fixed version.

## Recommended Security Settings

- `keycloak.security.cookie.secure=true` (default since 1.10.0) — required in HTTPS environments
- `keycloak.security.cookie.same-site=Lax` (or `Strict`)
- Behind a reverse proxy, set `keycloak.security.trusted-proxy-count` to match the number of proxies (prevents XFF spoofing)
- When using Redis sessions, keep the library's default JSON serialization (do not use JDK serialization)
- Keep PII masking (`DefaultPiiMaskingSanitizer`) on by default
- For detailed migration/configuration, see [docs/GUIDE.md](docs/GUIDE.md)
