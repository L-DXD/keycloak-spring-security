package com.ids.keycloak.security.token;

import java.util.Objects;

import org.springframework.security.oauth2.jwt.Jwt;

/**
 * 액세스 토큰 검증 결과 (01 설계 3절).
 * <ul>
 *   <li>{@link Status#VALID}: 통과. {@link #jwt()}가 있다</li>
 *   <li>{@link Status#EXPIRED}: 만료만 걸렸다. 갱신 대상이다</li>
 *   <li>{@link Status#INVALID}: 그 밖의 검증 실패. 갱신하지 않고 로컬 로그아웃한다</li>
 *   <li>{@link Status#UNAVAILABLE}: 서명 키(JWKS)를 받지 못했다. 토큰 탓이 아니므로 로그아웃하지 않고 503</li>
 * </ul>
 */
public class AccessTokenValidationResult {

    /** 결과 종류. */
    public enum Status {
        VALID, EXPIRED, INVALID, UNAVAILABLE
    }

    private final Status status;
    private final Jwt jwt;
    private final String reason;

    protected AccessTokenValidationResult(Status status, Jwt jwt, String reason) {
        this.status = Objects.requireNonNull(status);
        this.jwt = jwt;
        this.reason = reason;
    }

    public static AccessTokenValidationResult valid(Jwt jwt) {
        return new AccessTokenValidationResult(Status.VALID, Objects.requireNonNull(jwt), null);
    }

    public static AccessTokenValidationResult expired(String reason) {
        return new AccessTokenValidationResult(Status.EXPIRED, null, reason);
    }

    public static AccessTokenValidationResult invalid(String reason) {
        return new AccessTokenValidationResult(Status.INVALID, null, reason);
    }

    public static AccessTokenValidationResult unavailable(String reason) {
        return new AccessTokenValidationResult(Status.UNAVAILABLE, null, reason);
    }

    public Status status() {
        return status;
    }

    public boolean isValid() {
        return status == Status.VALID;
    }

    /** 갱신해도 되는 실패인가 (만료만 걸림). */
    public boolean isRefreshable() {
        return status == Status.EXPIRED;
    }

    /** 통과했을 때의 토큰. 아니면 {@code null}. */
    public Jwt jwt() {
        return jwt;
    }

    /** Keycloak 사용자 id ({@code sub}). 통과했을 때만. */
    public String subject() {
        return jwt == null ? null : jwt.getSubject();
    }

    /** Keycloak 세션 id ({@code sid}). 통과했을 때만, 토큰에 없으면 {@code null}. */
    public String sessionId() {
        return jwt == null ? null : jwt.getClaimAsString("sid");
    }

    /** 실패 사유 (로그용, 토큰 값 없음). 통과면 {@code null}. */
    public String reason() {
        return reason;
    }

    @Override
    public String toString() {
        return "AccessTokenValidationResult[" + status + (reason == null ? "" : ", " + reason) + "]";
    }
}
