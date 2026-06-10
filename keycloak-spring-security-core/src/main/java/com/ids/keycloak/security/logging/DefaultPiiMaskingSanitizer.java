package com.ids.keycloak.security.logging;

import java.util.regex.Pattern;

/**
 * 로그 출력 전 PII/민감정보를 마스킹하는 기본 {@link LoggingValueSanitizer} 구현체.
 * <p>
 * 사내 로깅 표준의 PiiMasker 패턴을 라이브러리 기본값으로 내장합니다.
 * </p>
 * 지원 패턴
 * <ul>
 *   <li>이메일              : {@code a***@example.com}</li>
 *   <li>휴대폰              : {@code 010-****-5678}</li>
 *   <li>주민번호             : {@code 900101-1******}</li>
 *   <li>Bearer 토큰         : {@code Bearer ***}</li>
 *   <li>카드/계좌            : {@code 1234-****-****-3456}</li>
 *   <li>OAuth2 쿼리 파라미터 : {@code access_token=***}, {@code refresh_token=***},
 *                            {@code code=***}, {@code id_token=***}</li>
 *   <li>JWT 원문             : {@code eyJ...(header).eyJ...(payload).*** }</li>
 * </ul>
 * <p>
 * <b>원칙</b> — 로그에 민감정보를 안 넣는 것이 1차 방어, 마스킹은 2차 방어선입니다.
 * </p>
 */
public class DefaultPiiMaskingSanitizer implements LoggingValueSanitizer {

    private static final Pattern EMAIL = Pattern.compile(
            "([A-Za-z0-9])[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\\.[A-Za-z]{2,})"
    );
    private static final Pattern PHONE = Pattern.compile(
            "(01[016789])[-. ]?\\d{3,4}[-. ]?(\\d{4})"
    );
    private static final Pattern RRN = Pattern.compile(
            "(\\d{6})-([1-4])\\d{6}"
    );
    private static final Pattern BEARER = Pattern.compile(
            "Bearer\\s+[A-Za-z0-9._~+/=-]+",
            Pattern.CASE_INSENSITIVE
    );
    private static final Pattern CARD = Pattern.compile(
            "(\\d{4})[-. ]?\\d{4}[-. ]?\\d{4}[-. ]?(\\d{4})"
    );

    /**
     * OAuth2 쿼리 파라미터 마스킹: access_token=, refresh_token=, code=, id_token= 값.
     * URL 인코딩된 경우도 처리하기 위해 값 부분을 {@code [^&# ]+} 로 매칭합니다.
     */
    private static final Pattern OAUTH2_QUERY_PARAM = Pattern.compile(
            "(?i)((?:access_token|refresh_token|id_token|code)=)[^&#\\s]+"
    );

    /**
     * JWT 원문 마스킹: eyJ로 시작하는 3파트(header.payload.signature) 형태.
     * Base64url 문자([A-Za-z0-9_-])만 허용하며 최소 길이 제한으로 오탐을 줄입니다.
     */
    private static final Pattern JWT_RAW = Pattern.compile(
            "eyJ[A-Za-z0-9_-]{4,}\\.eyJ[A-Za-z0-9_-]{4,}\\.[A-Za-z0-9_-]+"
    );

    @Override
    public String sanitize(String key, String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }

        String result = value;
        // 적용 순서: JWT 원문 → Bearer → OAuth2 쿼리파라미터 → 주민번호 → 카드 → 이메일 → 휴대폰
        // (JWT/Bearer 토큰은 내부에 숫자/기호가 많아 다른 패턴에 먼저 매칭될 수 있어 가장 먼저)
        result = JWT_RAW.matcher(result).replaceAll("eyJ***.[redacted]");
        result = BEARER.matcher(result).replaceAll("Bearer ***");
        result = OAUTH2_QUERY_PARAM.matcher(result).replaceAll("$1***");
        result = RRN.matcher(result).replaceAll("$1-$2******");
        result = CARD.matcher(result).replaceAll("$1-****-****-$2");
        result = EMAIL.matcher(result).replaceAll("$1***$2");
        result = PHONE.matcher(result).replaceAll("$1-****-$2");
        return result;
    }
}
