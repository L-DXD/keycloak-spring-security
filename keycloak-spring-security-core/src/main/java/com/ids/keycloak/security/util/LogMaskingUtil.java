package com.ids.keycloak.security.util;

import lombok.experimental.UtilityClass;

/**
 * 로그에 남기는 식별자(sub, sid, jti 등)를 비가역적으로 일부만 노출하도록 마스킹하는 유틸리티입니다.
 * <p>
 * Back-Channel Logout 등에서 사용자 식별자(sub)나 세션 ID(sid)를 추적 목적으로 로그에 남겨야 할 때,
 * 원문 전체를 남기지 않고 이 유틸리티를 통해 마스킹된 값만 로그 인자로 전달해야 합니다.
 * </p>
 * <p>
 * servlet 모듈({@code OidcBackChannelSessionLogoutHandler})과 reactive 모듈
 * ({@code ReactiveOidcBackChannelLogoutHandler})이 공통으로 사용합니다.
 * </p>
 */
@UtilityClass
public class LogMaskingUtil {

    private static final int VISIBLE_LENGTH = 4;

    /**
     * 추적용 식별자(sub, sid, jti 등)를 비가역적으로 일부만 마스킹합니다.
     * <p>
     * 길이가 {@value #VISIBLE_LENGTH} 이하인 짧은 값은 일부만 남겨도 사실상 원문 전체가
     * 노출되는 것과 다름없으므로, 접미사를 노출하지 않고 전체를 마스킹합니다.
     * </p>
     *
     * @param value 마스킹할 원본 식별자 (null 또는 공백 가능)
     * @return 마스킹된 값. 원본이 null/공백이면 {@code "(none)"}, 짧은 값이면 {@code "***"},
     *         그 외에는 마지막 {@value #VISIBLE_LENGTH}자만 노출한 {@code "***xxxx"} 형태
     */
    public static String maskIdentifier(String value) {
        if (value == null || value.isBlank()) {
            return "(none)";
        }
        if (value.length() <= VISIBLE_LENGTH) {
            return "***";
        }
        return "***" + value.substring(value.length() - VISIBLE_LENGTH);
    }
}
