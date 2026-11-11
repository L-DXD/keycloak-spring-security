package com.ids.keycloak.security.web.login;

import jakarta.servlet.http.HttpServletRequest;

/**
 * {@code ?return=/items/3}처럼 상대 경로만 받는다 (LOGIN-04). 다른 사이트로 보내는 값은 모두 {@code /}로 바꾼다:
 * 절대 주소({@code https://…}, {@code javascript:}), {@code //host}, 역슬래시, 공백·제어 문자, 2048자 넘는 값.
 * 화면 주소({@code frontend.base-url}) 뒤에 붙이므로 경로가 호스트를 바꿀 수 없다.
 */
public class DefaultLoginReturnPathResolver implements LoginReturnPathResolver {

    /** 기본 파라미터 이름. */
    public static final String DEFAULT_PARAMETER = "return";
    /** 받는 경로의 최대 길이. */
    public static final int MAX_LENGTH = 2048;

    private final String parameterName;

    public DefaultLoginReturnPathResolver() {
        this(DEFAULT_PARAMETER);
    }

    public DefaultLoginReturnPathResolver(String parameterName) {
        this.parameterName = parameterName;
    }

    @Override
    public String resolve(HttpServletRequest request) {
        return sanitize(request.getParameter(parameterName));
    }

    /** 받을 수 있는 상대 경로면 그대로, 아니면 {@code /}. */
    public String sanitize(String value) {
        if (value == null || value.isEmpty() || value.length() > MAX_LENGTH) {
            return "/";
        }
        if (value.charAt(0) != '/' || value.startsWith("//") || value.indexOf('\\') >= 0) {
            return "/";
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c <= 0x20 || c == 0x7f) {
                return "/";
            }
        }
        return value;
    }
}
