package com.ids.keycloak.security.web.login;

import java.io.IOException;
import java.net.URI;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import com.ids.keycloak.security.web.cookie.KeycloakCookie;
import com.ids.keycloak.security.web.cookie.KeycloakCookieWriter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 로그인 실패 (LOGIN-05): 로그인 임시 쿠키를 지우고 화면 주소로 302 {@code ?login_error=코드}. 세션 행은 만들지 않는다.
 * <ul>
 *   <li>{@code invalid_state}: 로그인 임시 쿠키가 없거나, 5분이 지났거나, state가 다르다</li>
 *   <li>{@code access_denied}: 사용자가 Keycloak에서 취소했다</li>
 *   <li>{@code invalid_token}: 받은 토큰이 검증 규칙에 맞지 않는다</li>
 *   <li>{@code login_failed}: 그 밖</li>
 * </ul>
 */
public class KeycloakLoginFailureHandler implements AuthenticationFailureHandler {

    private static final Logger log = LoggerFactory.getLogger(KeycloakLoginFailureHandler.class);

    /** 화면 주소에 붙이는 파라미터 이름. */
    public static final String ERROR_PARAMETER = "login_error";

    private final URI frontendBaseUrl;
    private final KeycloakCookieWriter cookies;

    public KeycloakLoginFailureHandler(URI frontendBaseUrl, KeycloakCookieWriter cookies) {
        this.frontendBaseUrl = Objects.requireNonNull(frontendBaseUrl);
        this.cookies = Objects.requireNonNull(cookies);
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
        throws IOException {
        String code = errorCode(exception);
        log.warn("[KSS] 로그인 실패: {} ({})", code, detail(exception));
        cookies.clear(response, KeycloakCookie.LOGIN);
        response.sendRedirect(errorUrl(code));
    }

    /** 화면에 넘기는 짧은 코드. */
    protected String errorCode(AuthenticationException exception) {
        if (exception instanceof OAuth2AuthenticationException oauth2) {
            return switch (oauth2.getError().getErrorCode()) {
                case "authorization_request_not_found", "invalid_state_parameter", "invalid_redirect_uri_parameter" -> "invalid_state";
                case "access_denied" -> "access_denied";
                case "invalid_token", "invalid_id_token", "invalid_nonce" -> "invalid_token";
                default -> "login_failed";
            };
        }
        return "login_failed";
    }

    /** 화면 주소 + {@code /?login_error=코드}. */
    protected String errorUrl(String code) {
        String base = frontendBaseUrl.toString();
        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        return base + "/?" + ERROR_PARAMETER + "=" + code;
    }

    private static String detail(AuthenticationException exception) {
        if (exception instanceof OAuth2AuthenticationException oauth2) {
            return oauth2.getError().getErrorCode();
        }
        return exception.getClass().getSimpleName();
    }
}
