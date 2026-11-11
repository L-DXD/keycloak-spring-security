package com.ids.keycloak.security.web.error;

import java.io.IOException;

import com.ids.keycloak.security.error.KeycloakErrorCode;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 401·403·503 JSON 응답 (확장 지점). 본문은 {@code {"code","message"}}, 401이면 {@code loginUrl}이 더 붙는다.
 * <pre>
 * {"code":"AUTHENTICATION_REQUIRED","message":"로그인이 필요합니다.","loginUrl":"/oauth2/authorization/keycloak"}
 * </pre>
 * 앱의 오류 형식을 쓰려면 이 빈을 상속해 {@link #body}를 덮어쓴다.
 */
public class KeycloakErrorResponseWriter {

    private final String registrationId;

    /**
     * @param registrationId OAuth2 Client 등록 id (로그인 주소 {@code /oauth2/authorization/{id}})
     */
    public KeycloakErrorResponseWriter(String registrationId) {
        this.registrationId = registrationId;
    }

    public void write(HttpServletRequest request, HttpServletResponse response, KeycloakErrorCode code) throws IOException {
        if (response.isCommitted()) {
            return;
        }
        response.setStatus(code.status());
        response.setContentType("application/json;charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write(body(request, code));
    }

    /** 로그인 시작 주소. context-path를 붙인다. */
    public String loginUrl(HttpServletRequest request) {
        return request.getContextPath() + "/oauth2/authorization/" + registrationId;
    }

    /** 응답 본문(JSON). */
    protected String body(HttpServletRequest request, KeycloakErrorCode code) {
        StringBuilder json = new StringBuilder("{\"code\":").append(quote(code.name()))
            .append(",\"message\":").append(quote(code.message()));
        if (code.status() == 401) {
            json.append(",\"loginUrl\":").append(quote(loginUrl(request)));
        }
        return json.append('}').toString();
    }

    /** JSON 문자열로 감싼다. */
    protected static String quote(String value) {
        StringBuilder out = new StringBuilder(value.length() + 2).append('"');
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '<' -> out.append("\\u003c");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append('"').toString();
    }
}
