package com.ids.keycloak.security.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.error.ErrorResponse;
import com.ids.keycloak.security.exception.ErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.io.OutputStream;

public class SecurityHandlerUtil {

    private static final String XML_HTTP_REQUEST = "XMLHttpRequest";
    private static final String X_REQUESTED_WITH = "X-Requested-With";

    private SecurityHandlerUtil() {
        // Private constructor to prevent instantiation
    }

    /**
     * AJAX 요청인지 확인합니다.
     * X-Requested-With 헤더가 XMLHttpRequest이거나 Accept 헤더가 application/json인 경우 AJAX 요청으로 판단합니다.
     */
    public static boolean isAjaxRequest(HttpServletRequest request) {
        String xRequestedWith = request.getHeader(X_REQUESTED_WITH);
        String acceptHeader = request.getHeader("Accept");

        return XML_HTTP_REQUEST.equals(xRequestedWith) ||
            (acceptHeader != null && acceptHeader.contains(MediaType.APPLICATION_JSON_VALUE));
    }

    /**
     * JSON 형식의 에러 응답을 전송합니다.
     */
    public static void sendJsonResponse(HttpServletResponse response, ObjectMapper objectMapper, ErrorCode errorCode) throws IOException {
        response.setStatus(errorCode.getHttpStatus());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        try (OutputStream os = response.getOutputStream()) {
            objectMapper.writeValue(os, new ErrorResponse(errorCode.getCode(), errorCode.getDefaultMessage()));
            os.flush();
        }
    }
}
