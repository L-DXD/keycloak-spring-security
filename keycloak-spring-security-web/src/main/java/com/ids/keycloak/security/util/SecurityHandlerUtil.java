package com.ids.keycloak.security.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.error.ErrorResponse;
import com.ids.keycloak.security.exception.ErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import org.springframework.http.MediaType;

public class SecurityHandlerUtil {

    private static final String XML_HTTP_REQUEST = "XMLHttpRequest";
    private static final String X_REQUESTED_WITH = "X-Requested-With";

    private SecurityHandlerUtil() {
        // Private constructor to prevent instantiation
    }

    /**
     * AJAX 요청인지 확인합니다.
     *
     * <p>판정 기준:
     * <ol>
     *   <li>{@code X-Requested-With: XMLHttpRequest} 헤더가 있으면 AJAX</li>
     *   <li>Accept 헤더에 {@code text/html}이 포함되어 있으면 브라우저 네비게이션 → non-AJAX</li>
     *   <li>Accept 헤더에 명시적 JSON(subtype이 "json" 또는 "+json"으로 끝나는 타입) 타입이 있고
     *       text/html이 없으면 AJAX</li>
     *   <li>{@code Accept: *&#47;*} 단독이나 Accept 헤더 없음 → non-AJAX</li>
     * </ol>
     * 기존 {@code acceptHeader.contains("application/json")} 방식은 webflux 모듈과
     * 동일한 규칙으로 통일한다.
     */
    public static boolean isAjaxRequest(HttpServletRequest request) {
        String xRequestedWith = request.getHeader(X_REQUESTED_WITH);
        if (XML_HTTP_REQUEST.equals(xRequestedWith)) {
            return true;
        }
        String acceptHeader = request.getHeader("Accept");
        if (acceptHeader == null || acceptHeader.isBlank()) {
            return false;
        }
        List<MediaType> accepts = MediaType.parseMediaTypes(acceptHeader);
        boolean acceptsHtml = accepts.stream().anyMatch(MediaType.TEXT_HTML::isCompatibleWith);
        boolean explicitJson = accepts.stream()
            .anyMatch(mt -> "json".equals(mt.getSubtype()) || mt.getSubtype().endsWith("+json"));
        return explicitJson && !acceptsHtml;
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
