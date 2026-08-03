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
     * Accept 헤더가 {@code text/html}을 명시적으로 수용하는지 확인합니다 (H-B).
     * <p>
     * <b>{@link #isAjaxRequest(HttpServletRequest)}와의 차이:</b> {@code isAjaxRequest}는
     * "AJAX 여부"를 판정하며, Accept 헤더가 없거나 {@code *&#47;*} 단독인 경우를 (안전 측으로)
     * non-AJAX로 분류한다. 그런데 curl 기본 요청, 서버간 호출, 일부 모바일 클라이언트는 대부분
     * Accept 헤더를 생략하거나 {@code *&#47;*}만 보낸다. OAuth2 로그인 리다이렉트 여부를
     * {@code !isAjaxRequest(request)}로 판단하면 이런 API 클라이언트가 401 JSON 대신 브라우저용
     * 302 리다이렉트를 받게 되어(2.0.2 대비 breaking change), 이 메서드로 판단을 뒤집는다 —
     * "AJAX가 아니면 브라우저"가 아니라 "Accept: text/html을 실제로 명시했을 때만 브라우저"로
     * 좁힌다. 순수 와일드카드({@code *&#47;*})는 브라우저 네비게이션의 신뢰 가능한 신호가 아니므로
     * 제외한다({@code text/*}처럼 타입은 구체적이고 서브타입만 와일드카드인 경우는 포함한다).
     * </p>
     */
    public static boolean acceptsHtmlExplicitly(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");
        if (acceptHeader == null || acceptHeader.isBlank()) {
            return false;
        }
        List<MediaType> accepts = MediaType.parseMediaTypes(acceptHeader);
        return accepts.stream()
            .anyMatch(mt -> !(mt.isWildcardType() && mt.isWildcardSubtype())
                && mt.isCompatibleWith(MediaType.TEXT_HTML));
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
