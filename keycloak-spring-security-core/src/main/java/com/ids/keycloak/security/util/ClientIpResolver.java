package com.ids.keycloak.security.util;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

/**
 * 신뢰 프록시 홉 수(trusted-proxy-count)에 따라 X-Forwarded-For 헤더에서
 * 실제 클라이언트 IP를 추출하는 유틸리티 클래스입니다.
 *
 * <p><b>보안 설계:</b> XFF 헤더는 클라이언트가 임의 위조할 수 있으므로,
 * 배포 환경의 신뢰 프록시 수를 정확히 지정해야 합니다.
 * {@code trustedProxyCount=0}이면 XFF를 무시하고 TCP 연결 원격 주소를 사용합니다.</p>
 *
 * <h3>동작 방식 (append 방식 XFF 기준, 예: nginx {@code $proxy_add_x_forwarded_for})</h3>
 * <pre>
 * X-Forwarded-For: client, proxy1, proxy2
 * 인덱스:                0       1       2
 *
 * 각 신뢰 프록시는 자신이 요청을 받은 IP를 헤더 우측에 append한다.
 * 따라서 trustedProxyCount개의 신뢰 프록시가 append한 항목은 배열의 가장 우측
 * trustedProxyCount개이며, 그 바로 앞(= parts.length - trustedProxyCount 위치)이
 * 마지막 신뢰 프록시가 실제로 관찰한 클라이언트 IP다.
 *
 * trustedProxyCount=1, parts=[client, proxy1] → targetIndex = 2 - 1 = 1 → "proxy1"(클라이언트가 직접 연결한 프록시가 관찰한 IP)
 * trustedProxyCount=2, parts=[client, proxy1, proxy2] → targetIndex = 3 - 2 = 1 → "proxy1"
 * trustedProxyCount가 parts.length보다 크면(설정 과대/헤더 절단) targetIndex&lt;0 → remoteAddr로 폴백
 * trustedProxyCount=-1(레거시) → XFF 첫 번째 무조건 신뢰 (비권장)
 * </pre>
 */
@Slf4j
@UtilityClass
public class ClientIpResolver {

    private static final String X_FORWARDED_FOR = "X-Forwarded-For";
    private static final String UNKNOWN = "unknown";

    /**
     * Servlet 환경에서 클라이언트 IP를 추출합니다.
     *
     * @param xffHeader          X-Forwarded-For 헤더 값 (없으면 {@code null})
     * @param remoteAddr         TCP 연결 원격 주소 ({@code request.getRemoteAddr()})
     * @param trustedProxyCount  신뢰 프록시 홉 수.
     *                           {@code 0}: remoteAddr 사용,
     *                           {@code -1}: XFF 첫 번째 무조건 신뢰(레거시, 비권장),
     *                           {@code N>0}: XFF에서 우측 N개(신뢰 프록시가 append한 구간) 바로 앞의 IP 사용,
     *                           단 N이 XFF 엔트리 수보다 크면 remoteAddr로 폴백
     * @return 클라이언트 IP 문자열
     */
    public static String resolve(String xffHeader, String remoteAddr, int trustedProxyCount) {
        // trustedProxyCount=0이면 XFF 무시, TCP remoteAddr 사용 (보안상 기본값)
        if (trustedProxyCount == 0) {
            return sanitize(remoteAddr);
        }

        // XFF 헤더가 없으면 remoteAddr 폴백
        if (xffHeader == null || xffHeader.isBlank()) {
            return sanitize(remoteAddr);
        }

        String[] parts = xffHeader.split(",");

        // trustedProxyCount=-1은 레거시 동작: XFF 첫 번째 무조건 신뢰
        if (trustedProxyCount < 0) {
            log.warn("[ClientIpResolver] trusted-proxy-count=-1: XFF 첫 번째 IP를 무조건 신뢰합니다. "
                + "스푸핑 위험이 있으므로 실제 프록시 홉 수로 변경을 권장합니다.");
            return sanitize(parts[0].trim());
        }

        // trustedProxyCount > 0: 신뢰 프록시가 append한 우측 trustedProxyCount개 항목의
        // 바로 앞 위치가 마지막 신뢰 프록시가 관찰한 실제 클라이언트 IP
        // 예) parts=[client, proxy1, proxy2], trustedProxyCount=2 → targetIndex = 3 - 2 = 1 → "proxy1"
        int targetIndex = parts.length - trustedProxyCount;
        if (targetIndex < 0) {
            // 프록시 홉 수가 XFF 엔트리 수보다 많음(설정 과대 또는 헤더 절단/조작 의심).
            // parts[0]은 공격자가 통제 가능한 구간이므로 스푸핑 방지를 위해 remoteAddr로 폴백한다.
            log.warn("[ClientIpResolver] trusted-proxy-count({})가 XFF 엔트리 수({})보다 많습니다. "
                    + "스푸핑 방지를 위해 remoteAddr로 폴백합니다. 설정값을 확인하세요.",
                trustedProxyCount, parts.length);
            return sanitize(remoteAddr);
        }

        return sanitize(parts[targetIndex].trim());
    }

    /**
     * IP 문자열을 정제합니다. null이거나 비어있으면 {@code "unknown"} 반환.
     */
    private static String sanitize(String ip) {
        if (ip == null || ip.isBlank()) {
            return UNKNOWN;
        }
        return ip;
    }
}
