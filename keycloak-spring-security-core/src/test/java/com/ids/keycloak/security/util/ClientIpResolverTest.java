package com.ids.keycloak.security.util;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * {@link ClientIpResolver} 단위 테스트.
 *
 * <p>Advisory 2(XFF Rate Limit) off-by-one 수정 검증. append 방식 XFF
 * ({@code X-Forwarded-For: client, proxy1, proxy2, ...})에서
 * {@code targetIndex = parts.length - trustedProxyCount} 위치, 즉 신뢰 프록시가
 * append한 우측 trustedProxyCount개 구간의 바로 앞(=가장 바깥쪽 신뢰 프록시가 실제로
 * 관찰한 클라이언트 IP)을 선택해야 하며, 공격자가 통제 가능한 좌측 구간(parts[0] 등)을
 * 신뢰해서는 안 된다.</p>
 */
class ClientIpResolverTest {

    private static final String REMOTE_ADDR = "203.0.113.1";

    @Nested
    class 신뢰_프록시_홉_기반_파싱 {

        @Test
        void 신뢰_프록시_1개일때_XFF_두번째_항목을_클라이언트_IP로_선택한다() {
            // XFF: fake(공격자 위조 가능), real(신뢰 프록시 1개가 append한, 마지막 신뢰 프록시가 관찰한 클라이언트 IP)
            String resolved = ClientIpResolver.resolve("fake, real", REMOTE_ADDR, 1);

            assertThat(resolved).isEqualTo("real");
        }

        @Test
        void XFF_엔트리가_1개뿐이고_신뢰_프록시도_1개면_그_항목을_클라이언트_IP로_선택한다() {
            String resolved = ClientIpResolver.resolve("real", REMOTE_ADDR, 1);

            assertThat(resolved).isEqualTo("real");
        }

        @Test
        void 신뢰_프록시_2개_체인에서도_공격자_통제_구간을_건너뛰고_실제_클라이언트_IP를_선택한다() {
            // XFF: fake(공격자), real(가장 바깥쪽 신뢰 프록시가 관찰한 클라이언트 IP), p1(안쪽 신뢰 프록시가 append)
            String resolved = ClientIpResolver.resolve("fake, real, p1", REMOTE_ADDR, 2);

            assertThat(resolved).isEqualTo("real");
        }

        @Test
        void 공백이_포함된_XFF_항목은_trim되어_사용된다() {
            String resolved = ClientIpResolver.resolve("fake ,  real  ", REMOTE_ADDR, 1);

            assertThat(resolved).isEqualTo("real");
        }
    }

    @Nested
    class 설정_과대_또는_비정상_XFF는_remoteAddr로_안전_폴백 {

        @Test
        void trustedProxyCount가_XFF_엔트리_수보다_많으면_remoteAddr로_폴백한다() {
            // 설정 과대(운영 오설정) 또는 XFF가 프록시 단에서 절단/조작된 상황.
            // parts[0]("fake")은 공격자가 통제 가능한 구간이므로 그대로 신뢰해서는 안 된다.
            String resolved = ClientIpResolver.resolve("fake, real", REMOTE_ADDR, 5);

            assertThat(resolved).isEqualTo(REMOTE_ADDR);
            assertThat(resolved).isNotEqualTo("fake");
        }

        @Test
        void trustedProxyCount가_기본값_0이면_XFF를_완전히_무시하고_remoteAddr를_사용한다() {
            String resolved = ClientIpResolver.resolve("attacker-controlled, another", REMOTE_ADDR, 0);

            assertThat(resolved).isEqualTo(REMOTE_ADDR);
        }

        @Test
        void trustedProxyCount가_0이면_XFF_헤더가_없어도_remoteAddr를_사용한다() {
            String resolved = ClientIpResolver.resolve(null, REMOTE_ADDR, 0);

            assertThat(resolved).isEqualTo(REMOTE_ADDR);
        }

        @Test
        void XFF_헤더가_null이면_remoteAddr로_폴백한다() {
            String resolved = ClientIpResolver.resolve(null, REMOTE_ADDR, 1);

            assertThat(resolved).isEqualTo(REMOTE_ADDR);
        }

        @Test
        void XFF_헤더가_공백문자열이면_remoteAddr로_폴백한다() {
            String resolved = ClientIpResolver.resolve("   ", REMOTE_ADDR, 1);

            assertThat(resolved).isEqualTo(REMOTE_ADDR);
        }

        @Test
        void 대상_위치의_항목이_빈_문자열이면_unknown으로_안전_처리한다() {
            // XFF: "fake,,real" → ["fake", "", "real"] (중간 빈 값은 String#split의
            // trailing-empty 제거 대상이 아니므로 그대로 유지된다). trustedProxyCount=2이면
            // targetIndex=1 위치("")가 대상이므로, 빈 문자열을 그대로 반환하지 않고
            // "unknown"으로 대체해야 한다.
            String resolved = ClientIpResolver.resolve("fake,,real", REMOTE_ADDR, 2);

            assertThat(resolved).isEqualTo("unknown");
        }

        @Test
        void 대상_위치의_항목이_공백뿐이면_unknown으로_안전_처리한다() {
            String resolved = ClientIpResolver.resolve("real,   ", REMOTE_ADDR, 1);

            assertThat(resolved).isEqualTo("unknown");
        }

        @Test
        void remoteAddr마저_비어있으면_unknown으로_안전_처리한다() {
            String resolved = ClientIpResolver.resolve(null, "", 0);

            assertThat(resolved).isEqualTo("unknown");
        }

        @Test
        void 엔트리_수가_매우_많은_초과길이_XFF도_예외없이_안전하게_인덱스를_계산한다() {
            // 헤더 부풀리기(초과길이) 공격을 흉내낸 500개 엔트리. 신뢰 프록시 1개이므로
            // 마지막(가장 우측) 엔트리가 "마지막 신뢰 프록시가 관찰한 클라이언트 IP"다.
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 500; i++) {
                if (i > 0) {
                    sb.append(", ");
                }
                sb.append("hop-").append(i);
            }

            String resolved = ClientIpResolver.resolve(sb.toString(), REMOTE_ADDR, 1);

            assertThat(resolved).isEqualTo("hop-499");
        }
    }

    @Nested
    class 스푸핑_로테이션_방어 {

        @Test
        void 매_요청마다_XFF_첫_엔트리가_바뀌어도_trustedProxyCount_1이면_해석된_클라이언트_IP는_불변이다() {
            // 공격자가 매 요청마다 XFF 좌측(공격자 통제 구간)을 바꿔가며 rate limit 키를
            // 회전시키려 해도, 신뢰 프록시가 append한 우측 항목(마지막 신뢰 프록시가 관찰한 IP)만
            // 신뢰하므로 rate limit 키는 항상 동일해야 한다.
            String fixedProxyObservedIp = "172.16.0.9";
            String[] rotatingSpoofedValues = {
                "1.1.1.1", "2.2.2.2", "9.9.9.9", "evil-header-value", "0.0.0.0"
            };

            for (String spoofed : rotatingSpoofedValues) {
                String xff = spoofed + ", " + fixedProxyObservedIp;
                String resolved = ClientIpResolver.resolve(xff, REMOTE_ADDR, 1);

                assertThat(resolved).isEqualTo(fixedProxyObservedIp);
            }
        }
    }

    @Nested
    class 레거시_동작_trustedProxyCount_음수 {

        @Test
        void trustedProxyCount가_음수이면_XFF_첫번째_항목을_무조건_신뢰한다() {
            // 레거시(비권장) 동작: -1은 하위호환을 위해 유지되며 스푸핑 위험이 있다.
            String resolved = ClientIpResolver.resolve("first, second", REMOTE_ADDR, -1);

            assertThat(resolved).isEqualTo("first");
        }
    }
}
