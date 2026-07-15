package com.ids.keycloak.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.exception.ConfigurationException;
import com.ids.keycloak.security.exception.IntrospectionFailedException;
import com.ids.keycloak.security.exception.TokenBindingException;
import com.ids.keycloak.security.exception.UserInfoFetchException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakIntrospectResponse;
import com.sd.KeycloakClient.dto.user.KeycloakUserInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * {@link KeycloakAuthenticationProvider} 테스트.
 * Provider는 온라인 검증(Introspect)과 로컬 서명 검증(JwtDecoder), 토큰 결합 검증을 담당하고,
 * 토큰 재발급은 Filter에서 처리합니다.
 *
 * <p><b>보안 Advisory 1 테스트:</b> ID Token/Access Token/UserInfo의 sub/aud/azp 결합 검증을
 * {@link #결합_검증_테스트} 에서 검증합니다.</p>
 */
@ExtendWith(MockitoExtension.class)
class KeycloakAuthenticationProviderTest {

    private KeycloakAuthenticationProvider provider;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private KeycloakClient keycloakClient;

    @Mock
    private JwtDecoder jwtDecoder;

    private static final String CLIENT_ID = "test-client-id";
    private static final String USER_SUB = "user-123";
    private static final String OTHER_USER_SUB = "user-456";
    private static final String ID_TOKEN_VAL = "valid-id-token";
    private static final String ACCESS_TOKEN_VAL = "valid-access-token";

    @BeforeEach
    void setUp() {
        provider = new KeycloakAuthenticationProvider(keycloakClient, CLIENT_ID, jwtDecoder);
    }

    // ------------------------------------------------------------------
    // 헬퍼
    // ------------------------------------------------------------------

    private KeycloakPrincipal createPreAuthPrincipal(String subject) {
        OidcIdToken idToken = new OidcIdToken(
            "token-value",
            Instant.now(),
            Instant.now().plusSeconds(3600),
            Map.of("sub", subject)
        );
        return new KeycloakPrincipal(subject, Collections.emptyList(), idToken, null);
    }

    private KeycloakAuthentication buildAuthRequest(String idToken, String accessToken, String subject) {
        return new KeycloakAuthentication(createPreAuthPrincipal(subject), idToken, accessToken, false);
    }

    /** 서명 검증을 통과한 것으로 간주되는(테스트 더블) ID Token {@link Jwt}를 생성합니다. */
    private Jwt buildJwt(String tokenValue, String subject, List<String> audience, String azp) {
        Instant now = Instant.now();
        Jwt.Builder builder = Jwt.withTokenValue(tokenValue)
            .header("alg", "RS256")
            .subject(subject)
            .issuedAt(now)
            .expiresAt(now.plusSeconds(3600));
        if (audience != null) {
            builder.audience(audience);
        }
        if (azp != null) {
            builder.claim("azp", azp);
        }
        return builder.build();
    }

    /**
     * {@code JwtUtil.isStructurallyJwt()}가 {@code true}를 반환하도록 실제로 서명된(점 2개 포함,
     * header.payload.signature 구조) JWT 문자열을 생성합니다.
     *
     * <p>이 문자열 자체의 서명/클레임은 이 테스트에서 신뢰되지 않습니다 — {@link #jwtDecoder}가 mock이므로
     * 실제 검증은 {@code when(jwtDecoder.decode(...))} 스텁으로 대체됩니다. 오직 "구조적으로 JWT인가"만
     * 확인하는 {@code JwtUtil.isStructurallyJwt()} 분기를 통과시키기 위한 픽스처입니다(2.0.1 패치:
     * Opaque Access Token과 구분해야 subject 직접 비교 로직이 호출됨).</p>
     */
    private String buildStructuralJwtAccessToken() {
        try {
            JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("fixture-subject").build();
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
            signedJWT.sign(new MACSigner("0123456789abcdef0123456789abcdef"));
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("테스트 픽스처 JWT 서명 생성에 실패했습니다.", e);
        }
    }

    private void stubIntrospectSuccess(String idToken) {
        KeycloakIntrospectResponse introspectBody = mock(KeycloakIntrospectResponse.class);
        lenient().when(introspectBody.getActive()).thenReturn(true);

        @SuppressWarnings("unchecked")
        KeycloakResponse<KeycloakIntrospectResponse> introspectResponse = mock(KeycloakResponse.class);
        lenient().when(introspectResponse.getStatus()).thenReturn(200);
        lenient().when(introspectResponse.getBody()).thenReturn(Optional.of(introspectBody));

        lenient().when(keycloakClient.auth().authenticationByIntrospect(idToken)).thenReturn(introspectResponse);
    }

    private void stubUserInfoSuccess(String accessToken, String subject) {
        KeycloakUserInfo keycloakUserInfo = mock(KeycloakUserInfo.class);
        lenient().when(keycloakUserInfo.getSubject()).thenReturn(subject);
        lenient().when(keycloakUserInfo.getOtherInfo()).thenReturn(new HashMap<>());

        @SuppressWarnings("unchecked")
        KeycloakResponse<KeycloakUserInfo> userInfoResponse = mock(KeycloakResponse.class);
        lenient().when(userInfoResponse.getStatus()).thenReturn(200);
        lenient().when(userInfoResponse.getBody()).thenReturn(Optional.of(keycloakUserInfo));

        lenient().when(keycloakClient.user().getUserInfo(accessToken)).thenReturn(userInfoResponse);
    }

    @Nested
    class 인증_성공_테스트 {

        @Test
        void 온라인_검증_성공시_인증에_성공하고_Principal을_생성한다() {
            stubIntrospectSuccess(ID_TOKEN_VAL);
            stubUserInfoSuccess(ACCESS_TOKEN_VAL, USER_SUB);
            when(jwtDecoder.decode(ID_TOKEN_VAL))
                .thenReturn(buildJwt(ID_TOKEN_VAL, USER_SUB, List.of(CLIENT_ID), CLIENT_ID));

            KeycloakAuthentication authRequest = buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL, USER_SUB);

            Authentication result = provider.authenticate(authRequest);

            assertThat(result).isInstanceOf(KeycloakAuthentication.class);
            assertThat(result.isAuthenticated()).isTrue();
            assertThat(result.getPrincipal()).isInstanceOf(KeycloakPrincipal.class);

            KeycloakPrincipal principal = (KeycloakPrincipal) result.getPrincipal();
            assertThat(principal.getName()).isEqualTo(USER_SUB);
        }
    }

    @Nested
    class 인증_실패_테스트 {

        @Test
        void 온라인_검증_active_false시_IntrospectionFailedException이_발생한다() {
            String idTokenVal = "invalid-id-token";
            String accessTokenVal = "invalid-access-token";
            KeycloakAuthentication authRequest = buildAuthRequest(idTokenVal, accessTokenVal, USER_SUB);

            KeycloakIntrospectResponse introspectBody = mock(KeycloakIntrospectResponse.class);
            lenient().when(introspectBody.getActive()).thenReturn(false);

            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakIntrospectResponse> introspectResponse = mock(KeycloakResponse.class);
            lenient().when(introspectResponse.getStatus()).thenReturn(200);
            lenient().when(introspectResponse.getBody()).thenReturn(Optional.of(introspectBody));

            when(keycloakClient.auth().authenticationByIntrospect(idTokenVal)).thenReturn(introspectResponse);

            assertThatThrownBy(() -> provider.authenticate(authRequest))
                .isInstanceOf(IntrospectionFailedException.class)
                .hasMessageContaining("유효하지 않습니다");
        }

        @Test
        void 온라인_검증_401_응답시_IntrospectionFailedException이_발생한다() {
            String idTokenVal = "expired-id-token";
            String accessTokenVal = "expired-access-token";
            KeycloakAuthentication authRequest = buildAuthRequest(idTokenVal, accessTokenVal, USER_SUB);

            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakIntrospectResponse> introspectResponse = mock(KeycloakResponse.class);
            lenient().when(introspectResponse.getStatus()).thenReturn(401);

            when(keycloakClient.auth().authenticationByIntrospect(idTokenVal)).thenReturn(introspectResponse);

            assertThatThrownBy(() -> provider.authenticate(authRequest))
                .isInstanceOf(IntrospectionFailedException.class);
        }
    }

    @Nested
    class 예외_테스트 {

        @Test
        void 온라인_검증_500_응답시_ConfigurationException이_발생한다() {
            String idTokenVal = "valid-id-token-2";
            String accessTokenVal = "valid-access-token-2";
            KeycloakAuthentication authRequest = buildAuthRequest(idTokenVal, accessTokenVal, USER_SUB);

            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakIntrospectResponse> introspectResponse = mock(KeycloakResponse.class);
            lenient().when(introspectResponse.getStatus()).thenReturn(500);

            when(keycloakClient.auth().authenticationByIntrospect(idTokenVal)).thenReturn(introspectResponse);

            assertThatThrownBy(() -> provider.authenticate(authRequest))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining("Keycloak 서버");
        }
    }

    /**
     * 보안 Advisory 1: ID Token/Access Token/UserInfo 결합 검증 테스트.
     * "정상 동일 사용자 ID/Access → 성공", "A의 ID + B의 Access → 실패", "잘못된 iss → 실패(서명검증 실패로 시뮬레이션)",
     * "aud에 client-id 없음 → 실패", "azp 불일치 → 실패", "만료 → 실패"를 검증합니다.
     */
    @Nested
    class 결합_검증_테스트 {

        @BeforeEach
        void setUpIntrospectAndUserInfoDefaults() {
            stubIntrospectSuccess(ID_TOKEN_VAL);
        }

        @Test
        void 동일_사용자_ID_Access_Token_조합이면_인증에_성공한다() {
            stubUserInfoSuccess(ACCESS_TOKEN_VAL, USER_SUB);
            when(jwtDecoder.decode(ID_TOKEN_VAL))
                .thenReturn(buildJwt(ID_TOKEN_VAL, USER_SUB, List.of(CLIENT_ID), CLIENT_ID));

            Authentication result =
                provider.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL, USER_SUB));

            assertThat(result.isAuthenticated()).isTrue();
            assertThat(((KeycloakPrincipal) result.getPrincipal()).getName()).isEqualTo(USER_SUB);
        }

        @Test
        void A의_ID_Token과_B의_Access_Token_조합이면_TokenBindingException이_발생한다() {
            // ID Token은 사용자 A(USER_SUB), UserInfo(Access Token 소유자)는 사용자 B(OTHER_USER_SUB)
            stubUserInfoSuccess(ACCESS_TOKEN_VAL, OTHER_USER_SUB);
            when(jwtDecoder.decode(ID_TOKEN_VAL))
                .thenReturn(buildJwt(ID_TOKEN_VAL, USER_SUB, List.of(CLIENT_ID), CLIENT_ID));

            assertThatThrownBy(() ->
                provider.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL, USER_SUB)))
                .isInstanceOf(TokenBindingException.class)
                .hasMessageContaining("subject");
        }

        @Test
        void ID_Token_서명_검증_실패시_TokenBindingException이_발생한다() {
            // JwtDecoder.decode()가 서명/iss 등 검증 실패를 의미하는 JwtException을 던지는 상황을 시뮬레이션
            when(jwtDecoder.decode(ID_TOKEN_VAL))
                .thenThrow(new BadJwtException("잘못된 issuer 또는 서명입니다."));

            assertThatThrownBy(() ->
                provider.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL, USER_SUB)))
                .isInstanceOf(TokenBindingException.class);
        }

        @Test
        void ID_Token_만료시_TokenBindingException이_발생한다() {
            // 만료된 토큰에 대해 JwtDecoder가 던지는 JwtException을 시뮬레이션
            when(jwtDecoder.decode(ID_TOKEN_VAL))
                .thenThrow(new BadJwtException("Jwt expired at " + Instant.now().minusSeconds(10)));

            assertThatThrownBy(() ->
                provider.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL, USER_SUB)))
                .isInstanceOf(TokenBindingException.class);
        }

        @Test
        void ID_Token_aud에_client_id가_없으면_TokenBindingException이_발생한다() {
            stubUserInfoSuccess(ACCESS_TOKEN_VAL, USER_SUB);
            when(jwtDecoder.decode(ID_TOKEN_VAL))
                .thenReturn(buildJwt(ID_TOKEN_VAL, USER_SUB, List.of("other-client-id"), null));

            assertThatThrownBy(() ->
                provider.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL, USER_SUB)))
                .isInstanceOf(TokenBindingException.class)
                .hasMessageContaining("aud");
        }

        @Test
        void ID_Token_azp가_client_id와_다르면_TokenBindingException이_발생한다() {
            stubUserInfoSuccess(ACCESS_TOKEN_VAL, USER_SUB);
            when(jwtDecoder.decode(ID_TOKEN_VAL))
                .thenReturn(buildJwt(ID_TOKEN_VAL, USER_SUB, List.of(CLIENT_ID), "malicious-client-id"));

            assertThatThrownBy(() ->
                provider.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL, USER_SUB)))
                .isInstanceOf(TokenBindingException.class)
                .hasMessageContaining("azp");
        }

        @Test
        void 결합_검증_실패시_SecurityContext에_반영될_인증객체가_생성되지_않는다() {
            // authenticate()가 예외를 던지면 호출부(Filter)에서 SecurityContext를 세팅하지 않으므로
            // 예외 발생 자체가 "SecurityContext 미생성"을 보장한다.
            stubUserInfoSuccess(ACCESS_TOKEN_VAL, OTHER_USER_SUB);
            when(jwtDecoder.decode(ID_TOKEN_VAL))
                .thenReturn(buildJwt(ID_TOKEN_VAL, USER_SUB, List.of(CLIENT_ID), CLIENT_ID));

            assertThatThrownBy(() ->
                provider.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL, USER_SUB)))
                .isInstanceOf(TokenBindingException.class);
        }
    }

    /**
     * 2.0.1 패치(외부 검토 High #1) 핵심 회귀 방지 테스트.
     *
     * <p>패치 이전에는 Access Token에 대해 azp만 검증하고 sub는 UserInfo를 통해서만 간접 확인했습니다.
     * {@code require-user-info=false}(기본값)에서 UserInfo 조회가 실패하면 이 간접 sub 검증 자체가
     * 스킵되어, 사용자 A의 ID Token과 같은 Client에서 발급된 사용자 B의 JWT Access Token 조합이
     * azp 일치만으로 인증을 통과할 수 있었습니다. 이 클래스는 그 회귀가 재발하지 않는지 검증합니다.</p>
     */
    @Nested
    class Access_Token_Subject_직접_검증_2_0_1_패치 {

        private String jwtAccessTokenVal;

        @BeforeEach
        void setUp() {
            stubIntrospectSuccess(ID_TOKEN_VAL);
            jwtAccessTokenVal = buildStructuralJwtAccessToken();
            when(jwtDecoder.decode(ID_TOKEN_VAL))
                .thenReturn(buildJwt(ID_TOKEN_VAL, USER_SUB, List.of(CLIENT_ID), CLIENT_ID));
        }

        @Test
        void requireUserInfo_false_UserInfo_실패_JWT_AT_sub_불일치시_TokenBindingException으로_인증에_실패한다() {
            // require-user-info=false(기본값)에서 UserInfo 조회가 401로 실패하면 UserInfo 기반
            // validateSubjectBinding은 스킵된다. 그러나 Access Token이 JWT 구조이고 sub가 ID Token과
            // 다르면(OTHER_USER_SUB != USER_SUB) validateAccessTokenSubject가 이를 직접 차단해야 한다.
            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakUserInfo> userInfoResponse = mock(KeycloakResponse.class);
            lenient().when(userInfoResponse.getStatus()).thenReturn(401);
            when(keycloakClient.user().getUserInfo(jwtAccessTokenVal)).thenReturn(userInfoResponse);

            when(jwtDecoder.decode(jwtAccessTokenVal))
                .thenReturn(buildJwt(jwtAccessTokenVal, OTHER_USER_SUB, List.of(CLIENT_ID), CLIENT_ID));

            // 예외가 발생하므로 authenticate()가 Authentication을 반환하지 않고,
            // 호출부(Filter)도 SecurityContext를 세팅하지 않는다(SecurityContext 미생성 보장).
            assertThatThrownBy(() ->
                provider.authenticate(buildAuthRequest(ID_TOKEN_VAL, jwtAccessTokenVal, USER_SUB)))
                .isInstanceOf(TokenBindingException.class)
                .hasMessageContaining("subject");
        }

        @Test
        void Opaque_Access_Token은_UserInfo_실패해도_sub_직접_검증을_스킵하고_기존_정책대로_인증에_성공한다_회귀없음() {
            // Opaque(비-JWT) Access Token은 JwtUtil.isStructurallyJwt()가 false이므로
            // jwtDecoder.decode(accessToken)가 호출되지 않아야 하고, 기존 정책
            // (require-user-info=false → UserInfo 실패 시 빈 권한으로 인증 성공)이 그대로 유지되어야 한다.
            String opaqueAccessTokenVal = "opaque-access-token-no-dots";

            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakUserInfo> userInfoResponse = mock(KeycloakResponse.class);
            lenient().when(userInfoResponse.getStatus()).thenReturn(401);
            when(keycloakClient.user().getUserInfo(opaqueAccessTokenVal)).thenReturn(userInfoResponse);

            Authentication result =
                provider.authenticate(buildAuthRequest(ID_TOKEN_VAL, opaqueAccessTokenVal, USER_SUB));

            assertThat(result.isAuthenticated()).isTrue();
            assertThat(result.getAuthorities()).isEmpty();
            verify(jwtDecoder, never()).decode(opaqueAccessTokenVal);
        }

        @Test
        void Refresh_경로_createAuthenticatedToken_직접_호출에서도_JWT_AT_sub_불일치시_TokenBindingException이_발생한다() {
            // Refresh Token 재발급 후 Filter가 직접 호출하는 진입점(createAuthenticatedToken)도
            // 동일한 검증을 우회할 수 없어야 한다. UserInfo의 subject는 ID Token과 일치시켜
            // (기존 validateSubjectBinding 통과) 실패 원인이 오직 새 direct sub 비교임을 격리한다.
            stubUserInfoSuccess(jwtAccessTokenVal, USER_SUB);
            when(jwtDecoder.decode(jwtAccessTokenVal))
                .thenReturn(buildJwt(jwtAccessTokenVal, OTHER_USER_SUB, List.of(CLIENT_ID), CLIENT_ID));

            assertThatThrownBy(() ->
                provider.createAuthenticatedToken(ID_TOKEN_VAL, jwtAccessTokenVal))
                .isInstanceOf(TokenBindingException.class)
                .hasMessageContaining("subject");
        }
    }

    /**
     * Refresh 경로(Filter.refreshAndAuthenticate)가 직접 호출하는 createAuthenticatedToken()도
     * 동일한 검증 파이프라인을 통과하는지 검증합니다(우회 금지).
     */
    @Nested
    class createAuthenticatedToken_직접_호출_Refresh_경로 {

        @Test
        void 정상_토큰이면_인증객체를_생성한다() {
            stubUserInfoSuccess(ACCESS_TOKEN_VAL, USER_SUB);
            when(jwtDecoder.decode(ID_TOKEN_VAL))
                .thenReturn(buildJwt(ID_TOKEN_VAL, USER_SUB, List.of(CLIENT_ID), CLIENT_ID));

            Authentication result = provider.createAuthenticatedToken(ID_TOKEN_VAL, ACCESS_TOKEN_VAL);

            assertThat(result.isAuthenticated()).isTrue();
            assertThat(((KeycloakPrincipal) result.getPrincipal()).getName()).isEqualTo(USER_SUB);
        }

        @Test
        void Refresh로_재발급된_토큰_조합도_결합검증을_통과해야_한다() {
            // Refresh 후 재발급된 ID/Access Token 조합이 서로 다른 사용자면 Refresh 경로에서도 실패해야 함
            stubUserInfoSuccess(ACCESS_TOKEN_VAL, OTHER_USER_SUB);
            when(jwtDecoder.decode(ID_TOKEN_VAL))
                .thenReturn(buildJwt(ID_TOKEN_VAL, USER_SUB, List.of(CLIENT_ID), CLIENT_ID));

            assertThatThrownBy(() -> provider.createAuthenticatedToken(ID_TOKEN_VAL, ACCESS_TOKEN_VAL))
                .isInstanceOf(TokenBindingException.class);
        }
    }

    /**
     * N-1 회귀 방지: require-user-info 플래그가 모든 UserInfo 실패 경로에 일관 적용되는지 검증합니다.
     * require-user-info=false(기본): 200+빈body / 401 / 기타 / 네트워크 오류 모두 → 빈권한 성공.
     * require-user-info=true: 동일 실패 경로 모두 → UserInfoFetchException(인증 실패).
     */
    @Nested
    class requireUserInfo_플래그_동작 {

        private KeycloakIntrospectResponse introspectBody;
        @SuppressWarnings("unchecked")
        private KeycloakResponse<KeycloakIntrospectResponse> introspectResponse;

        @BeforeEach
        void setUpIntrospectSuccess() {
            introspectBody = mock(KeycloakIntrospectResponse.class);
            lenient().when(introspectBody.getActive()).thenReturn(true);
            introspectResponse = mock(KeycloakResponse.class);
            lenient().when(introspectResponse.getStatus()).thenReturn(200);
            lenient().when(introspectResponse.getBody()).thenReturn(Optional.of(introspectBody));
            when(keycloakClient.auth().authenticationByIntrospect(anyString()))
                .thenReturn(introspectResponse);
            lenient().when(jwtDecoder.decode(anyString()))
                .thenReturn(buildJwt("any-id-token", USER_SUB, List.of(CLIENT_ID), CLIENT_ID));
        }

        // ------------------------------------------------------------------
        // require-user-info=false (기본값) — 모든 실패 경로 → 빈권한 성공
        // ------------------------------------------------------------------

        @Test
        void requireUserInfo_false_UserInfo_빈body_200_인증_성공_빈권한() {
            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakUserInfo> userInfoResponse = mock(KeycloakResponse.class);
            lenient().when(userInfoResponse.getStatus()).thenReturn(200);
            lenient().when(userInfoResponse.getBody()).thenReturn(Optional.empty());
            when(keycloakClient.user().getUserInfo(anyString())).thenReturn(userInfoResponse);

            Authentication result = provider.authenticate(buildAuthRequest("any-id-token", "any-access-token", USER_SUB));

            assertThat(result.isAuthenticated()).isTrue();
            assertThat(((KeycloakPrincipal) result.getPrincipal()).getName()).isEqualTo(USER_SUB);
            assertThat(result.getAuthorities()).isEmpty();
        }

        @Test
        void requireUserInfo_false_UserInfo_401_인증_성공_빈권한() {
            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakUserInfo> userInfoResponse = mock(KeycloakResponse.class);
            lenient().when(userInfoResponse.getStatus()).thenReturn(401);
            when(keycloakClient.user().getUserInfo(anyString())).thenReturn(userInfoResponse);

            Authentication result = provider.authenticate(buildAuthRequest("any-id-token", "any-access-token", USER_SUB));

            assertThat(result.isAuthenticated()).isTrue();
            assertThat(result.getAuthorities()).isEmpty();
        }

        @Test
        void requireUserInfo_false_UserInfo_503_인증_성공_빈권한() {
            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakUserInfo> userInfoResponse = mock(KeycloakResponse.class);
            lenient().when(userInfoResponse.getStatus()).thenReturn(503);
            when(keycloakClient.user().getUserInfo(anyString())).thenReturn(userInfoResponse);

            Authentication result = provider.authenticate(buildAuthRequest("any-id-token", "any-access-token", USER_SUB));

            assertThat(result.isAuthenticated()).isTrue();
            assertThat(result.getAuthorities()).isEmpty();
        }

        @Test
        void requireUserInfo_false_RestClientException_인증_성공_빈권한() {
            when(keycloakClient.user().getUserInfo(anyString()))
                .thenThrow(new org.springframework.web.client.RestClientException("connection refused"));

            Authentication result = provider.authenticate(buildAuthRequest("any-id-token", "any-access-token", USER_SUB));

            assertThat(result.isAuthenticated()).isTrue();
            assertThat(result.getAuthorities()).isEmpty();
        }

        // ------------------------------------------------------------------
        // require-user-info=true — 모든 실패 경로 → 인증 실패(UserInfoFetchException)
        // ------------------------------------------------------------------

        @Test
        void requireUserInfo_true_UserInfo_빈body_200_인증_실패() {
            provider.setRequireUserInfo(true);

            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakUserInfo> userInfoResponse = mock(KeycloakResponse.class);
            lenient().when(userInfoResponse.getStatus()).thenReturn(200);
            lenient().when(userInfoResponse.getBody()).thenReturn(Optional.empty());
            when(keycloakClient.user().getUserInfo(anyString())).thenReturn(userInfoResponse);

            assertThatThrownBy(() ->
                provider.authenticate(buildAuthRequest("any-id-token", "any-access-token", USER_SUB)))
                .isInstanceOf(UserInfoFetchException.class);
        }

        @Test
        void requireUserInfo_true_UserInfo_401_인증_실패() {
            provider.setRequireUserInfo(true);

            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakUserInfo> userInfoResponse = mock(KeycloakResponse.class);
            lenient().when(userInfoResponse.getStatus()).thenReturn(401);
            when(keycloakClient.user().getUserInfo(anyString())).thenReturn(userInfoResponse);

            assertThatThrownBy(() ->
                provider.authenticate(buildAuthRequest("any-id-token", "any-access-token", USER_SUB)))
                .isInstanceOf(UserInfoFetchException.class)
                .hasMessageContaining("401");
        }

        @Test
        void requireUserInfo_true_UserInfo_503_인증_실패() {
            provider.setRequireUserInfo(true);

            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakUserInfo> userInfoResponse = mock(KeycloakResponse.class);
            lenient().when(userInfoResponse.getStatus()).thenReturn(503);
            when(keycloakClient.user().getUserInfo(anyString())).thenReturn(userInfoResponse);

            assertThatThrownBy(() ->
                provider.authenticate(buildAuthRequest("any-id-token", "any-access-token", USER_SUB)))
                .isInstanceOf(UserInfoFetchException.class);
        }

        @Test
        void requireUserInfo_true_RestClientException_인증_실패() {
            provider.setRequireUserInfo(true);

            when(keycloakClient.user().getUserInfo(anyString()))
                .thenThrow(new org.springframework.web.client.RestClientException("connection refused"));

            assertThatThrownBy(() ->
                provider.authenticate(buildAuthRequest("any-id-token", "any-access-token", USER_SUB)))
                .isInstanceOf(UserInfoFetchException.class);
        }
    }
}
