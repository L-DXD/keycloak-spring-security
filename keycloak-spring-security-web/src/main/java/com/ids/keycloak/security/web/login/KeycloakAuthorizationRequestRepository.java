package com.ids.keycloak.security.web.login;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.StringJoiner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import com.ids.keycloak.security.crypto.AesGcmTokenCipher;
import com.ids.keycloak.security.crypto.EncryptedToken;
import com.ids.keycloak.security.crypto.KeycloakKeyRing;
import com.ids.keycloak.security.crypto.TokenDecryptionException;
import com.ids.keycloak.security.web.cookie.KeycloakCookie;
import com.ids.keycloak.security.web.cookie.KeycloakCookieWriter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 로그인 임시 정보(state, PKCE verifier, nonce, 돌아갈 경로)를 HttpSession 대신 암호화 쿠키 {@code __Host-{앱}_login}에 둔다 (5분).
 * <p>
 * 쿠키는 AES-256-GCM(용도 {@code login-state})으로 암호화해 내용을 읽거나 바꿀 수 없다. 만든 시각을 안에 담아,
 * 브라우저가 쿠키를 더 오래 들고 있어도 5분이 지나면 받지 않는다 (LOGIN-05). 콜백을 처리하면 지운다.
 */
public class KeycloakAuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private static final Logger log = LoggerFactory.getLogger(KeycloakAuthorizationRequestRepository.class);

    /** HKDF 용도. */
    public static final String PURPOSE = "login-state";
    /** 기본 수명. */
    public static final Duration DEFAULT_TTL = Duration.ofMinutes(5);
    /** 콜백 요청에서 꺼낸 돌아갈 경로. 로그인 성공 처리기가 읽는다. */
    public static final String RETURN_PATH_ATTRIBUTE = KeycloakAuthorizationRequestRepository.class.getName() + ".RETURN_PATH";

    private static final String VERSION = "1";
    private static final Duration FUTURE_SKEW = Duration.ofMinutes(1);
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private final KeycloakCookieWriter cookies;
    private final AesGcmTokenCipher cipher;
    private final LoginReturnPathResolver returnPaths;
    private final Clock clock;
    private final Duration ttl;

    public KeycloakAuthorizationRequestRepository(KeycloakCookieWriter cookies, KeycloakKeyRing keyRing, LoginReturnPathResolver returnPaths,
                                                  Clock clock) {
        this(cookies, keyRing, returnPaths, clock, DEFAULT_TTL);
    }

    public KeycloakAuthorizationRequestRepository(KeycloakCookieWriter cookies, KeycloakKeyRing keyRing, LoginReturnPathResolver returnPaths,
                                                  Clock clock, Duration ttl) {
        this.cookies = Objects.requireNonNull(cookies);
        this.cipher = new AesGcmTokenCipher(keyRing, PURPOSE);
        this.returnPaths = Objects.requireNonNull(returnPaths);
        this.clock = Objects.requireNonNull(clock);
        this.ttl = Objects.requireNonNull(ttl);
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        LoginState state = loadState(request);
        return state == null ? null : state.request();
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request,
                                         HttpServletResponse response) {
        if (authorizationRequest == null) {
            cookies.clear(response, KeycloakCookie.LOGIN);
            return;
        }
        String returnPath = returnPaths.resolve(request);
        EncryptedToken encrypted = cipher.encrypt(encode(authorizationRequest, returnPath, clock.instant()));
        cookies.write(response, KeycloakCookie.LOGIN, encrypted.keyId() + "." + ENCODER.encodeToString(encrypted.ciphertext()), ttl);
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        LoginState state = loadState(request);
        cookies.clear(response, KeycloakCookie.LOGIN);
        if (state == null) {
            return null;
        }
        request.setAttribute(RETURN_PATH_ATTRIBUTE, state.returnPath());
        return state.request();
    }

    /** 쿠키를 풀고, 콜백의 state가 쿠키와 같을 때만 돌려준다. */
    private LoginState loadState(HttpServletRequest request) {
        LoginState state = read(request);
        if (state == null) {
            return null;
        }
        String stateParameter = request.getParameter(OAuth2ParameterNames.STATE);
        if (stateParameter == null || !stateParameter.equals(state.request().getState())) {
            log.debug("[KSS] 로그인 콜백의 state가 로그인 임시 쿠키와 다릅니다");
            return null;
        }
        return state;
    }

    private LoginState read(HttpServletRequest request) {
        String value = cookies.read(request, KeycloakCookie.LOGIN).orElse(null);
        if (value == null) {
            return null;
        }
        int dot = value.indexOf('.');
        if (dot <= 0) {
            return null;
        }
        try {
            String plain = cipher.decrypt(new EncryptedToken(value.substring(0, dot), DECODER.decode(value.substring(dot + 1))));
            LoginState state = decode(plain);
            Instant now = clock.instant();
            if (state.issuedAt().plus(ttl).isBefore(now) || state.issuedAt().isAfter(now.plus(FUTURE_SKEW))) {
                log.debug("[KSS] 로그인 임시 쿠키가 {}이 지났습니다", ttl);
                return null;
            }
            return state;
        } catch (TokenDecryptionException | IllegalArgumentException e) {
            log.debug("[KSS] 로그인 임시 쿠키를 읽지 못했습니다: {}", e.getMessage());
            return null;
        }
    }

    /** 쿠키 안의 내용: 만든 시각, Spring 인가 요청, 돌아갈 경로. */
    private record LoginState(Instant issuedAt, OAuth2AuthorizationRequest request, String returnPath) {
    }

    // 쿼리 문자열 모양으로 적는다: v=1&t=…&u=…&c=…&r=…&s=…&sc=…&ret=…&a.키=값&p.키=값
    private static String encode(OAuth2AuthorizationRequest r, String returnPath, Instant issuedAt) {
        StringJoiner out = new StringJoiner("&");
        put(out, "v", VERSION);
        put(out, "t", Long.toString(issuedAt.getEpochSecond()));
        put(out, "u", r.getAuthorizationUri());
        put(out, "c", r.getClientId());
        put(out, "r", r.getRedirectUri());
        put(out, "s", r.getState());
        put(out, "sc", String.join(" ", r.getScopes()));
        put(out, "ret", returnPath);
        r.getAttributes().forEach((k, v) -> put(out, "a." + k, String.valueOf(v)));
        r.getAdditionalParameters().forEach((k, v) -> put(out, "p." + k, String.valueOf(v)));
        return out.toString();
    }

    private static LoginState decode(String text) {
        Map<String, String> fields = new LinkedHashMap<>();
        Map<String, Object> attributes = new LinkedHashMap<>();
        Map<String, Object> parameters = new LinkedHashMap<>();
        for (String pair : text.split("&")) {
            int eq = pair.indexOf('=');
            if (eq <= 0) {
                throw new IllegalArgumentException("모양이 틀립니다");
            }
            String key = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
            String value = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            if (key.startsWith("a.")) {
                attributes.put(key.substring(2), value);
            } else if (key.startsWith("p.")) {
                parameters.put(key.substring(2), value);
            } else {
                fields.put(key, value);
            }
        }
        if (!VERSION.equals(fields.get("v"))) {
            throw new IllegalArgumentException("모르는 판입니다");
        }
        Set<String> scopes = new LinkedHashSet<>();
        for (String scope : fields.getOrDefault("sc", "").split(" ")) {
            if (!scope.isEmpty()) {
                scopes.add(scope);
            }
        }
        OAuth2AuthorizationRequest request = OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri(required(fields, "u"))
            .clientId(required(fields, "c"))
            .redirectUri(fields.get("r"))
            .state(required(fields, "s"))
            .scopes(scopes)
            .attributes(a -> a.putAll(attributes))
            .additionalParameters(p -> p.putAll(parameters))
            .build();
        return new LoginState(Instant.ofEpochSecond(Long.parseLong(required(fields, "t"))), request, fields.getOrDefault("ret", "/"));
    }

    private static String required(Map<String, String> fields, String key) {
        String value = fields.get(key);
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(key + "가 없습니다");
        }
        return value;
    }

    private static void put(StringJoiner out, String key, String value) {
        if (value != null) {
            out.add(URLEncoder.encode(key, StandardCharsets.UTF_8) + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8));
        }
    }
}
