package com.ids.keycloak.security.token;

import java.io.IOException;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * JWKS를 받아 두고 쓴다. 모르는 kid가 오면 다시 받되, 다시 받기는 {@code minRefetchInterval}(기본 1분)에 한 번만 한다 (JWT-08).
 * <ul>
 *   <li>다시 받았는데도 모르는 kid: 키 없음 → 검증 결과 INVALID</li>
 *   <li>간격 제한 때문에 다시 받지 못한 모르는 kid: {@link KeySourceException} → UNAVAILABLE(503).
 *       Keycloak이 키를 막 바꾼 때 사용자를 로그아웃시키지 않기 위해서다</li>
 *   <li>처음 쓸 때 받는다. 받지 못하면 {@link KeySourceException} → UNAVAILABLE</li>
 * </ul>
 */
public class KeycloakJwkSource implements JWKSource<SecurityContext> {

    /** 모르는 kid 때문에 다시 받는 최소 간격 기본값. */
    public static final Duration DEFAULT_MIN_REFETCH_INTERVAL = Duration.ofMinutes(1);

    private static final Logger log = LoggerFactory.getLogger(KeycloakJwkSource.class);

    private final JwkSetFetcher fetcher;
    private final Duration minRefetchInterval;
    private final Clock clock;

    private volatile JWKSet cached;
    private volatile Instant fetchedAt;
    private int fetchCount;

    public KeycloakJwkSource(JwkSetFetcher fetcher, Clock clock) {
        this(fetcher, DEFAULT_MIN_REFETCH_INTERVAL, clock);
    }

    public KeycloakJwkSource(JwkSetFetcher fetcher, Duration minRefetchInterval, Clock clock) {
        this.fetcher = Objects.requireNonNull(fetcher);
        this.minRefetchInterval = Objects.requireNonNull(minRefetchInterval);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public List<JWK> get(JWKSelector selector, SecurityContext context) throws KeySourceException {
        JWKSet current = cached;
        if (current == null) {
            current = refetch(null);
        }
        List<JWK> matches = selector.select(current);
        if (!matches.isEmpty()) {
            return matches;
        }
        // 모르는 kid: Keycloak이 키를 바꿨을 수 있다. 간격 제한 안에서 한 번 더 받는다
        JWKSet refreshed = refetch(current);
        if (refreshed == current) {
            throw new KeySourceException("모르는 서명 키입니다. JWKS는 " + minRefetchInterval.toSeconds() + "초에 한 번만 다시 받습니다");
        }
        return selector.select(refreshed);
    }

    /**
     * @param seen 호출한 쪽이 본 묶음. 그새 다른 스레드가 받았으면 다시 받지 않는다
     */
    private synchronized JWKSet refetch(JWKSet seen) throws KeySourceException {
        if (cached != null && cached != seen) {
            return cached;
        }
        Instant now = clock.instant();
        if (cached != null && fetchedAt != null && now.isBefore(fetchedAt.plus(minRefetchInterval))) {
            return cached;
        }
        try {
            JWKSet fetched = JWKSet.parse(fetcher.fetch());
            cached = fetched;
            fetchedAt = now;
            fetchCount++;
            log.debug("[KSS] JWKS를 받았습니다: 키 {}개 ({}번째)", fetched.getKeys().size(), fetchCount);
            return fetched;
        } catch (IOException | ParseException e) {
            throw new KeySourceException("JWKS를 받지 못했습니다: " + e.getMessage(), e);
        }
    }

    /** 지금까지 JWKS를 받은 횟수 (테스트·지표용). */
    public synchronized int fetchCount() {
        return fetchCount;
    }
}
