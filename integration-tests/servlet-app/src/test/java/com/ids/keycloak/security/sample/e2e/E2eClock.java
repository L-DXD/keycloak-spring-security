package com.ids.keycloak.security.sample.e2e;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 샘플 앱의 {@code keycloakSecurityClock}. 테스트가 앞으로 돌려 5분·절대 상한 같은 시간 시나리오를 바로 만든다 (03 문서 6절).
 * 테스트가 끝나면 {@link #reset()}으로 되돌린다.
 */
public class E2eClock extends Clock {

    private final AtomicReference<Duration> offset = new AtomicReference<>(Duration.ZERO);

    /** 지금보다 {@code amount}만큼 앞으로. */
    public void advance(Duration amount) {
        offset.updateAndGet(current -> current.plus(amount));
    }

    public void reset() {
        offset.set(Duration.ZERO);
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }

    @Override
    public Instant instant() {
        return Instant.now().plus(offset.get());
    }
}
