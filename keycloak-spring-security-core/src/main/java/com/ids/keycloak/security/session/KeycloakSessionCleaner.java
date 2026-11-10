package com.ids.keycloak.security.session;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;

import com.ids.keycloak.security.event.KeycloakSessionEndReason;
import com.ids.keycloak.security.event.KeycloakSessionEvent;
import com.ids.keycloak.security.event.KeycloakSessionEventPublisher;

/**
 * 끝난 세션 행 정리 작업 (STORE-05). {@code session.cleanup-interval}마다 데몬 스레드 하나로 돈다.
 * 지운 행마다 {@link KeycloakSessionEndReason#ABSOLUTE_TIMEOUT} 또는 {@link KeycloakSessionEndReason#IDLE} 이벤트를 낸다.
 * <p>
 * 서버를 여러 대 띄워도 된다. 한 행은 한 서버만 지운 것으로 센다.
 */
public class KeycloakSessionCleaner implements SmartLifecycle {

    private static final Logger log = LoggerFactory.getLogger(KeycloakSessionCleaner.class);

    /** 한 번에 지우는 행 수. */
    public static final int BATCH_SIZE = 500;
    private static final int MAX_BATCHES_PER_RUN = 100;

    private final KeycloakSessionStore store;
    private final KeycloakSessionEventPublisher events;
    private final Clock clock;
    private final Duration interval;
    private volatile ScheduledExecutorService executor;

    public KeycloakSessionCleaner(KeycloakSessionStore store, KeycloakSessionEventPublisher events, Clock clock, Duration interval) {
        this.store = Objects.requireNonNull(store);
        this.events = Objects.requireNonNull(events);
        this.clock = Objects.requireNonNull(clock);
        if (interval == null || interval.isZero() || interval.isNegative()) {
            throw new IllegalArgumentException("interval은 0보다 커야 한다");
        }
        this.interval = interval;
    }

    /**
     * 지금 끝난 행을 지운다.
     *
     * @return 지운 행 수
     */
    public int cleanup() {
        int total = 0;
        for (int batch = 0; batch < MAX_BATCHES_PER_RUN; batch++) {
            Instant now = clock.instant();
            List<KeycloakSessionRecord> deleted = store.deleteEnded(now, BATCH_SIZE);
            for (KeycloakSessionRecord record : deleted) {
                KeycloakSessionEndReason reason = record.isAbsolutelyExpired(now)
                    ? KeycloakSessionEndReason.ABSOLUTE_TIMEOUT : KeycloakSessionEndReason.IDLE;
                events.publish(KeycloakSessionEvent.ended(record, reason, now));
            }
            total += deleted.size();
            if (deleted.size() < BATCH_SIZE) {
                break;
            }
        }
        if (total > 0) {
            log.debug("[KSS] 끝난 세션 행 {}개를 지웠습니다", total);
        }
        return total;
    }

    private void runSafely() {
        try {
            cleanup();
        } catch (RuntimeException e) {
            log.warn("[KSS] 세션 정리 작업이 실패했습니다. 다음 주기에 다시 합니다: {}", e.toString());
        }
    }

    @Override
    public synchronized void start() {
        if (executor != null) {
            return;
        }
        executor = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "kss-session-cleaner");
            thread.setDaemon(true);
            return thread;
        });
        long millis = interval.toMillis();
        executor.scheduleWithFixedDelay(this::runSafely, millis, millis, TimeUnit.MILLISECONDS);
    }

    @Override
    public synchronized void stop() {
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
    }

    @Override
    public boolean isRunning() {
        return executor != null;
    }

    /** 정리 주기. */
    public Duration interval() {
        return interval;
    }
}
