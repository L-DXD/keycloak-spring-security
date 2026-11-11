package com.ids.keycloak.security.sample.e2e;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import ch.qos.logback.core.AppenderBase;

/**
 * 테스트 JVM의 모든 로그(샘플 앱 두 개 + 하네스)를 E2E가 끝날 때까지 모은다 (EVT-02). 메시지, MDC 값, 예외 내용을 한 줄로 남긴다.
 * 샘플 앱이 뜰 때 Spring Boot가 로그 설정을 다시 하므로 앱을 띄운 뒤 {@link #attach()}를 부른다.
 */
public final class E2eLogRecorder extends AppenderBase<ILoggingEvent> {

    private static final E2eLogRecorder INSTANCE = new E2eLogRecorder();

    private final List<String> lines = new ArrayList<>();

    private E2eLogRecorder() {
        setName("e2e-log-recorder");
    }

    /** 루트 로거에 붙인다 (이미 붙어 있으면 그대로). */
    public static synchronized void attach() {
        Logger root = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        INSTANCE.setContext(root.getLoggerContext());
        if (!INSTANCE.isStarted()) {
            INSTANCE.start();
        }
        if (root.getAppender(INSTANCE.getName()) == null) {
            root.addAppender(INSTANCE);
        }
    }

    /** 지금까지 모은 줄. */
    public static List<String> lines() {
        synchronized (INSTANCE.lines) {
            return List.copyOf(INSTANCE.lines);
        }
    }

    @Override
    protected void append(ILoggingEvent event) {
        StringBuilder line = new StringBuilder().append(event.getLevel()).append(' ').append(event.getLoggerName()).append(" - ")
            .append(event.getFormattedMessage());
        if (event.getMDCPropertyMap() != null && !event.getMDCPropertyMap().isEmpty()) {
            line.append(" mdc=").append(event.getMDCPropertyMap());
        }
        if (event.getThrowableProxy() != null) {
            line.append('\n').append(ThrowableProxyUtil.asString(event.getThrowableProxy()));
        }
        synchronized (lines) {
            lines.add(line.toString());
        }
    }
}
