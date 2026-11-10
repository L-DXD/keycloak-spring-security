package com.ids.keycloak.security.sample.e2e;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;

/** 샘플 앱 서버에 만들어진 HttpSession 수 (REQ-05). 테스트에서만 올린다. 실패 원인을 찾도록 마지막으로 만든 곳의 호출 순서를 남긴다. */
public class HttpSessionCounter implements HttpSessionListener {

    private final AtomicInteger created = new AtomicInteger();
    private final AtomicReference<String> lastCreatedBy = new AtomicReference<>("");

    @Override
    public void sessionCreated(HttpSessionEvent event) {
        created.incrementAndGet();
        StringWriter stack = new StringWriter();
        new Throwable("HttpSession을 만든 곳").printStackTrace(new PrintWriter(stack));
        lastCreatedBy.set(stack.toString());
    }

    public int created() {
        return created.get();
    }

    /** 마지막으로 HttpSession을 만든 곳의 호출 순서 (없으면 빈 문자열). */
    public String lastCreatedBy() {
        return lastCreatedBy.get();
    }
}
