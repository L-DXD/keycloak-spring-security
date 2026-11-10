package com.ids.keycloak.security.sample.e2e;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.Statement;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.sql.DataSource;

import org.springframework.beans.factory.config.BeanPostProcessor;

/**
 * 샘플 앱이 DB에 보낸 SQL을 적어 둔다 (REQ-03 "세션 행 조회 0번"). 앱의 DataSource 빈을 감싼다. 테스트에서만 올린다.
 */
public class SqlRecorder implements BeanPostProcessor {

    /** 보낸 SQL 하나와 보낸 스레드. */
    public record Sql(String thread, String text) {
    }

    private final List<Sql> statements = new CopyOnWriteArrayList<>();

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        if (bean instanceof DataSource dataSource) {
            return proxy(dataSource, new Class<?>[]{DataSource.class, AutoCloseable.class});
        }
        return bean;
    }

    public void clear() {
        statements.clear();
    }

    public List<Sql> statements() {
        return List.copyOf(statements);
    }

    /** 세션 테이블(auth_session)에 보낸 SQL. 정리 작업 스레드(kss-session-cleaner)는 뺀다. */
    public List<String> sessionTableStatements() {
        return statements.stream()
            .filter(s -> !s.thread().startsWith("kss-session-cleaner"))
            .map(Sql::text)
            .filter(t -> t.toLowerCase(Locale.ROOT).contains("auth_session"))
            .toList();
    }

    private Object proxy(Object target, Class<?>[] interfaces) {
        InvocationHandler handler = (proxy, method, args) -> {
            if (method.getName().equals("close") && !(target instanceof AutoCloseable)) {
                return null;
            }
            record(method, args);
            Object result;
            try {
                result = method.invoke(target, args);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }
            if (result instanceof Connection connection && !method.getName().equals("unwrap")) {
                return proxy(connection, new Class<?>[]{Connection.class});
            }
            if (result instanceof Statement statement && method.getName().equals("createStatement")) {
                return proxy(statement, new Class<?>[]{Statement.class});
            }
            return result;
        };
        return Proxy.newProxyInstance(getClass().getClassLoader(), interfaces, handler);
    }

    private void record(Method method, Object[] args) {
        String name = method.getName();
        boolean carriesSql = name.startsWith("prepare") || name.startsWith("execute") || name.equals("addBatch");
        if (carriesSql && args != null && args.length > 0 && args[0] instanceof String sql) {
            statements.add(new Sql(Thread.currentThread().getName(), sql));
        }
    }
}
