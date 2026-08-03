package com.ids.keycloak.security.config;

import lombok.experimental.UtilityClass;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * {@link SecurityContextRepositoryMode} 설정값에 해당하는 {@link SecurityContextRepository} 인스턴스를
 * 생성하는 유틸리티입니다.
 *
 * <p>{@code KeycloakHttpConfigurer}(SecurityFilterChain 구성)와 {@code KeycloakLoginService}
 * (프로그래밍 방식 로그인)가 동일한 {@code keycloak.security.authentication.security-context-repository}
 * 정책을 일관되게 따르도록, 두 곳에서 공유하는 단일 생성 로직입니다.</p>
 *
 * @see SecurityContextRepositoryMode
 */
@UtilityClass
public class SecurityContextRepositoryFactory {

    /**
     * 지정된 정책에 해당하는 {@link SecurityContextRepository}를 생성합니다.
     *
     * @param mode 저장 정책 ({@code null}이면 {@link SecurityContextRepositoryMode#NULL}로 처리)
     * @return 선택된 정책에 해당하는 새 {@link SecurityContextRepository} 인스턴스
     */
    public static SecurityContextRepository create(SecurityContextRepositoryMode mode) {
        SecurityContextRepositoryMode effectiveMode = mode != null ? mode : SecurityContextRepositoryMode.NULL;
        switch (effectiveMode) {
            case HTTP_SESSION:
                return new HttpSessionSecurityContextRepository();
            case DELEGATING:
                return new DelegatingSecurityContextRepository(
                    new RequestAttributeSecurityContextRepository(),
                    new HttpSessionSecurityContextRepository()
                );
            case NULL:
            default:
                return new NullSecurityContextRepository();
        }
    }
}
