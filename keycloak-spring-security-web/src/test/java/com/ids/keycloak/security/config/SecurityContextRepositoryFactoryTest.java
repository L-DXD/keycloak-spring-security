package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * {@link SecurityContextRepositoryFactory}가 {@link SecurityContextRepositoryMode}별로 기대한
 * {@link SecurityContextRepository} 구현체를 생성하는지 검증한다 (23d36d6, 항목 1).
 *
 * <p>{@code KeycloakHttpConfigurer}와 {@code KeycloakLoginService}가 이 팩토리를 공유하므로,
 * 매핑 자체가 두 소비자의 정책 일치를 보장하는 단일 지점이다.</p>
 */
class SecurityContextRepositoryFactoryTest {

    @Nested
    class NULL_모드 {

        @Test
        void NULL_모드는_NullSecurityContextRepository를_반환한다() {
            SecurityContextRepository repository =
                SecurityContextRepositoryFactory.create(SecurityContextRepositoryMode.NULL);

            assertThat(repository).isInstanceOf(NullSecurityContextRepository.class);
        }

        @Test
        void mode가_null이면_기본값인_NullSecurityContextRepository로_처리된다() {
            SecurityContextRepository repository = SecurityContextRepositoryFactory.create(null);

            assertThat(repository).isInstanceOf(NullSecurityContextRepository.class);
        }
    }

    @Nested
    class HTTP_SESSION_모드 {

        @Test
        void HTTP_SESSION_모드는_HttpSessionSecurityContextRepository를_반환한다() {
            SecurityContextRepository repository =
                SecurityContextRepositoryFactory.create(SecurityContextRepositoryMode.HTTP_SESSION);

            assertThat(repository).isInstanceOf(HttpSessionSecurityContextRepository.class);
        }
    }

    @Nested
    class DELEGATING_모드 {

        @Test
        void DELEGATING_모드는_DelegatingSecurityContextRepository를_반환한다() {
            SecurityContextRepository repository =
                SecurityContextRepositoryFactory.create(SecurityContextRepositoryMode.DELEGATING);

            assertThat(repository).isInstanceOf(DelegatingSecurityContextRepository.class);
        }
    }

    @Nested
    class 호출마다_새_인스턴스 {

        @Test
        void 같은_모드라도_호출마다_새로운_인스턴스를_생성한다() {
            SecurityContextRepository first =
                SecurityContextRepositoryFactory.create(SecurityContextRepositoryMode.HTTP_SESSION);
            SecurityContextRepository second =
                SecurityContextRepositoryFactory.create(SecurityContextRepositoryMode.HTTP_SESSION);

            assertThat(first).isNotSameAs(second);
        }
    }
}
