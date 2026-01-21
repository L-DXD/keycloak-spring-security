package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.MapSession;

class IndexedMapSessionRepositoryTest {

    private IndexedMapSessionRepository repository;

    @BeforeEach
    void setUp() {
        repository = new IndexedMapSessionRepository();
    }

    @Nested
    class 정상_케이스 {
        @Test
        void 세션을_생성하고_저장하고_조회한다() {
            // Given
            MapSession session = repository.createSession();
            String sessionId = session.getId();

            // When
            repository.save(session);
            MapSession found = repository.findById(sessionId);

            // Then
            assertThat(found).isNotNull();
            assertThat(found.getId()).isEqualTo(sessionId);
        }

        @Test
        void Principal_Name으로_세션을_검색한다() {
            // Given
            MapSession sessionA = repository.createSession();
            sessionA.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, "user1");

            MapSession sessionB = repository.createSession();
            sessionB.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, "user1");

            MapSession sessionC = repository.createSession();
            sessionC.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, "user2");

            repository.save(sessionA);
            repository.save(sessionB);
            repository.save(sessionC);

            // When
            Map<String, MapSession> result = repository.findByPrincipalName("user1");

            // Then
            assertThat(result).hasSize(2);
            assertThat(result).containsKey(sessionA.getId());
            assertThat(result).containsKey(sessionB.getId());
            assertThat(result).doesNotContainKey(sessionC.getId());
        }

        @Test
        void findByIndexNameAndIndexValue로_Principal_Name_검색이_가능하다() {
            // Given
            MapSession session = repository.createSession();
            session.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, "user1");
            repository.save(session);

            // When
            Map<String, MapSession> result = repository.findByIndexNameAndIndexValue(
                FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, "user1");

            // Then
            assertThat(result).hasSize(1);
            assertThat(result).containsKey(session.getId());
        }

        @Test
        void 세션을_삭제한다() {
            // Given
            MapSession session = repository.createSession();
            String sessionId = session.getId();
            repository.save(session);

            // When
            repository.deleteById(sessionId);

            // Then
            assertThat(repository.findById(sessionId)).isNull();
        }

        @Test
        void 기본_만료_시간을_설정한다() {
            // Given
            Duration customDuration = Duration.ofHours(1);
            repository.setDefaultMaxInactiveInterval(customDuration);

            // When
            MapSession session = repository.createSession();

            // Then
            assertThat(session.getMaxInactiveInterval()).isEqualTo(customDuration);
        }
    }

    @Nested
    class 바운더리_케이스 {

        @Test
        void 만료된_세션은_조회되지_않고_삭제된다() {
            // Given
            MapSession session = repository.createSession();
            String sessionId = session.getId();
            session.setLastAccessedTime(Instant.now().minus(Duration.ofHours(1)));
            session.setMaxInactiveInterval(Duration.ofMinutes(30));
            repository.save(session);

            // When
            MapSession found = repository.findById(sessionId);

            // Then
            assertThat(found).isNull();
        }

        @Test
        void 존재하지_않는_ID로_조회하면_null을_반환한다() {
            // When
            MapSession found = repository.findById("non-existent-id");

            // Then
            assertThat(found).isNull();
        }

        @Test
        void 지원하지_않는_인덱스로_검색하면_빈_맵을_반환한다() {
            // Given
            MapSession session = repository.createSession();
            session.setAttribute("CUSTOM_INDEX", "value");
            repository.save(session);

            // When
            Map<String, MapSession> result = repository.findByIndexNameAndIndexValue("UNSUPPORTED_INDEX", "value");

            // Then
            assertThat(result).isEmpty();
        }

        @Test
        void 세션_ID가_변경되면_기존_세션이_제거된다() {
            // Given
            MapSession session = repository.createSession();
            String originalId = session.getId();
            repository.save(session);

            // When - 세션 ID 변경
            session.changeSessionId();
            String newId = session.getId();
            repository.save(session);

            // Then
            assertThat(repository.findById(originalId)).isNull();
            assertThat(repository.findById(newId)).isNotNull();
        }

        @Test
        void 만료된_세션은_Principal_Name_검색에서_제외된다() {
            // Given
            MapSession validSession = repository.createSession();
            validSession.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, "user1");
            repository.save(validSession);

            MapSession expiredSession = repository.createSession();
            expiredSession.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, "user1");
            expiredSession.setLastAccessedTime(Instant.now().minus(Duration.ofHours(1)));
            expiredSession.setMaxInactiveInterval(Duration.ofMinutes(30));
            repository.save(expiredSession);

            // When
            Map<String, MapSession> result = repository.findByPrincipalName("user1");

            // Then
            assertThat(result).hasSize(1);
            assertThat(result).containsKey(validSession.getId());
        }
    }
}
