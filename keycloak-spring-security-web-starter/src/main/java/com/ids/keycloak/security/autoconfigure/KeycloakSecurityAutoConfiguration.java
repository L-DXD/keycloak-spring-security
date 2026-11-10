package com.ids.keycloak.security.autoconfigure;

import java.time.Clock;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.LazyInitializationExcludeFilter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import com.ids.keycloak.security.KeycloakSecurityVersion;
import com.ids.keycloak.security.config.KeycloakSecuritySettings;
import com.ids.keycloak.security.config.SessionStoreType;

/**
 * Servlet 앱 자동 설정 (v3). 모든 빈은 {@code @ConditionalOnMissingBean}이라 같은 빈을 올리면 그것을 쓴다.
 * <p>
 * 이 판(#79)은 설정 검사와 기동 로그만 한다. 세션 저장소, 토큰 검증, 로그인·로그아웃 빈은 이슈마다 여기에 더한다.
 * Boot의 기본 보안 체인보다 먼저 돈다.
 */
@AutoConfiguration(
    after = OAuth2ClientAutoConfiguration.class,
    beforeName = {
        "org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration",
        "org.springframework.boot.security.oauth2.client.autoconfigure.servlet.OAuth2ClientWebSecurityAutoConfiguration"
    })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(ClientRegistrationRepository.class)
@ConditionalOnBooleanProperty(name = KeycloakSecuritySettings.PREFIX + ".enabled", matchIfMissing = true)
@EnableConfigurationProperties(KeycloakSecurityProperties.class)
public class KeycloakSecurityAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(KeycloakSecurityAutoConfiguration.class);

    /**
     * 설정을 검사한다. 잘못되면 기동하지 않는다 (CONF-02~04). 지연 초기화를 켜도 기동 때 검사한다.
     */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakSecuritySettings keycloakSecuritySettings(KeycloakSecurityProperties properties,
                                                             ObjectProvider<ClientRegistrationRepository> registrations) {
        String registrationId = properties.getRegistrationId();
        ClientRegistration registration = findRegistration(registrations.getIfAvailable(), registrationId);
        KeycloakSecuritySettings.Builder builder = properties.toSettingsBuilder(registration == null ? null : registration.getClientId());
        String registrationProperty = "spring.security.oauth2.client.registration." + registrationId;
        if (registration == null) {
            builder.problem(registrationProperty, "OAuth2 Client 등록이 없습니다 (client-id, client-secret, provider.issuer-uri)");
        } else {
            if (!AuthorizationGrantType.AUTHORIZATION_CODE.equals(registration.getAuthorizationGrantType())) {
                builder.problem(registrationProperty + ".authorization-grant-type", "authorization_code여야 합니다");
            }
            if (ClientAuthenticationMethod.NONE.equals(registration.getClientAuthenticationMethod())) {
                builder.problem(registrationProperty + ".client-secret", "비공개 client여야 합니다 (client-secret이 필요합니다)");
            }
        }
        KeycloakSecuritySettings settings = builder.build();
        logStartup(settings, registration);
        return settings;
    }

    /** 설정 검사를 지연 초기화에서 뺀다. */
    @Bean
    public static LazyInitializationExcludeFilter keycloakSecuritySettingsEagerInit() {
        return LazyInitializationExcludeFilter.forBeanTypes(KeycloakSecuritySettings.class);
    }

    /** 라이브러리가 쓰는 시계. 테스트에서 바꿔 끼운다 (절대 상한·만료 시나리오). */
    @Bean(name = "keycloakSecurityClock")
    @ConditionalOnMissingBean(name = "keycloakSecurityClock")
    public Clock keycloakSecurityClock() {
        return Clock.systemUTC();
    }

    private static ClientRegistration findRegistration(ClientRegistrationRepository repository, String registrationId) {
        if (repository == null || registrationId == null || registrationId.isBlank()) {
            return null;
        }
        return repository.findByRegistrationId(registrationId);
    }

    /** CONF-01·05: 기동 로그. 비밀값(키, client secret)은 찍지 않는다. */
    private static void logStartup(KeycloakSecuritySettings settings, ClientRegistration registration) {
        String store = settings.sessionStore().name().toLowerCase(Locale.ROOT)
            + (settings.sessionStore() == SessionStoreType.JDBC ? "(" + settings.sessionTableName() + ")" : "");
        log.info("[KSS] keycloak-spring-security v3 ({}) 켜짐: 세션 저장소={}, 앱 이름={}, 화면 주소={}, 클라이언트={}({}), 활성 키={}",
            KeycloakSecurityVersion.current(), store, settings.cookieAppName(), settings.frontendBaseUrl(),
            settings.registrationId(), registration.getClientId(), settings.keyRing().activeKeyId());
        if (settings.sessionStore() == SessionStoreType.MEMORY) {
            log.warn("[KSS] 세션 저장소가 memory입니다. 서버를 여러 대 띄우면 로그인이 서로 보이지 않고, 재시작하면 모두 로그아웃됩니다. "
                + "개발·테스트에만 쓰고 운영에서는 keycloak.security.session.store=jdbc를 쓰세요.");
        }
    }
}
