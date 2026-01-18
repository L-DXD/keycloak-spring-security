package com.ids.keycloak.security.test.servlet;

import java.util.List;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisSentinelConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

@Setter
@Configuration
@ConfigurationProperties(prefix = "spring.data.redis.sentinel")
@Slf4j
public class RedisConfigSentinel {

  private List<String> nodes;  // spring.data.redis.sentinel.nodes
  private String master;       // spring.data.redis.sentinel.masterx

  @Value("${spring.data.redis.password}")
  private String password;

  @Bean
  public RedisConnectionFactory redisConnectionFactory() {
    RedisSentinelConfiguration sentinelConfig = new RedisSentinelConfiguration()
        .master(master);

    nodes.forEach(node -> {
      String[] parts = node.split(":");
      sentinelConfig.sentinel(parts[0], Integer.parseInt(parts[1]));
    });

    sentinelConfig.setPassword(password); // redis 인증
    sentinelConfig.setSentinelPassword(password); // Sentinel 인증

    return new LettuceConnectionFactory(sentinelConfig);
  }
}
