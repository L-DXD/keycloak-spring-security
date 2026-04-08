package com.ids.keycloak.security.test.servlet;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
@RequiredArgsConstructor
public class RedisConfigLocal {

   private final RedisProperties redisProperties;

   @Bean
   public RedisConnectionFactory redisConnectionFactory() {
      RedisStandaloneConfiguration config = new RedisStandaloneConfiguration();
      config.setHostName(redisProperties.getHost());
      config.setPort(redisProperties.getPort());
      config.setPassword(redisProperties.getPassword());
      return new LettuceConnectionFactory(config);
   }

   @Bean
   public RedisTemplate<String, Object> redisTemplate() {
      RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
      redisTemplate.setConnectionFactory(redisConnectionFactory());
      redisTemplate.setKeySerializer(new StringRedisSerializer());
      redisTemplate.setValueSerializer(new StringRedisSerializer());
      return redisTemplate;
   }
}
