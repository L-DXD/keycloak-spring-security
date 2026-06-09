package com.ids.keycloak.security.dto;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * H-3: Reactive DTO @NotBlank 검증 테스트.
 */
class ReactiveDtoValidationTest {

  private static Validator validator;

  @BeforeAll
  static void setup() {
    validator = Validation.buildDefaultValidatorFactory().getValidator();
  }

  @Test
  @DisplayName("ReactiveTokenRequest - username 비어있으면 위반")
  void tokenRequest_username_blank_위반() {
    var req = new ReactiveTokenRequest("", "pass123");
    Set<ConstraintViolation<ReactiveTokenRequest>> violations = validator.validate(req);
    assertThat(violations).isNotEmpty();
    assertThat(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("username"))).isTrue();
  }

  @Test
  @DisplayName("ReactiveTokenRequest - password 비어있으면 위반")
  void tokenRequest_password_blank_위반() {
    var req = new ReactiveTokenRequest("user1", "");
    Set<ConstraintViolation<ReactiveTokenRequest>> violations = validator.validate(req);
    assertThat(violations).isNotEmpty();
    assertThat(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("password"))).isTrue();
  }

  @Test
  @DisplayName("ReactiveTokenRequest - 정상 입력이면 위반 없음")
  void tokenRequest_정상() {
    var req = new ReactiveTokenRequest("user1", "pass123");
    Set<ConstraintViolation<ReactiveTokenRequest>> violations = validator.validate(req);
    assertThat(violations).isEmpty();
  }

  @Test
  @DisplayName("ReactiveRefreshRequest - refreshToken 비어있으면 위반")
  void refreshRequest_blank_위반() {
    var req = new ReactiveRefreshRequest("");
    Set<ConstraintViolation<ReactiveRefreshRequest>> violations = validator.validate(req);
    assertThat(violations).isNotEmpty();
  }

  @Test
  @DisplayName("ReactiveRefreshRequest - 정상 입력이면 위반 없음")
  void refreshRequest_정상() {
    var req = new ReactiveRefreshRequest("refresh-token-value");
    Set<ConstraintViolation<ReactiveRefreshRequest>> violations = validator.validate(req);
    assertThat(violations).isEmpty();
  }

  @Test
  @DisplayName("ReactiveLogoutRequest - refreshToken 비어있으면 위반")
  void logoutRequest_blank_위반() {
    var req = new ReactiveLogoutRequest("");
    Set<ConstraintViolation<ReactiveLogoutRequest>> violations = validator.validate(req);
    assertThat(violations).isNotEmpty();
  }

  @Test
  @DisplayName("ReactiveLogoutRequest - 정상 입력이면 위반 없음")
  void logoutRequest_정상() {
    var req = new ReactiveLogoutRequest("refresh-token-value");
    Set<ConstraintViolation<ReactiveLogoutRequest>> violations = validator.validate(req);
    assertThat(violations).isEmpty();
  }
}
