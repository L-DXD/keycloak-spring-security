package com.ids.keycloak.security.util;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * SecurityHandlerUtil.isAjaxRequest() 단위 테스트.
 *
 * <p>이슈 #52: 브라우저 {@code Accept: *}{@code /*} 와일드카드를 application/json 포함으로 오판하던
 * 기존 {@code acceptHeader.contains("application/json")} 방식을 개선한 로직을 검증한다.
 *
 * <p>검증 케이스:
 * <ul>
 *   <li>브라우저 표준 Accept (text/html,...,*&#47;*;q=0.8) → false</li>
 *   <li>Accept: application/json 단독 → true</li>
 *   <li>X-Requested-With: XMLHttpRequest (임의 Accept) → true</li>
 *   <li>Accept: *&#47;* 단독 → false</li>
 *   <li>Accept 없음/빈 값 → false</li>
 * </ul>
 */
class SecurityHandlerUtilTest {

  // =========================================================
  // X-Requested-With 헤더 기반 판정
  // =========================================================
  @Nested
  @DisplayName("X-Requested-With 헤더 기반 판정")
  class XRequestedWith_헤더 {

    @Test
    @DisplayName("X-Requested-With: XMLHttpRequest → true (Accept 무관)")
    void XRequestedWith_XMLHttpRequest_AJAX() {
      MockHttpServletRequest request = new MockHttpServletRequest();
      request.addHeader("X-Requested-With", "XMLHttpRequest");
      // Accept가 */* 이어도 X-Requested-With가 있으면 AJAX
      request.addHeader("Accept", "*/*");

      assertThat(SecurityHandlerUtil.isAjaxRequest(request)).isTrue();
    }

    @Test
    @DisplayName("X-Requested-With: XMLHttpRequest (Accept 없음) → true")
    void XRequestedWith_XMLHttpRequest_Accept_없음() {
      MockHttpServletRequest request = new MockHttpServletRequest();
      request.addHeader("X-Requested-With", "XMLHttpRequest");

      assertThat(SecurityHandlerUtil.isAjaxRequest(request)).isTrue();
    }

    @Test
    @DisplayName("X-Requested-With 값이 다른 경우 → X-Requested-With로 AJAX 판정 안 함")
    void XRequestedWith_다른값_비AJAX() {
      MockHttpServletRequest request = new MockHttpServletRequest();
      request.addHeader("X-Requested-With", "fetch");

      assertThat(SecurityHandlerUtil.isAjaxRequest(request)).isFalse();
    }
  }

  // =========================================================
  // Accept 헤더 기반 판정
  // =========================================================
  @Nested
  @DisplayName("Accept 헤더 기반 판정")
  class Accept_헤더 {

    @Test
    @DisplayName("브라우저 표준 Accept (text/html,...,*/*;q=0.8) → false")
    void 브라우저_표준_Accept_비AJAX() {
      MockHttpServletRequest request = new MockHttpServletRequest();
      // Chrome/Firefox 계열 브라우저 표준 Accept
      request.addHeader("Accept",
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");

      assertThat(SecurityHandlerUtil.isAjaxRequest(request)).isFalse();
    }

    @Test
    @DisplayName("Accept: application/json 단독 → true")
    void Accept_application_json_단독_AJAX() {
      MockHttpServletRequest request = new MockHttpServletRequest();
      request.addHeader("Accept", "application/json");

      assertThat(SecurityHandlerUtil.isAjaxRequest(request)).isTrue();
    }

    @Test
    @DisplayName("Accept: application/json;charset=UTF-8 → true")
    void Accept_application_json_charset_AJAX() {
      MockHttpServletRequest request = new MockHttpServletRequest();
      request.addHeader("Accept", "application/json;charset=UTF-8");

      assertThat(SecurityHandlerUtil.isAjaxRequest(request)).isTrue();
    }

    @Test
    @DisplayName("Accept: application/vnd.api+json → true (+json subtype)")
    void Accept_plus_json_subtype_AJAX() {
      MockHttpServletRequest request = new MockHttpServletRequest();
      request.addHeader("Accept", "application/vnd.api+json");

      assertThat(SecurityHandlerUtil.isAjaxRequest(request)).isTrue();
    }

    @Test
    @DisplayName("Accept: */* 단독 → false")
    void Accept_wildcard_단독_비AJAX() {
      MockHttpServletRequest request = new MockHttpServletRequest();
      request.addHeader("Accept", "*/*");

      assertThat(SecurityHandlerUtil.isAjaxRequest(request)).isFalse();
    }

    @Test
    @DisplayName("Accept 헤더 없음 → false")
    void Accept_헤더_없음_비AJAX() {
      MockHttpServletRequest request = new MockHttpServletRequest();
      // Accept 헤더 설정 안 함

      assertThat(SecurityHandlerUtil.isAjaxRequest(request)).isFalse();
    }

    @Test
    @DisplayName("Accept 빈 값 → false")
    void Accept_빈값_비AJAX() {
      MockHttpServletRequest request = new MockHttpServletRequest();
      request.addHeader("Accept", "");

      assertThat(SecurityHandlerUtil.isAjaxRequest(request)).isFalse();
    }

    @Test
    @DisplayName("Accept: application/json,text/html → text/html 포함 → false")
    void Accept_json_and_html_비AJAX() {
      MockHttpServletRequest request = new MockHttpServletRequest();
      // application/json이 있더라도 text/html도 있으면 브라우저 네비게이션으로 판정
      request.addHeader("Accept", "application/json, text/html");

      assertThat(SecurityHandlerUtil.isAjaxRequest(request)).isFalse();
    }
  }

  // =========================================================
  // 복합 케이스
  // =========================================================
  @Nested
  @DisplayName("복합 케이스")
  class 복합_케이스 {

    @Test
    @DisplayName("X-Requested-With + 브라우저 Accept → X-Requested-With 우선 → true")
    void XRequestedWith_우선_AJAX() {
      MockHttpServletRequest request = new MockHttpServletRequest();
      request.addHeader("X-Requested-With", "XMLHttpRequest");
      request.addHeader("Accept",
          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");

      assertThat(SecurityHandlerUtil.isAjaxRequest(request)).isTrue();
    }

    @Test
    @DisplayName("헤더 전혀 없음 → false")
    void 헤더_없음_비AJAX() {
      MockHttpServletRequest request = new MockHttpServletRequest();

      assertThat(SecurityHandlerUtil.isAjaxRequest(request)).isFalse();
    }
  }
}
