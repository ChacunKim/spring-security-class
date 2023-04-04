package com.prgrms.devcourse.configures;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/*
* EnableWebSecurity: WebSecurityConfigurerAdapter 를 상속하고
* @EnableWebSecurity 어노테이션을 붙이면 해당 클래스(WebSecurityConfigure) 내에서 대부분의 설정이 자동으로 추가됨
* 개별 설정을 원하면 WebSecurityConfigurerAdapter의 configure(WebSecurity web), configure(HttpSecurity http)을
* 오버라이드해서 spring security 를 커스텀할 수 있음
* */

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

  @Override
  public void configure(WebSecurity web) {
    /*
    WebSecurity 클래스는 필터 체인 관련 전역 설정을 처리할 수 있는 API 제공
      ignoring()
        - Spring Security 필터 체인을 적용하고 싶지 않은 리소스에 대해 설정
        - 일반적으로 정적 리소스(*.html, *.css, *.js 등)을 예외 대상으로 설정
        - 불필요한 서버 자원 낭비를 방지
     */
    web.ignoring().antMatchers("/assets/**"); //assets 디렉토리 이하에 있는 것은 스프링 필터 체인을 적용하지 않겠다
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    /*
    HttpSecurity 클래스는 세부적인 웹 보안기능 설정을 처리할 수 있는 API를 제공
      주요 메소드
        - authorizeRequests(): 공개 리소스 또는 보호받는 리소스에 대한 세부 설정
        - fromLogin(): 로그인 기능 세부설정
            -> Spring Security 가 로그인 화면을 자동으로 생성할 수 있게 해주는 설정
            -> defaultSuccessUrl("/"): 로그인 성공 시 "/" url 로 이동

        - logout(): 로그아웃 기능 세부설정
        - rememberMe(): 자동 로그인 기능 세부설정
    */
    http
          .authorizeRequests()
            .antMatchers("/me").hasAnyRole("USER", "ADMIN") // "/me"에 접근하려면 사용자가 USER 또는 ADMIN이라는 접근 권한을 가져야 한다. >> "/me"는 인증영역임.
            .anyRequest().permitAll() // (그 외에 모든 영역은) 익명영역임. 모두 허용한다.
            .and()
          .formLogin()
            .defaultSuccessUrl("/")
            .permitAll() // 모두 허용
            .and()
          .logout()
            .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
            .logoutSuccessUrl("/")
            .invalidateHttpSession(true)
            .clearAuthentication(true)
            .and()
          .rememberMe()
            .rememberMeParameter("remember-me")
            .tokenValiditySeconds(300)
    ;
  }
  /*
  /me로 바로 접근하면 로그인 페이지 생성됨.
  >> user, 콘솔창의 user 패스워드로 로그인
  >> 아래와 같은 에러 발생: 사용자가 로그인을 성공했으나 Granted Authorities=[], 즉 권한이 없어(USER, ROLE_ADMIN) 접근하지 못했다.(Failed to~)
  Set SecurityContextHolder to SecurityContextImpl
  [Authentication=UsernamePasswordAuthenticationToken
  [Principal=org.springframework.security.core.userdetails.User
  [Username=user, Password=[PROTECTED], Enabled=true, AccountNonExpired=true, credentialsNonExpired=true, AccountNonLocked=true, Granted Authorities=[]],
  Credentials=[PROTECTED],
  Authenticated=true,
  Details=WebAuthenticationDetails
  [RemoteIpAddress=0:0:0:0:0:0:0:1, SessionId=DSFUmOJ5m55nI23JLsZGfbjyS8Q-D4q-Dex4J7Dd],
  Granted Authorities=[]]]

  Failed to authorize filter invocation [GET /me] with attributes [hasAnyRole('ROLE_USER','ROLE_ADMIN')]

  >>> 기본 로그인 계정 설정 추가 -> application.yml
    security:
    user:
      name: user
      password: user123
      roles: USER

   */

}