package com.prgrms.devcourse.configures;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

  private final Logger log = LoggerFactory.getLogger(getClass());

  @Override
  public void configure(WebSecurity web) {
    web.ignoring().antMatchers("/assets/**");
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication()
      .withUser("user").password("{noop}user123").roles("USER")
      .and()
      .withUser("admin01").password("{noop}admin123").roles("ADMIN")
      .and()
      .withUser("admin02").password("{noop}admin123").roles("ADMIN")
    ;
  }

  @Bean
  public AccessDeniedHandler accessDeniedHandler() {
    return (request, response, e) -> {
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      Object principal = authentication != null ? authentication.getPrincipal() : null;
      log.warn("{} is denied", principal, e);
      response.setStatus(HttpServletResponse.SC_FORBIDDEN);
      response.setContentType("text/plain;charset=UTF-8");
      response.getWriter().write("ACCESS DENIED");
      response.getWriter().flush();
      response.getWriter().close();
    };
  }

  public SecurityExpressionHandler<FilterInvocation> expressionHandler() {
    return new CustomWebSecurityExpressionHandler(new AuthenticationTrustResolverImpl(), "ROLE_");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .authorizeRequests()
        .antMatchers("/me").hasAnyRole("USER", "ADMIN")
        .antMatchers("/admin").access("isFullyAuthenticated() and hasRole('ADMIN') and oddAdmin")
            /**
             * /admin에 접근하기 위해서는
             *   1) isFullyAuthenticated(): rememberMe가 아닌 id, password 를 입력하고 인증받은 사용자여야 한다.
             *   2) hasRole('ADMIN'): ADMIN권한을 가진 사용자여야 한다.
             *   3) oddAdmin: CustomWebSecurityExpressionRoot의 isOddAdmin(): 홀수 admin이어야 함(admin01)
             * */

        .anyRequest().permitAll()
        .expressionHandler(expressionHandler()) //customExpressionHandler를 설정
        .and()
      .formLogin()
        .defaultSuccessUrl("/my-login") //로그인 url을 기본으로 생성되는 로그인 페이지가 아니라 직접 만든 로그인 페이지로 설정
        .usernameParameter("my-username") // 파라미터 커스텀 가능. html login 페이지의 input box 에 동일한 이름으로 입력
         .passwordParameter("my-password")
        .permitAll()
        .and()
      /**
       * remember me 설정
       */
      .rememberMe()
        .rememberMeParameter("remember-me")  // 파라미터 커스텀 가능. html login 페이지의 remember me check box 에 동일한 이름으로 입력
        .tokenValiditySeconds(300)
        .and()
      /**
       * 로그아웃 설정
       */
      .logout()
        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
        .logoutSuccessUrl("/")
        .invalidateHttpSession(true)
        .clearAuthentication(true)
        .and()
      /**
       * HTTP 요청을 HTTPS 요청으로 리다이렉트
       */
      .requiresChannel()
        .anyRequest().requiresSecure()
        .and()
      /**
       * sessionManagement: sessionFixation attack 방어: 로그인 후 세션 새로 발급
       * */
      .sessionManagement()
         .sessionFixation()
         .changeSessionId()
         .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) //세션 생성 전략 설정
         .invalidSessionUrl("/") //유효하지 않은 session이 감시되었을 때 이동할 url
         .maximumSessions(1) //최대로 동시 로그인 가능한 session 개수
            .maxSessionsPreventsLogin(false) // 로그인 가능한 session 개수 도달 시 로그인 여부. 불가
            .and()
         .and()
      /**
       * 예외처리 핸들러
       */
      .exceptionHandling()
        .accessDeniedHandler(accessDeniedHandler())
    ;
  }

}
