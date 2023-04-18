package com.prgrms.devcourse.configures;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;

@EnableAsync
@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

  private final Logger log = LoggerFactory.getLogger(getClass());

  @Bean
  @Qualifier("myAsyncTaskExecutor")
  public ThreadPoolTaskExecutor threadPoolTaskExecutor() {
    ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
    executor.setCorePoolSize(3);
    executor.setMaxPoolSize(5);
    executor.setThreadNamePrefix("my-executor-");
    return executor;
  }

  @Bean
  public DelegatingSecurityContextAsyncTaskExecutor taskExecutor(
    @Qualifier("myAsyncTaskExecutor") ThreadPoolTaskExecutor delegate
  ) {
    return new DelegatingSecurityContextAsyncTaskExecutor(delegate);
  }

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
  public AccessDecisionManager accessDecisionManager() {
    List<AccessDecisionVoter<?>> decisionVoters = new ArrayList<>();
    decisionVoters.add(new WebExpressionVoter());
    decisionVoters.add(new OddAdminVoter(new AntPathRequestMatcher("/admin")));
    return new UnanimousBased(decisionVoters);
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

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .authorizeRequests()
        .antMatchers("/me", "/asyncHello", "/someMethod").hasAnyRole("USER", "ADMIN")
        .antMatchers("/admin").access("isFullyAuthenticated() and hasRole('ADMIN')")
        .anyRequest().permitAll()
        .accessDecisionManager(accessDecisionManager())
        .and()
      .formLogin()
        .defaultSuccessUrl("/")
        .permitAll()
        .and()
      /**
       * Basic Authentication 설정
       */
      .httpBasic()
        .and()
      /**
       * remember me 설정
       */
      .rememberMe()
        .rememberMeParameter("remember-me")
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
       * 예외처리 핸들러
       */
      .exceptionHandling()
        .accessDeniedHandler(accessDeniedHandler())
    ;
  }

}