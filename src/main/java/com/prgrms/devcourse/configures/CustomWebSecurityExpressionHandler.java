package com.prgrms.devcourse.configures;

import org.springframework.security.access.expression.AbstractSecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;

//DefaultWebSecurityExpressionHandler 와 비슷하게 구현
public class CustomWebSecurityExpressionHandler extends AbstractSecurityExpressionHandler<FilterInvocation> {

  private final AuthenticationTrustResolver trustResolver;

  private final String defaultRolePrefix;

  public CustomWebSecurityExpressionHandler(AuthenticationTrustResolver trustResolver, String defaultRolePrefix) {
    this.trustResolver = trustResolver;
    this.defaultRolePrefix = defaultRolePrefix;
  }

  //isOddAdmin()을 security 표현식에 사용 가능하도록 설정.
  @Override
  protected SecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication, FilterInvocation fi) {
//DefaultWebSecurityExpressionHandler 의
//    WebSecurityExpressionRoot root = new WebSecurityExpressionRoot(authentication, fi); 를 아래와 같이 변경
    CustomWebSecurityExpressionRoot root = new CustomWebSecurityExpressionRoot(authentication, fi);
    root.setPermissionEvaluator(getPermissionEvaluator());
    root.setTrustResolver(this.trustResolver);
    root.setRoleHierarchy(getRoleHierarchy());
    root.setDefaultRolePrefix(this.defaultRolePrefix);
    return root;
  }

}