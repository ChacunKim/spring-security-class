package com.prgrms.devcourse.configures;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.apache.commons.lang3.math.NumberUtils.toInt;

public class CustomWebSecurityExpressionRoot extends WebSecurityExpressionRoot {

  static final Pattern PATTERN = Pattern.compile("[0-9]+$"); //정규식

  public CustomWebSecurityExpressionRoot(Authentication a, FilterInvocation fi) {
    super(a, fi);
  }

  public boolean isOddAdmin() {
    User user = (User) getAuthentication().getPrincipal(); //사용자 principal: 사용자 객체
    String name = user.getUsername(); //user 이름 가져옴
    Matcher matcher = PATTERN.matcher(name); //이름 끝부분이 홀/짝인지 확인
    if (matcher.find()) {
      int number = toInt(matcher.group(), 0);
      return number % 2 == 1; //홀수이면 true 리턴
    }
    return false;//짝수이면 false 리턴
  }

}