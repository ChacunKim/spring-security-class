package com.prgrms.devcourse.configures;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component //Bean 등록
public class CustomAuthenticationEventHandler {

  private final Logger log = LoggerFactory.getLogger(getClass());

  @Async // 쓰레드 분리. @Async 를 활성화시키기 위해 WebMvcConfigure 에 @EnableAsync 추가.
  @EventListener  //  EventListener 추가: Authentication 성공 이벤트를 다루는 EventListener
  public void handleAuthenticationSuccessEvent(AuthenticationSuccessEvent event) { //method parameter 로 event 를 수신
    /*
    EventListener 처리가 지연되면 호출한 측도 처리 지연됨.
     - 로그의 [XNIO-1 task-2] : 별도의 쓰레드가 아니라 WAS 에서 요청을 처리하기 위해 바인딩된 쓰레드에서 EventHandler 까지 처리.
        -> 즉, EventListener 는 동기적으로 처리된다.
     - @Async: 쓰레드 분리. @Async 를 붙이면 별도의 쓰레드에서 이벤트가 처리된다.
        -> 지연을 기다리지 않고 즉시 로그인 처리됨.
        -> 로그가 지연 시간만큼 나중에 찍히고, 쓰레드도 다른 것임을 알 수 있음 (XNIO-1이라는 prefix 를 볼 수 없음)
     */
    try{
      Thread.sleep(5000L); //지연 테스트: sleep 걸어놓은 만큼 지연됨
    }catch (InterruptedException e){
    }

    Authentication authentication = event.getAuthentication();
    log.info("Successful authentication result: {}", authentication.getPrincipal());
  }

  //  EventListener 추가: Authentication 실패 이벤트를 다루는 EventListener
  @EventListener
  public void handleAuthenticationFailureEvent(AbstractAuthenticationFailureEvent event) {
    Exception e = event.getException();
    Authentication authentication = event.getAuthentication();
    log.warn("Unsuccessful authentication result: {}", authentication, e);
  }

}