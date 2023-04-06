package com.prgrms.devcourse;

import java.util.concurrent.CompletableFuture;

import static java.util.concurrent.CompletableFuture.runAsync;

public class ThreadLocalApp {

    final static ThreadLocal<Integer> threadLocalValue = new ThreadLocal<>();

    public static void main(String[] args){
        System.out.println(getCurrentThreadName() + " ### main set value = 1"); // 1
        threadLocalValue.set(1);

        //main thread 에서 threadLocal 변수 1에 접근.
        a(); // main ### a() get value = 1   -> main 쓰레드의 메소드 a()에서 threadLocal value 에 접근
        b(); // main ### b() get value = 1   -> main 쓰레드의 메소드 b()에서 threadLocal value 에 접근

        //runAsync(): 메인 thread 가 아닌 다른 thread 에서 수행되도록 하는 람다 코드블럭.
        CompletableFuture<Void> task = runAsync(() -> {
            a(); // 다른 thread 에서 접근했으므로 null, thread 이름도 main이 아니다.
            b(); // a와 마찬가지.
        });

        task.join();
    }

    public static void a(){
        Integer value = threadLocalValue.get();
        System.out.println(getCurrentThreadName() + " ### a() get value = " + value);
    }

    public static void b(){
        Integer value = threadLocalValue.get();
        System.out.println(getCurrentThreadName() + " ### b() get value = " + value);
    }

    public static String getCurrentThreadName(){
        return Thread.currentThread().getName();
    }
}
