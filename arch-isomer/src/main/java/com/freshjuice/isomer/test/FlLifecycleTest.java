package com.freshjuice.isomer.test;

import org.springframework.context.annotation.AnnotationConfigApplicationContext;

public class FlLifecycleTest {

    public static void main(String argv[]) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.register(FlConfig.class);

        //容器refresh不会触发Lifecycle.start
        //if SmartLifecycle.isAutoStartup=true, 容器refresh触发SmartLifecycle.start
        context.refresh();

        //容器start触发Lifecycle.start(会判断isRunning=false的才会执行)
        //容器start触发SmartLifecycle.start(会判断isRunning=false的才会执行)
        //context.start();

        //容器stop触发Lifecycle.stop(会判断isRunning=true的才会执行)
        //容器stop触发SmartLifecycle.stop(会判断isRunning=true的才会执行)
        //context.stop();

        //容器close触发Lifecycle.stop(会判断isRunning=true才会执行), 先于DisposableBean执行
        //容器close触发SmartLifecycle.stop(会判断isRunning=true才会执行), 先于DisposableBean执行
        context.close();

        //容器hot refresh(?)，只会DisposableBean，没有Lifecycle
        //容器refresh发生异常，只会DisposableBean，没有Lifecycle
        //Lifecycle的phase=0,SmartLifecycle实现Phased，lowest phase先start后stop
        //lazy-init对SmartLifecycle影响非常有限?

    }


}
