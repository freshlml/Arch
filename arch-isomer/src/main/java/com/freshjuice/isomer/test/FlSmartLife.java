package com.freshjuice.isomer.test;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.SmartLifecycle;

public class FlSmartLife implements SmartLifecycle, DisposableBean {

    private boolean running;
    @Autowired
    private FlLife flLife;

    private void setRunning(boolean running) {
        this.running = running;
    }

    @Override
    public void start() {
        System.out.println("SmartLifecycle start");
        setRunning(true);
    }

    @Override
    public void stop() {
        System.out.println("SmartLifecycle stop");
        setRunning(false);
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    @Override
    public boolean isAutoStartup() {
        return true;
    }

    @Override
    public void stop(Runnable callback) {
        stop();
        callback.run();
    }

    @Override
    public int getPhase() {
        return Integer.MAX_VALUE;
    }

    @Override
    public void destroy() throws Exception {
        System.out.println("SmartLifecycle destroy");
        setRunning(false);
    }
}
