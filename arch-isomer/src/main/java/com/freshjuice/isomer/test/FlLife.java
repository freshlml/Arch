package com.freshjuice.isomer.test;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.context.Lifecycle;

public class FlLife implements Lifecycle, DisposableBean {

    private boolean running;

    @Override
    public void start() {
        System.out.println("Lifecycle start");
        setRunning(true);
    }

    @Override
    public void stop() {
        System.out.println("Lifecycle stop");
        setRunning(false);
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    private void setRunning(boolean running) {
        this.running = running;
    }

    @Override
    public void destroy() throws Exception {
        System.out.println("Lifecycle destroy");
        setRunning(false);
    }
}
