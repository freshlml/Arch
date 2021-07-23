package com.freshjuice.isomer.test;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;

@Configuration
public class FlConfig {

    @Bean
    public FlLife flLife() {
        return new FlLife();
    }

    @Lazy
    @Bean
    public FlSmartLife flSmartLife() {
        return new FlSmartLife();
    }

}
