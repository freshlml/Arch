package com.freshjuice.isomer.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@ConditionalOnProperty(prefix = "spring", value = "datasource")
@Configuration
public class FlTestConditionalOnProperty {

    @Bean
    public T t() {
        System.out.println("中间属性");
        return new T();
    }

    public static class T {

    }
}
