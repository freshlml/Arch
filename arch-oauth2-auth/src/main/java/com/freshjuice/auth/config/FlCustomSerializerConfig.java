package com.freshjuice.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FlCustomSerializerConfig {

    @Bean
    public FlCustomSerializer flCustomSerializer() {
        return new FlCustomSerializer();
    }
}
