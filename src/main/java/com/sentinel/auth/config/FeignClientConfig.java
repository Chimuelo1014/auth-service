package com.sentinel.auth.config;

import feign.Logger;
import feign.RequestInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FeignClientConfig {

    @Bean
    public Logger.Level feignLoggerLevel() {
        return Logger.Level.FULL;
    }

    @Bean
    public RequestInterceptor requestInterceptor() {
        return requestTemplate -> {
            // Agregar headers comunes para todas las requests
            requestTemplate.header("Content-Type", "application/json");
            requestTemplate.header("X-Service-Name", "auth-service");
        };
    }
}