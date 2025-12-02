package com.sentinel.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * Configuración OAuth2 - Spring Boot Auto-Configuration
 * 
 * Por ahora usamos la configuración automática de Spring Security OAuth2.
 * Los ClientRegistrations se cargan desde application.properties.
 * 
 * Más adelante implementaremos handlers custom para:
 * - Redirigir al frontend con tokens
 * - Crear tenant automáticamente
 * - Vincular cuentas OAuth2 con cuentas locales
 */
@Configuration
public class OAuth2Config {

    @Value("${spring.security.oauth2.client.registration.google.client-id:}")
    private String googleClientId;

    @Value("${spring.security.oauth2.client.registration.microsoft.client-id:}")
    private String microsoftClientId;

    // Por ahora, Spring Boot auto-configura todo desde application.properties
    // No necesitamos beans custom todavía
    
    // TODO: Implementar custom OAuth2AuthenticationSuccessHandler
    // TODO: Implementar custom OAuth2AuthenticationFailureHandler
}