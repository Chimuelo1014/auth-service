package com.sentinel.auth.events;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Publisher de eventos de autenticación hacia RabbitMQ.
 * 
 * Eventos publicados:
 * - auth.user.registered: Cuando un usuario se registra
 * - auth.user.login: Cuando un usuario hace login
 * - auth.password.changed: Cuando se cambia la contraseña
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuthEventPublisher {

    private final RabbitTemplate rabbitTemplate;

    @Value("${auth.events.exchange}")
    private String authExchange;

    @Value("${auth.events.user-registered-routing-key}")
    private String userRegisteredRoutingKey;

    @Value("${auth.events.user-login-routing-key}")
    private String userLoginRoutingKey;

    /**
     * Publica evento cuando un usuario se registra.
     * 
     * Este evento lo consumirá tenant-service para crear el tenant automáticamente.
     */
    @Async
    public void publishUserRegistered(UUID userId, String email, String globalRole) {
        Map<String, Object> event = new HashMap<>();
        event.put("eventType", "auth.user.registered");
        event.put("userId", userId.toString());
        event.put("email", email);
        event.put("globalRole", globalRole);
        event.put("timestamp", LocalDateTime.now().toString());

        try {
            rabbitTemplate.convertAndSend(authExchange, userRegisteredRoutingKey, event);
            log.info("Published user.registered event for user: {}", userId);
        } catch (Exception e) {
            log.error("Failed to publish user.registered event for user {}: {}", userId, e.getMessage());
        }
    }

    /**
     * Publica evento cuando un usuario hace login exitoso.
     */
    @Async
    public void publishUserLogin(UUID userId, String email, String ipAddress) {
        Map<String, Object> event = new HashMap<>();
        event.put("eventType", "auth.user.login");
        event.put("userId", userId.toString());
        event.put("email", email);
        event.put("ipAddress", ipAddress);
        event.put("timestamp", LocalDateTime.now().toString());

        try {
            rabbitTemplate.convertAndSend(authExchange, userLoginRoutingKey, event);
            log.debug("Published user.login event for user: {}", userId);
        } catch (Exception e) {
            log.error("Failed to publish user.login event for user {}: {}", userId, e.getMessage());
        }
    }
}