package com.sentinel.auth.config;

import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuración de RabbitMQ para Auth-Service.
 * 
 * Exchanges y Queues:
 * - auth-exchange (topic): Para eventos de autenticación
 * - Routing keys:
 *   - auth.user.registered
 *   - auth.user.login
 *   - auth.password.changed
 */
@Configuration
public class RabbitMQConfig {

    @Value("${auth.events.exchange}")
    private String authExchange;

    // ========================================
    // EXCHANGES
    // ========================================
    
    @Bean
    public TopicExchange authExchange() {
        return new TopicExchange(authExchange);
    }

    // ========================================
    // QUEUES (Para que otros servicios consuman)
    // ========================================
    
    /**
     * Queue para tenant-service (crear tenant al registrarse)
     */
    @Bean
    public Queue userRegisteredQueue() {
        return QueueBuilder
                .durable("auth.user.registered.queue")
                .build();
    }

    /**
     * Binding: auth-exchange -> userRegisteredQueue
     */
    @Bean
    public Binding userRegisteredBinding(Queue userRegisteredQueue, TopicExchange authExchange) {
        return BindingBuilder
                .bind(userRegisteredQueue)
                .to(authExchange)
                .with("auth.user.registered");
    }

    // ========================================
    // MESSAGE CONVERTER (JSON)
    // ========================================
    
    @Bean
    public MessageConverter jsonMessageConverter() {
        return new Jackson2JsonMessageConverter();
    }

    @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        RabbitTemplate template = new RabbitTemplate(connectionFactory);
        template.setMessageConverter(jsonMessageConverter());
        return template;
    }
}