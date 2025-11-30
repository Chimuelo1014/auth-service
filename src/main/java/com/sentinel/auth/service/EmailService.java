package com.sentinel.auth.service;

public interface EmailService {
    
    /**
     * Envía email de recuperación de contraseña.
     */
    void sendPasswordResetEmail(String to, String resetUrl, String userName);
    
    /**
     * Envía email de confirmación de cambio de contraseña.
     */
    void sendPasswordChangedEmail(String to, String userName);
    
    /**
     * Envía email de bienvenida.
     */
    void sendWelcomeEmail(String to, String userName);
    
    /**
     * Envía email de verificación (futuro).
     */
    void sendVerificationEmail(String to, String verificationUrl, String userName);
}