package com.sentinel.auth.enums;

/**
 * Tipos de tokens en el sistema.
 */
public enum TokenType {
    /**
     * Access token JWT (corta duración - 1 hora).
     */
    ACCESS,
    
    /**
     * Refresh token (larga duración - 30 días).
     */
    REFRESH,
    
    /**
     * Token de recuperación de contraseña (1 hora).
     */
    PASSWORD_RESET,
    
    /**
     * Token de verificación de email (24 horas).
     */
    EMAIL_VERIFICATION
}
