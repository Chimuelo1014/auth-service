package com.sentinel.auth.enums;

/**
 * Estados del usuario en el sistema.
 */
public enum UserStatus {
    /**
     * Usuario activo y con acceso completo.
     */
    ACTIVE,
    
    /**
     * Usuario pendiente de verificación de email.
     */
    PENDING_VERIFICATION,
    
    /**
     * Usuario bloqueado temporalmente (ej: intentos fallidos).
     */
    LOCKED,
    
    /**
     * Usuario suspendido por administrador.
     */
    SUSPENDED,
    
    /**
     * Usuario eliminado (soft delete).
     */
    DELETED
}