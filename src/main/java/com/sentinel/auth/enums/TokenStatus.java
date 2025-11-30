package com.sentinel.auth.enums;

/**
 * Estados posibles de los tokens (refresh, password reset).
 */
public enum TokenStatus {
    /**
     * Token activo y válido.
     */
    ACTIVE,
    
    /**
     * Token ya utilizado.
     */
    USED,
    
    /**
     * Token revocado manualmente.
     */
    REVOKED,
    
    /**
     * Token expirado por tiempo.
     */
    EXPIRED
}
