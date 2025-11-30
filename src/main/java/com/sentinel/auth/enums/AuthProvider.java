package com.sentinel.auth.enums;

/**
 * Proveedores de autenticación soportados.
 */
public enum AuthProvider {
    /**
     * Autenticación local con email y contraseña.
     */
    LOCAL,
    
    /**
     * Autenticación vía OAuth2 con Google.
     */
    GOOGLE,
    
    /**
     * Autenticación vía OAuth2 con Microsoft.
     */
    MICROSOFT
}