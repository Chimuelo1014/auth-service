package com.sentinel.auth.enums;

/**
 * Roles globales a nivel de plataforma.
 * Define los permisos base del usuario en el sistema completo.
 */
public enum GlobalRole {
    /**
     * Super administrador de la plataforma.
     * Acceso total a todos los recursos y configuraciones.
     */
    SUPER_ADMIN,
    
    /**
     * Usuario regular de la plataforma.
     * Puede crear tenants y gestionar sus propios recursos.
     */
    USER
}