package com.sentinel.auth.enums;

/**
 * Roles a nivel de tenant (organización/workspace).
 * Define los permisos del usuario dentro de un tenant específico.
 * 
 * NOTA: TENANT_VIEWER comentado para implementación futura.
 */
public enum TenantRole {
    /**
     * Administrador del tenant.
     * Puede gestionar miembros, proyectos, y configuraciones del tenant.
     */
    TENANT_ADMIN,
    
    /**
     * Usuario regular del tenant.
     * Puede crear y gestionar proyectos asignados.
     */
    TENANT_USER
    
    // TENANT_VIEWER - Solo lectura (implementar en futuro)
}
