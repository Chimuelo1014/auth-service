package com.sentinel.auth.enums;

/**
 * Roles a nivel de proyecto.
 * Define los permisos del usuario dentro de un proyecto específico.
 * 
 * NOTA: PROJECT_VIEWER comentado para implementación futura.
 * Estos roles se gestionarán en TENANT-SERVICE.
 */
public enum ProjectRole {
    /**
     * Administrador del proyecto.
     * Control total sobre el proyecto y sus scans.
     */
    PROJECT_ADMIN,
    
    /**
     * Miembro del proyecto.
     * Puede crear y visualizar scans del proyecto.
     */
    PROJECT_MEMBER
    
    // PROJECT_VIEWER - Solo lectura (implementar en futuro)
}