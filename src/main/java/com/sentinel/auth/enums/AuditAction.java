package com.sentinel.auth.enums;

/**
 * Acciones auditables del sistema.
 * Cada acción importante del usuario se registra para compliance.
 */
public enum AuditAction {
    // Autenticación
    USER_REGISTERED,
    USER_LOGIN,
    USER_LOGOUT,
    USER_LOGIN_FAILED,
    
    // OAuth2
    OAUTH2_LOGIN_SUCCESS,
    OAUTH2_LOGIN_FAILED,
    
    // Seguridad
    PASSWORD_CHANGED,
    PASSWORD_RESET_REQUESTED,
    PASSWORD_RESET_COMPLETED,
    TWO_FACTOR_ENABLED,
    TWO_FACTOR_DISABLED,
    TWO_FACTOR_VERIFIED,
    
    // Tokens
    TOKEN_REFRESHED,
    TOKEN_REVOKED,
    ALL_TOKENS_REVOKED,
    
    // Perfil
    PROFILE_UPDATED,
    EMAIL_CHANGED,
    
    // Tenant (future)
    TENANT_CREATED,
    TENANT_JOINED,
    TENANT_LEFT
}
