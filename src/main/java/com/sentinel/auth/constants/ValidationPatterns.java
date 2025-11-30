package com.sentinel.auth.constants;

/**
 * Patrones de validación regex.
 */
public final class ValidationPatterns {
    
    private ValidationPatterns() {
        throw new UnsupportedOperationException("Cannot instantiate constants class");
    }
    
    // Email pattern (RFC 5322 simplificado)
    public static final String EMAIL_PATTERN = 
        "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";
    
    // Password pattern (mínimo 8 chars, 1 mayúscula, 1 minúscula, 1 número, 1 especial)
    public static final String PASSWORD_PATTERN = 
        "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{8,}$";
    
    // UUID pattern
    public static final String UUID_PATTERN = 
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";
    
    // Role patterns
    public static final String GLOBAL_ROLE_PATTERN = "^(SUPER_ADMIN|USER)$";
    public static final String TENANT_ROLE_PATTERN = "^(TENANT_ADMIN|TENANT_USER)$";
    public static final String PROJECT_ROLE_PATTERN = "^(PROJECT_ADMIN|PROJECT_MEMBER)$";
}
