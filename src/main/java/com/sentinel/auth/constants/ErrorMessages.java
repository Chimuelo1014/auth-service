package com.sentinel.auth.constants;

/**
 * Mensajes de error estandarizados.
 */
public final class ErrorMessages {
    
    private ErrorMessages() {
        throw new UnsupportedOperationException("Cannot instantiate constants class");
    }
    
    // User errors
    public static final String USER_NOT_FOUND = "User not found with email: %s";
    public static final String USER_ALREADY_EXISTS = "User already exists with email: %s";
    public static final String USER_LOCKED = "Account is locked. Please try again later.";
    public static final String USER_SUSPENDED = "Account has been suspended. Contact support.";
    public static final String USER_DELETED = "Account has been deleted.";
    
    // Authentication errors
    public static final String INVALID_CREDENTIALS = "Invalid email or password";
    public static final String AUTHENTICATION_FAILED = "Authentication failed";
    public static final String UNAUTHORIZED_ACCESS = "Unauthorized access";
    public static final String SESSION_EXPIRED = "Session has expired";
    
    // Token errors
    public static final String TOKEN_INVALID = "Invalid token";
    public static final String TOKEN_EXPIRED = "Token has expired";
    public static final String TOKEN_REVOKED = "Token has been revoked";
    public static final String TOKEN_USED = "Token has already been used";
    public static final String TOKEN_GENERATION_FAILED = "Failed to generate token";
    
    // Password errors
    public static final String PASSWORD_WEAK = "Password does not meet security requirements";
    public static final String PASSWORD_MISMATCH = "Passwords do not match";
    public static final String PASSWORD_RESET_INVALID = "Invalid or expired password reset token";
    public static final String PASSWORD_SAME_AS_OLD = "New password must be different from old password";
    
    // Two-Factor Authentication errors
    public static final String TWO_FACTOR_NOT_ENABLED = "Two-factor authentication is not enabled";
    public static final String TWO_FACTOR_ALREADY_ENABLED = "Two-factor authentication is already enabled";
    public static final String TWO_FACTOR_CODE_INVALID = "Invalid two-factor authentication code";
    public static final String TWO_FACTOR_CODE_EXPIRED = "Two-factor authentication code has expired";
    public static final String TWO_FACTOR_SETUP_FAILED = "Failed to setup two-factor authentication";
    
    // OAuth2 errors
    public static final String OAUTH2_PROVIDER_ERROR = "OAuth2 provider error: %s";
    public static final String OAUTH2_TOKEN_EXCHANGE_FAILED = "Failed to exchange OAuth2 code for token";
    public static final String OAUTH2_USER_INFO_FAILED = "Failed to retrieve user information from OAuth2 provider";
    public static final String OAUTH2_STATE_MISMATCH = "OAuth2 state parameter mismatch";
    
    // Validation errors
    public static final String VALIDATION_FAILED = "Validation failed";
    public static final String INVALID_EMAIL = "Invalid email format";
    public static final String INVALID_ROLE = "Invalid role: %s";
    public static final String REQUIRED_FIELD = "Field '%s' is required";
    
    // Tenant errors (para integración futura)
    public static final String TENANT_CREATION_FAILED = "Failed to create tenant";
    public static final String TENANT_NOT_FOUND = "Tenant not found";
    public static final String TENANT_ACCESS_DENIED = "Access denied to tenant";
    
    // Generic errors
    public static final String INTERNAL_SERVER_ERROR = "An unexpected error occurred";
    public static final String SERVICE_UNAVAILABLE = "Service temporarily unavailable";
    public static final String BAD_REQUEST = "Bad request";
}
