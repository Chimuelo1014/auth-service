package com.sentinel.auth.constants;

/**
 * Constantes de seguridad del sistema.
 */
public final class SecurityConstants {
    
    private SecurityConstants() {
        throw new UnsupportedOperationException("Cannot instantiate constants class");
    }
    
    // JWT Configuration
    public static final String JWT_SECRET_PROPERTY = "jwt.secret";
    public static final String JWT_EXPIRATION_PROPERTY = "jwt.expiration";
    public static final String JWT_REFRESH_EXPIRATION_PROPERTY = "jwt.refresh.expiration";
    
    // Token Validity (in milliseconds)
    public static final long ACCESS_TOKEN_VALIDITY = 3600000L; // 1 hora
    public static final long REFRESH_TOKEN_VALIDITY = 2592000000L; // 30 días
    public static final long PASSWORD_RESET_TOKEN_VALIDITY = 3600000L; // 1 hora
    public static final long EMAIL_VERIFICATION_TOKEN_VALIDITY = 86400000L; // 24 horas
    
    // JWT Claims
    public static final String CLAIM_USER_ID = "userId";
    public static final String CLAIM_EMAIL = "email";
    public static final String CLAIM_TENANT_ID = "tenantId";
    public static final String CLAIM_GLOBAL_ROLE = "globalRole";
    public static final String CLAIM_AUTH_PROVIDER = "authProvider";
    public static final String CLAIM_TWO_FACTOR_ENABLED = "twoFactorEnabled";
    
    // Headers
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String HEADER_BEARER_PREFIX = "Bearer ";
    
    // Password Policy
    public static final int PASSWORD_MIN_LENGTH = 8;
    public static final int PASSWORD_MAX_LENGTH = 100;
    public static final String PASSWORD_PATTERN = 
        "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!]).*$";
    
    // Rate Limiting
    public static final int MAX_LOGIN_ATTEMPTS = 5;
    public static final long ACCOUNT_LOCK_DURATION_MS = 900000L; // 15 minutos
    
    // Two-Factor Authentication
    public static final String TOTP_ISSUER = "Sentinel Security Scanner";
    public static final int TOTP_CODE_LENGTH = 6;
    public static final int TOTP_TIME_STEP = 30; // segundos
    
    // OAuth2
    public static final String OAUTH2_REDIRECT_URI = "/oauth2/callback";
    public static final String OAUTH2_STATE_COOKIE = "oauth2_state";
    public static final int OAUTH2_STATE_COOKIE_DURATION = 180; // 3 minutos
}