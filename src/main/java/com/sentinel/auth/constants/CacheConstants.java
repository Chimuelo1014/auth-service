package com.sentinel.auth.constants;

/**
 * Constantes para caché (para implementación futura con Redis).
 */
public final class CacheConstants {
    
    private CacheConstants() {
        throw new UnsupportedOperationException("Cannot instantiate constants class");
    }
    
    // Cache names
    public static final String USER_CACHE = "users";
    public static final String TOKEN_CACHE = "tokens";
    public static final String ROLE_CACHE = "roles";
    
    // Cache TTL (Time To Live) in seconds
    public static final long USER_CACHE_TTL = 3600L; // 1 hora
    public static final long TOKEN_BLACKLIST_TTL = 3600L; // 1 hora
    public static final long ROLE_CACHE_TTL = 7200L; // 2 horas
    
    // Cache keys
    public static final String USER_BY_EMAIL_KEY = "user:email:%s";
    public static final String USER_BY_ID_KEY = "user:id:%s";
    public static final String TOKEN_BLACKLIST_KEY = "token:blacklist:%s";
}