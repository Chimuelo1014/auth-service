package com.sentinel.auth.constants;

/**
 * Constantes de rutas API.
 */
public final class APIConstants {
    
    private APIConstants() {
        throw new UnsupportedOperationException("Cannot instantiate constants class");
    }
    
    // Base paths
    public static final String API_BASE_PATH = "/api";
    public static final String AUTH_BASE_PATH = API_BASE_PATH + "/auth";
    
    // Auth endpoints
    public static final String AUTH_REGISTER = "/register";
    public static final String AUTH_LOGIN = "/login";
    public static final String AUTH_REFRESH = "/refresh";
    public static final String AUTH_LOGOUT = "/logout";
    
    // OAuth2 endpoints
    public static final String OAUTH2_BASE_PATH = AUTH_BASE_PATH + "/oauth2";
    public static final String OAUTH2_GOOGLE = "/google";
    public static final String OAUTH2_MICROSOFT = "/microsoft";
    public static final String OAUTH2_CALLBACK = "/callback/{provider}";
    
    // Password reset endpoints
    public static final String PASSWORD_BASE_PATH = AUTH_BASE_PATH + "/password";
    public static final String PASSWORD_FORGOT = "/forgot";
    public static final String PASSWORD_RESET = "/reset";
    public static final String PASSWORD_CHANGE = "/change";
    
    // Two-Factor Authentication endpoints
    public static final String TWO_FACTOR_BASE_PATH = AUTH_BASE_PATH + "/2fa";
    public static final String TWO_FACTOR_SETUP = "/setup";
    public static final String TWO_FACTOR_ENABLE = "/enable";
    public static final String TWO_FACTOR_DISABLE = "/disable";
    public static final String TWO_FACTOR_VERIFY = "/verify";
    
    // User endpoints
    public static final String USER_BASE_PATH = API_BASE_PATH + "/users";
    public static final String USER_PROFILE = "/profile";
    public static final String USER_UPDATE = "/update";
}
