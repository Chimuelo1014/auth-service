package com.sentinel.auth.constants;

/**
 * Mensajes de éxito estandarizados.
 */
public final class SuccessMessages {
    
    private SuccessMessages() {
        throw new UnsupportedOperationException("Cannot instantiate constants class");
    }
    
    // Registration
    public static final String USER_REGISTERED = "User registered successfully";
    public static final String REGISTRATION_EMAIL_SENT = "Registration email sent. Please verify your email.";
    
    // Authentication
    public static final String LOGIN_SUCCESS = "Login successful";
    public static final String LOGOUT_SUCCESS = "Logout successful";
    public static final String TOKEN_REFRESHED = "Token refreshed successfully";
    
    // Password
    public static final String PASSWORD_CHANGED = "Password changed successfully";
    public static final String PASSWORD_RESET_EMAIL_SENT = "Password reset email sent. Check your inbox.";
    public static final String PASSWORD_RESET_SUCCESS = "Password reset successfully";
    
    // Two-Factor Authentication
    public static final String TWO_FACTOR_SETUP_COMPLETE = "Two-factor authentication setup complete";
    public static final String TWO_FACTOR_ENABLED = "Two-factor authentication enabled";
    public static final String TWO_FACTOR_DISABLED = "Two-factor authentication disabled";
    public static final String TWO_FACTOR_VERIFIED = "Two-factor code verified";
    
    // Profile
    public static final String PROFILE_UPDATED = "Profile updated successfully";
    public static final String EMAIL_VERIFIED = "Email verified successfully";
    
    // OAuth2
    public static final String OAUTH2_LOGIN_SUCCESS = "OAuth2 login successful";
}