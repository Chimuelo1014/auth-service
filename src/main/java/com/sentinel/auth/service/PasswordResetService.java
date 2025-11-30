package com.sentinel.auth.service;

import com.sentinel.auth.dto.request.ForgotPasswordRequest;
import com.sentinel.auth.dto.request.ResetPasswordRequest;
import com.sentinel.auth.dto.response.PasswordResetResponse;

public interface PasswordResetService {
    
    /**
     * Solicita un token de recuperación de contraseña.
     * Envía email al usuario con el link de reset.
     */
    PasswordResetResponse requestPasswordReset(ForgotPasswordRequest request);
    
    /**
     * Valida el token y resetea la contraseña.
     */
    PasswordResetResponse resetPassword(ResetPasswordRequest request);
    
    /**
     * Valida si un token de reset es válido.
     */
    boolean validateResetToken(String token);
}