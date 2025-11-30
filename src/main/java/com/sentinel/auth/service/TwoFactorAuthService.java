package com.sentinel.auth.service;

import com.sentinel.auth.dto.request.Enable2FARequest;
import com.sentinel.auth.dto.request.Verify2FARequest;
import com.sentinel.auth.dto.response.TwoFactorSetupResponse;

import java.util.UUID;

public interface TwoFactorAuthService {
    
    /**
     * Genera un nuevo secret para 2FA y retorna QR code.
     */
    TwoFactorSetupResponse setup2FA(UUID userId);
    
    /**
     * Habilita 2FA después de verificar el código.
     */
    void enable2FA(UUID userId, Enable2FARequest request);
    
    /**
     * Deshabilita 2FA.
     */
    void disable2FA(UUID userId, String password);
    
    /**
     * Verifica un código 2FA.
     */
    boolean verify2FACode(UUID userId, String code);
    
    /**
     * Genera códigos de backup (recuperación).
     */
    List<String> generateBackupCodes(UUID userId);
}