package com.sentinel.auth.dto.response;

import java.util.List;

import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TwoFactorSetupResponse {
    
    /**
     * Secret key for the authenticator app.
     */
    private String secret;
    
    /**
     * QR code data URL (otpauth://).
     */
    private String qrCodeUrl;
    
    /**
     * Manual entry key (formatted for easy typing).
     */
    private String manualEntryKey;
    
    /**
     * Backup codes (optional - for account recovery).
     */
    private List<String> backupCodes;
    
    /**
     * Instructions for the user.
     */
    private String instructions;
}