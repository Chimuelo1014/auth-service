package com.sentinel.auth.service.impl;

import com.sentinel.auth.constants.ErrorMessages;
import com.sentinel.auth.constants.SecurityConstants;
import com.sentinel.auth.dto.request.Enable2FARequest;
import com.sentinel.auth.dto.response.TwoFactorSetupResponse;
import com.sentinel.auth.entity.UserEntity;
import com.sentinel.auth.enums.AuditAction;
import com.sentinel.auth.exception.types.TwoFactorAuthException;
import com.sentinel.auth.exception.types.UserNotFoundException;
import com.sentinel.auth.repository.UserRepository;
import com.sentinel.auth.service.AuditLogService;
import com.sentinel.auth.service.TwoFactorAuthService;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class TwoFactorAuthServiceImpl implements TwoFactorAuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditLogService auditLogService;
    private final HttpServletRequest request;
    private final GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator();

    @Override
    @Transactional
    public TwoFactorSetupResponse setup2FA(UUID userId) {
        log.info("Setting up 2FA for user: {}", userId);

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(ErrorMessages.USER_NOT_FOUND));

        if (user.isTwoFactorEnabled()) {
            throw new TwoFactorAuthException(ErrorMessages.TWO_FACTOR_ALREADY_ENABLED);
        }

        // Generar nuevo secret
        GoogleAuthenticatorKey key = googleAuthenticator.createCredentials();
        String secret = key.getKey();

        // Guardar secret temporalmente (hasta que se verifique)
        user.setTwoFactorSecret(secret);
        userRepository.save(user);

        // Generar QR code URL
        String qrCodeUrl = GoogleAuthenticatorQRGenerator.getOtpAuthURL(
                SecurityConstants.TOTP_ISSUER,
                user.getEmail(),
                key
        );

        // Generar códigos de backup
        List<String> backupCodes = generateBackupCodes(userId);

        // Formatear secret para entrada manual
        String manualEntryKey = formatSecretForManualEntry(secret);

        log.info("2FA setup generated for user: {}", userId);

        return TwoFactorSetupResponse.builder()
                .secret(secret)
                .qrCodeUrl(qrCodeUrl)
                .manualEntryKey(manualEntryKey)
                .backupCodes(backupCodes)
                .instructions("Scan the QR code with Google Authenticator or enter the key manually")
                .build();
    }

    @Override
    @Transactional
    public void enable2FA(UUID userId, Enable2FARequest enableRequest) {
        log.info("Enabling 2FA for user: {}", userId);

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(ErrorMessages.USER_NOT_FOUND));

        if (user.isTwoFactorEnabled()) {
            throw new TwoFactorAuthException(ErrorMessages.TWO_FACTOR_ALREADY_ENABLED);
        }

        // Verificar que el secret coincida
        if (!enableRequest.getSecret().equals(user.getTwoFactorSecret())) {
            throw new TwoFactorAuthException("Invalid secret");
        }

        // Verificar el código
        if (!verify2FACode(userId, enableRequest.getCode())) {
            throw new TwoFactorAuthException(ErrorMessages.TWO_FACTOR_CODE_INVALID);
        }

        // Habilitar 2FA
        user.setTwoFactorEnabled(true);
        userRepository.save(user);

        // Audit log
        auditLogService.logAction(
            userId,
            user.getTenantId(),
            AuditAction.TWO_FACTOR_ENABLED,
            "Two-factor authentication enabled",
            getClientIP(),
            request.getHeader("User-Agent"), // ← request.getHeader NO enableRequest.getHeader
            true,
            null
        );

        log.info("2FA enabled successfully for user: {}", userId);
    }

    @Override
    @Transactional
    public void disable2FA(UUID userId, String password) {
        log.info("Disabling 2FA for user: {}", userId);

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(ErrorMessages.USER_NOT_FOUND));

        if (!user.isTwoFactorEnabled()) {
            throw new TwoFactorAuthException(ErrorMessages.TWO_FACTOR_NOT_ENABLED);
        }

        // Verificar contraseña actual
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new TwoFactorAuthException("Invalid password");
        }

        // Deshabilitar 2FA
        user.setTwoFactorEnabled(false);
        user.setTwoFactorSecret(null);
        userRepository.save(user);

        // Audit log
        auditLogService.logAction(
            userId,
            user.getTenantId(),
            AuditAction.TWO_FACTOR_DISABLED,
            "Two-factor authentication disabled",
            getClientIP(),
            request.getHeader("User-Agent"),
            true,
            null
        );

        log.info("2FA disabled successfully for user: {}", userId);
    }

    @Override
    public boolean verify2FACode(UUID userId, String code) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(ErrorMessages.USER_NOT_FOUND));

        if (user.getTwoFactorSecret() == null) {
            throw new TwoFactorAuthException("2FA not configured");
        }

        try {
            int codeInt = Integer.parseInt(code);
            boolean valid = googleAuthenticator.authorize(user.getTwoFactorSecret(), codeInt);
            
            if (valid) {
                auditLogService.logAction(
                    userId,
                    user.getTenantId(),
                    AuditAction.TWO_FACTOR_VERIFIED,
                    "2FA code verified successfully",
                    getClientIP(),
                    request.getHeader("User-Agent"),
                    true,
                    null
                );
            } else {
                auditLogService.logAction(
                    userId,
                    user.getTenantId(),
                    AuditAction.TWO_FACTOR_VERIFIED,
                    "2FA code verification failed",
                    getClientIP(),
                    request.getHeader("User-Agent"),
                    false,
                    "Invalid code"
                );
            }
            
            return valid;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    @Override
    public List<String> generateBackupCodes(UUID userId) {
        // Generar 10 códigos de backup únicos
        List<String> codes = new ArrayList<>();
        SecureRandom random = new SecureRandom();
        
        for (int i = 0; i < 10; i++) {
            String code = String.format("%08d", random.nextInt(100000000));
            codes.add(code);
        }
        
        // TODO: Guardar hashes de estos códigos en BD para validación futura
        // Por ahora solo los generamos
        
        return codes;
    }

    // Helper methods
    private String formatSecretForManualEntry(String secret) {
        // Formato: XXXX XXXX XXXX XXXX
        StringBuilder formatted = new StringBuilder();
        for (int i = 0; i < secret.length(); i++) {
            if (i > 0 && i % 4 == 0) {
                formatted.append(" ");
            }
            formatted.append(secret.charAt(i));
        }
        return formatted.toString();
    }

    private String getClientIP() {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}