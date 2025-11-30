package com.sentinel.auth.service.impl;

import com.sentinel.auth.constants.ErrorMessages;
import com.sentinel.auth.constants.SecurityConstants;
import com.sentinel.auth.constants.SuccessMessages;
import com.sentinel.auth.dto.request.ForgotPasswordRequest;
import com.sentinel.auth.dto.request.ResetPasswordRequest;
import com.sentinel.auth.dto.response.PasswordResetResponse;
import com.sentinel.auth.entity.PasswordResetTokenEntity;
import com.sentinel.auth.entity.UserEntity;
import com.sentinel.auth.enums.AuditAction;
import com.sentinel.auth.enums.TokenStatus;
import com.sentinel.auth.exception.types.TokenValidationException;
import com.sentinel.auth.exception.types.UserNotFoundException;
import com.sentinel.auth.repository.PasswordResetTokenRepository;
import com.sentinel.auth.repository.RefreshTokenRepository;
import com.sentinel.auth.repository.UserRepository;
import com.sentinel.auth.service.AuditLogService;
import com.sentinel.auth.service.EmailService;
import com.sentinel.auth.service.PasswordResetService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordResetServiceImpl implements PasswordResetService {

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final AuditLogService auditLogService;
    private final HttpServletRequest request;

    @Value("${app.url:http://localhost:3000}")
    private String appUrl;

    @Override
    @Transactional
    public PasswordResetResponse requestPasswordReset(ForgotPasswordRequest req) {
        log.info("Password reset requested for email: {}", req.getEmail());

        // Buscar usuario
        UserEntity user = userRepository.findByEmail(req.getEmail())
                .orElseThrow(() -> new UserNotFoundException(
                    String.format(ErrorMessages.USER_NOT_FOUND, req.getEmail())
                ));

        // Revocar tokens anteriores del usuario
        tokenRepository.revokeAllUserTokens(
            user.getId(),
            TokenStatus.REVOKED,
            TokenStatus.ACTIVE
        );

        // Generar nuevo token
        String token = UUID.randomUUID().toString();
        LocalDateTime expiresAt = LocalDateTime.now()
                .plusSeconds(SecurityConstants.PASSWORD_RESET_TOKEN_VALIDITY / 1000);

        PasswordResetTokenEntity resetToken = PasswordResetTokenEntity.builder()
                .token(token)
                .userId(user.getId())
                .status(TokenStatus.ACTIVE)
                .expiresAt(expiresAt)
                .build();

        tokenRepository.save(resetToken);

        // Construir URL de reset
        String resetUrl = String.format("%s/reset-password?token=%s", appUrl, token);

        // Enviar email
        try {
            emailService.sendPasswordResetEmail(user.getEmail(), resetUrl, user.getEmail());
            log.info("Password reset email sent to: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to send password reset email: {}", e.getMessage());
            // No lanzar excepción, continuar
        }

        // Audit log
        auditLogService.logAction(
            user.getId(),
            user.getTenantId(),
            AuditAction.PASSWORD_RESET_REQUESTED,
            "Password reset requested",
            getClientIP(),
            request.getHeader("User-Agent"),
            true,
            null
        );

        return PasswordResetResponse.builder()
                .success(true)
                .message(SuccessMessages.PASSWORD_RESET_EMAIL_SENT)
                .maskedEmail(maskEmail(user.getEmail()))
                .build();
    }

    @Override
    @Transactional
    public PasswordResetResponse resetPassword(ResetPasswordRequest req) {
        log.info("Password reset attempt with token");

        // Validar que las contraseñas coincidan
        if (!req.getNewPassword().equals(req.getConfirmPassword())) {
            throw new TokenValidationException(ErrorMessages.PASSWORD_MISMATCH);
        }

        // Buscar token
        PasswordResetTokenEntity resetToken = tokenRepository
                .findByTokenAndStatus(req.getToken(), TokenStatus.ACTIVE)
                .orElseThrow(() -> new TokenValidationException(ErrorMessages.TOKEN_INVALID));

        // Validar expiración
        if (!resetToken.isValid()) {
            throw new TokenValidationException(ErrorMessages.PASSWORD_RESET_INVALID);
        }

        // Buscar usuario
        UserEntity user = userRepository.findById(resetToken.getUserId())
                .orElseThrow(() -> new UserNotFoundException(ErrorMessages.USER_NOT_FOUND));

        // Validar que no sea la misma contraseña
        if (passwordEncoder.matches(req.getNewPassword(), user.getPassword())) {
            throw new TokenValidationException(ErrorMessages.PASSWORD_SAME_AS_OLD);
        }

        // Actualizar contraseña
        user.setPassword(passwordEncoder.encode(req.getNewPassword()));
        user.setLastPasswordChange(LocalDateTime.now());
        user.resetFailedAttempts(); // Reset intentos fallidos
        userRepository.save(user);

        // Marcar token como usado
        resetToken.markAsUsed();
        tokenRepository.save(resetToken);

        // Revocar todos los refresh tokens (logout de todos los dispositivos)
        refreshTokenRepository.revokeAllUserTokens(
            user.getId(),
            TokenStatus.REVOKED,
            TokenStatus.ACTIVE,
            LocalDateTime.now()
        );

        // Audit log
        auditLogService.logAction(
            user.getId(),
            user.getTenantId(),
            AuditAction.PASSWORD_RESET_COMPLETED,
            "Password reset completed",
            getClientIP(),
            request.getHeader("User-Agent"),
            true,
            null
        );

        // Enviar email de confirmación
        try {
            emailService.sendPasswordChangedEmail(user.getEmail(), user.getEmail());
        } catch (Exception e) {
            log.error("Failed to send password changed email: {}", e.getMessage());
        }

        log.info("Password reset successfully for user: {}", user.getId());

        return PasswordResetResponse.builder()
                .success(true)
                .message(SuccessMessages.PASSWORD_RESET_SUCCESS)
                .build();
    }

    @Override
    public boolean validateResetToken(String token) {
        return tokenRepository
                .findByTokenAndStatus(token, TokenStatus.ACTIVE)
                .map(PasswordResetTokenEntity::isValid)
                .orElse(false);
    }

    // Helper methods
    private String maskEmail(String email) {
        int atIndex = email.indexOf('@');
        if (atIndex <= 1) return email;
        
        String username = email.substring(0, atIndex);
        String domain = email.substring(atIndex);
        
        if (username.length() <= 2) {
            return username.charAt(0) + "***" + domain;
        }
        
        return username.charAt(0) + "***" + username.charAt(username.length() - 1) + domain;
    }

    private String getClientIP() {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
