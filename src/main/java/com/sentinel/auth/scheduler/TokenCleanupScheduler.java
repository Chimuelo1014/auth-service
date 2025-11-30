package com.sentinel.auth.scheduler;

import com.sentinel.auth.enums.TokenStatus;
import com.sentinel.auth.repository.PasswordResetTokenRepository;
import com.sentinel.auth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Scheduled job para limpiar tokens expirados.
 * Se ejecuta diariamente a las 3 AM.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TokenCleanupScheduler {

    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;

    /**
     * Limpia refresh tokens expirados.
     * Cron: Cada día a las 3:00 AM
     */
    @Scheduled(cron = "0 0 3 * * *")
    @Transactional
    public void cleanupExpiredRefreshTokens() {
        log.info("Starting cleanup of expired refresh tokens");
        
        try {
            refreshTokenRepository.deleteExpiredTokens(
                LocalDateTime.now(),
                TokenStatus.EXPIRED
            );
            
            log.info("Expired refresh tokens cleanup completed");
        } catch (Exception e) {
            log.error("Error during refresh tokens cleanup: {}", e.getMessage());
        }
    }

    /**
     * Limpia password reset tokens expirados.
     * Cron: Cada día a las 3:30 AM
     */
    @Scheduled(cron = "0 30 3 * * *")
    @Transactional
    public void cleanupExpiredPasswordResetTokens() {
        log.info("Starting cleanup of expired password reset tokens");
        
        try {
            passwordResetTokenRepository.deleteExpiredTokens(LocalDateTime.now());
            
            log.info("Expired password reset tokens cleanup completed");
        } catch (Exception e) {
            log.error("Error during password reset tokens cleanup: {}", e.getMessage());
        }
    }
}