package com.sentinel.auth.scheduler;

import com.sentinel.auth.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Scheduled job para limpiar audit logs antiguos.
 * Se ejecuta semanalmente los domingos a las 4 AM.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuditLogCleanupScheduler {

    private final AuditLogRepository auditLogRepository;

    @Value("${audit.retention.days:90}")
    private int retentionDays;

    /**
     * Limpia audit logs más antiguos que el período de retención.
     * Cron: Cada domingo a las 4:00 AM
     */
    @Scheduled(cron = "0 0 4 * * SUN")
    @Transactional
    public void cleanupOldAuditLogs() {
        log.info("Starting cleanup of old audit logs (retention: {} days)", retentionDays);
        
        try {
            LocalDateTime cutoffDate = LocalDateTime.now().minusDays(retentionDays);
            auditLogRepository.deleteOldLogs(cutoffDate);
            
            log.info("Old audit logs cleanup completed");
        } catch (Exception e) {
            log.error("Error during audit logs cleanup: {}", e.getMessage());
        }
    }
}
