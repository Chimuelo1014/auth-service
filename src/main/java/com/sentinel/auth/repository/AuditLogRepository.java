package com.sentinel.auth.repository;

import com.sentinel.auth.entity.AuditLogEntity;
import com.sentinel.auth.enums.AuditAction;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLogEntity, UUID> {

    /**
     * Find all audit logs for a specific user.
     */
    Page<AuditLogEntity> findByUserIdOrderByTimestampDesc(UUID userId, Pageable pageable);

    /**
     * Find all audit logs for a specific tenant.
     */
    Page<AuditLogEntity> findByTenantIdOrderByTimestampDesc(UUID tenantId, Pageable pageable);

    /**
     * Find audit logs by action type.
     */
    Page<AuditLogEntity> findByActionOrderByTimestampDesc(AuditAction action, Pageable pageable);

    /**
     * Find failed login attempts for a user in a time range.
     */
    @Query("SELECT COUNT(a) FROM AuditLogEntity a WHERE a.userId = :userId " +
           "AND a.action = :action AND a.success = false " +
           "AND a.timestamp >= :since")
    long countFailedLoginAttempts(
        @Param("userId") UUID userId,
        @Param("action") AuditAction action,
        @Param("since") LocalDateTime since
    );

    /**
     * Find recent audit logs for a user.
     */
    @Query("SELECT a FROM AuditLogEntity a WHERE a.userId = :userId " +
           "ORDER BY a.timestamp DESC")
    List<AuditLogEntity> findRecentByUserId(@Param("userId") UUID userId, Pageable pageable);

    /**
     * Delete old audit logs (cleanup job - mantener últimos 90 días).
     */
    @Modifying
    @Query("DELETE FROM AuditLogEntity a WHERE a.timestamp < :cutoffDate")
    void deleteOldLogs(@Param("cutoffDate") LocalDateTime cutoffDate);
}
