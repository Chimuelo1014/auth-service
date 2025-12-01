package com.sentinel.auth.repository;

import com.sentinel.auth.entity.AuditLogEntity;
import com.sentinel.auth.enums.AuditAction;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLogEntity, UUID> {

    Page<AuditLogEntity> findByUserIdOrderByTimestampDesc(UUID userId, Pageable pageable);

    Page<AuditLogEntity> findByTenantIdOrderByTimestampDesc(UUID tenantId, Pageable pageable);

    Page<AuditLogEntity> findByActionOrderByTimestampDesc(AuditAction action, Pageable pageable);

    @Query("SELECT COUNT(a) FROM AuditLogEntity a WHERE a.userId = :userId " +
           "AND a.action = :action AND a.success = false " +
           "AND a.timestamp >= :since")
    long countFailedLoginAttempts(
        @Param("userId") UUID userId,
        @Param("action") AuditAction action,
        @Param("since") LocalDateTime since
    );

    @Query("SELECT a FROM AuditLogEntity a WHERE a.userId = :userId " +
           "ORDER BY a.timestamp DESC")
    List<AuditLogEntity> findRecentByUserId(@Param("userId") UUID userId, Pageable pageable);

    @Modifying
    @Query("DELETE FROM AuditLogEntity a WHERE a.timestamp < :cutoffDate")
    void deleteOldLogs(@Param("cutoffDate") LocalDateTime cutoffDate);
}