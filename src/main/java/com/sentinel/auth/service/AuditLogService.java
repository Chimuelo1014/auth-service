package com.sentinel.auth.service;

import com.sentinel.auth.enums.AuditAction;
import java.util.UUID;

public interface AuditLogService {
    
    void logAction(
        UUID userId,
        UUID tenantId,
        AuditAction action,
        String details,
        String ipAddress,
        String userAgent,
        boolean success,
        String errorMessage
    );
}