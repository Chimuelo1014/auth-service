package com.sentinel.auth.dto.internal;

import com.sentinel.auth.enums.AuditAction;
import lombok.*;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLogDTO {
    
    private UUID userId;
    private UUID tenantId;
    private AuditAction action;
    private String details;
    private String ipAddress;
    private String userAgent;
    private boolean success;
    private String errorMessage;
}