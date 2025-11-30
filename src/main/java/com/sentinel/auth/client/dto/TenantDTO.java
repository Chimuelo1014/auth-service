package com.sentinel.auth.client.dto;

import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TenantDTO {
    
    private UUID id;
    private String name;
    private UUID ownerId;
    private String plan;
    private String status;
    private LocalDateTime createdAt;
}