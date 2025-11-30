package com.sentinel.auth.client.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TenantCreationRequest {
    
    @NotBlank(message = "Tenant name is required")
    private String name;
    
    @NotNull(message = "Owner ID is required")
    private UUID ownerId;
    
    /**
     * Plan by default: FREE
     */
    @Builder.Default
    private String plan = "FREE";
    
    /**
     * User's email (for reference).
     */
    private String ownerEmail;
    
    /**
     * Auto-generated workspace name if not provided.
     */
    private boolean autoGenerateName = true;
}