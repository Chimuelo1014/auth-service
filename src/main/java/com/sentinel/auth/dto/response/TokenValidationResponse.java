package com.sentinel.auth.dto.response;

import lombok.*;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenValidationResponse {
    
    private boolean valid;
    private UUID userId;
    private String email;
    private UUID tenantId;
    private String globalRole;
    private Long expiresIn; // seconds until expiration
}