package com.sentinel.auth.dto.internal;

import lombok.*;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JWTClaims {
    
    private UUID userId;
    private String email;
    private UUID tenantId;
    private String globalRole;
    private String authProvider;
    private boolean twoFactorEnabled;
}