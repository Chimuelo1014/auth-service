package com.sentinel.auth.dto.response;

import com.sentinel.auth.enums.AuthProvider;
import com.sentinel.auth.enums.GlobalRole;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserProfileResponse {
    
    private UUID id;
    private String email;
    private GlobalRole globalRole;
    private UUID tenantId;
    private AuthProvider authProvider;
    private boolean twoFactorEnabled;
    private boolean emailVerified;
    private LocalDateTime lastLogin;
    private LocalDateTime createdAt;
}