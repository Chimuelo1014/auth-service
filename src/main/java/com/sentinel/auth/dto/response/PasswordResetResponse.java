package com.sentinel.auth.dto.response;

import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PasswordResetResponse {
    
    private boolean success;
    
    private String message;
    
    /**
     * Email masked for security (e.g., "j***@example.com").
     */
    private String maskedEmail;
}