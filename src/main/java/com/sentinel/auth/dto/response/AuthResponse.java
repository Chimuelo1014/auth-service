package com.sentinel.auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response returned after successful authentication (login/register/refresh).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

    /**
     * JWT access token (short lived).
     */
    private String token;

    /**
     * Refresh token (longer lived). May be the same token passed in refresh flow.
     */
    private String refreshToken;

    /**
     * Token type, typically "Bearer".
     */
    private String tokenType = "Bearer";
}
