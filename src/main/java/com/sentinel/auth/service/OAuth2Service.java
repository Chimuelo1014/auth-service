package com.sentinel.auth.service;

import com.sentinel.auth.dto.response.AuthResponse;
import com.sentinel.auth.dto.response.OAuth2UserInfo;

public interface OAuth2Service {
    
    /**
     * Procesa el login con OAuth2 (Google o Microsoft).
     * Crea usuario si no existe.
     */
    AuthResponse processOAuth2Login(OAuth2UserInfo userInfo, String provider);
    
    /**
     * Genera la URL de autorización para el provider.
     */
    String getAuthorizationUrl(String provider);
}