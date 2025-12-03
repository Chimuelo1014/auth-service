package com.sentinel.auth.controller;

import com.sentinel.auth.constants.APIConstants;
import com.sentinel.auth.dto.response.AuthResponse;
import com.sentinel.auth.dto.response.OAuth2UserInfo;
import com.sentinel.auth.service.OAuth2Service;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import java.util.Map;

/**
 * Controller para OAuth2 authentication (Google y Microsoft).
 * Solo se activa si app.oauth2.enabled=true
 */
@Slf4j
@RestController
@RequestMapping(APIConstants.OAUTH2_BASE_PATH)
@RequiredArgsConstructor
@ConditionalOnProperty(name = "app.oauth2.enabled", havingValue = "true")
public class OAuth2Controller {

    private final OAuth2Service oauth2Service;
    private final OAuth2AuthorizedClientService authorizedClientService;

    /**
     * Inicia el flujo OAuth2 con Google.
     * GET /api/auth/oauth2/google
     */
    @GetMapping(APIConstants.OAUTH2_GOOGLE)
    public RedirectView loginWithGoogle() {
        String authUrl = oauth2Service.getAuthorizationUrl("google");
        return new RedirectView(authUrl);
    }

    /**
     * Inicia el flujo OAuth2 con Microsoft.
     * GET /api/auth/oauth2/microsoft
     */
    @GetMapping(APIConstants.OAUTH2_MICROSOFT)
    public RedirectView loginWithMicrosoft() {
        String authUrl = oauth2Service.getAuthorizationUrl("microsoft");
        return new RedirectView(authUrl);
    }

    /**
     * Callback para Google OAuth2.
     * GET /api/auth/oauth2/callback/google
     */
    @GetMapping("/callback/google")
    public ResponseEntity<AuthResponse> googleCallback(OAuth2AuthenticationToken authentication) {
        log.info("Google OAuth2 callback received");
        
        OAuth2User oauth2User = authentication.getPrincipal();
        OAuth2UserInfo userInfo = extractGoogleUserInfo(oauth2User);
        
        AuthResponse response = oauth2Service.processOAuth2Login(userInfo, "google");
        
        return ResponseEntity.ok(response);
    }

    /**
     * Callback para Microsoft OAuth2.
     * GET /api/auth/oauth2/callback/microsoft
     */
    @GetMapping("/callback/microsoft")
    public ResponseEntity<AuthResponse> microsoftCallback(OAuth2AuthenticationToken authentication) {
        log.info("Microsoft OAuth2 callback received");
        
        OAuth2User oauth2User = authentication.getPrincipal();
        OAuth2UserInfo userInfo = extractMicrosoftUserInfo(oauth2User);
        
        AuthResponse response = oauth2Service.processOAuth2Login(userInfo, "microsoft");
        
        return ResponseEntity.ok(response);
    }

    // Helper methods para extraer user info de cada provider
    private OAuth2UserInfo extractGoogleUserInfo(OAuth2User oauth2User) {
        Map<String, Object> attributes = oauth2User.getAttributes();
        
        return OAuth2UserInfo.builder()
                .providerId(attributes.get("sub").toString())
                .email(attributes.get("email").toString())
                .name(attributes.get("name") != null ? attributes.get("name").toString() : null)
                .firstName(attributes.get("given_name") != null ? attributes.get("given_name").toString() : null)
                .lastName(attributes.get("family_name") != null ? attributes.get("family_name").toString() : null)
                .profilePictureUrl(attributes.get("picture") != null ? attributes.get("picture").toString() : null)
                .emailVerified(attributes.get("email_verified") != null 
                    ? Boolean.parseBoolean(attributes.get("email_verified").toString()) 
                    : false)
                .build();
    }

    private OAuth2UserInfo extractMicrosoftUserInfo(OAuth2User oauth2User) {
        Map<String, Object> attributes = oauth2User.getAttributes();
        
        return OAuth2UserInfo.builder()
                .providerId(attributes.get("id").toString())
                .email(attributes.get("mail") != null 
                    ? attributes.get("mail").toString() 
                    : attributes.get("userPrincipalName").toString())
                .name(attributes.get("displayName") != null ? attributes.get("displayName").toString() : null)
                .firstName(attributes.get("givenName") != null ? attributes.get("givenName").toString() : null)
                .lastName(attributes.get("surname") != null ? attributes.get("surname").toString() : null)
                .emailVerified(true) // Microsoft emails are pre-verified
                .build();
    }
}