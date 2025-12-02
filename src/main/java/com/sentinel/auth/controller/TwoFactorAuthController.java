package com.sentinel.auth.controller;

import com.sentinel.auth.constants.APIConstants;
import com.sentinel.auth.dto.request.Enable2FARequest;
import com.sentinel.auth.dto.request.Verify2FARequest;
import com.sentinel.auth.dto.response.TwoFactorSetupResponse;
import com.sentinel.auth.entity.UserEntity;
import com.sentinel.auth.repository.UserRepository;
import com.sentinel.auth.service.TwoFactorAuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

/**
 * Controller para gestión de Two-Factor Authentication.
 * 
 * NOTA: extractUserId() ahora busca el usuario por email desde el Authentication
 */
@RestController
@RequestMapping(APIConstants.TWO_FACTOR_BASE_PATH)
@RequiredArgsConstructor
public class TwoFactorAuthController {

    private final TwoFactorAuthService twoFactorAuthService;
    private final UserRepository userRepository;

    /**
     * Inicia el setup de 2FA (genera QR code).
     * POST /api/auth/2fa/setup
     */
    @PostMapping(APIConstants.TWO_FACTOR_SETUP)
    public ResponseEntity<TwoFactorSetupResponse> setup2FA(Authentication authentication) {
        UUID userId = extractUserId(authentication);
        return ResponseEntity.ok(twoFactorAuthService.setup2FA(userId));
    }

    /**
     * Habilita 2FA después de verificar el código.
     * POST /api/auth/2fa/enable
     */
    @PostMapping(APIConstants.TWO_FACTOR_ENABLE)
    public ResponseEntity<Map<String, String>> enable2FA(
            Authentication authentication,
            @Valid @RequestBody Enable2FARequest request
    ) {
        UUID userId = extractUserId(authentication);
        twoFactorAuthService.enable2FA(userId, request);
        return ResponseEntity.ok(Map.of("message", "Two-factor authentication enabled successfully"));
    }

    /**
     * Deshabilita 2FA.
     * POST /api/auth/2fa/disable
     */
    @PostMapping(APIConstants.TWO_FACTOR_DISABLE)
    public ResponseEntity<Map<String, String>> disable2FA(
            Authentication authentication,
            @RequestBody Map<String, String> payload
    ) {
        UUID userId = extractUserId(authentication);
        String password = payload.get("password");
        twoFactorAuthService.disable2FA(userId, password);
        return ResponseEntity.ok(Map.of("message", "Two-factor authentication disabled successfully"));
    }

    /**
     * Verifica un código 2FA.
     * POST /api/auth/2fa/verify
     */
    @PostMapping(APIConstants.TWO_FACTOR_VERIFY)
    public ResponseEntity<Map<String, Boolean>> verify2FA(
            Authentication authentication,
            @Valid @RequestBody Verify2FARequest request
    ) {
        UUID userId = extractUserId(authentication);
        boolean valid = twoFactorAuthService.verify2FACode(userId, request.getCode());
        return ResponseEntity.ok(Map.of("valid", valid));
    }

    /**
     * Extrae userId desde el Authentication (UserDetails).
     * 
     * El Authentication.getPrincipal() devuelve UserEntity (que implementa UserDetails).
     */
    private UUID extractUserId(Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            throw new RuntimeException("No authenticated user found");
        }
        
        Object principal = authentication.getPrincipal();
        
        // Si el principal es UserEntity (nuestro caso)
        if (principal instanceof UserEntity userEntity) {
            return userEntity.getId();
        }
        
        // Si es un String (username/email)
        if (principal instanceof String email) {
            return userRepository.findByEmail(email)
                    .map(UserEntity::getId)
                    .orElseThrow(() -> new RuntimeException("User not found: " + email));
        }
        
        throw new RuntimeException("Unexpected principal type: " + principal.getClass().getName());
    }
}