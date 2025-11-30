package com.sentinel.auth.controller;

import com.sentinel.auth.constants.APIConstants;
import com.sentinel.auth.dto.request.ForgotPasswordRequest;
import com.sentinel.auth.dto.request.ResetPasswordRequest;
import com.sentinel.auth.dto.response.PasswordResetResponse;
import com.sentinel.auth.service.PasswordResetService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Controller para gestión de recuperación de contraseña.
 */
@RestController
@RequestMapping(APIConstants.PASSWORD_BASE_PATH)
@RequiredArgsConstructor
public class PasswordResetController {

    private final PasswordResetService passwordResetService;

    /**
     * Solicita recuperación de contraseña.
     * POST /api/auth/password/forgot
     */
    @PostMapping(APIConstants.PASSWORD_FORGOT)
    public ResponseEntity<PasswordResetResponse> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request
    ) {
        return ResponseEntity.ok(passwordResetService.requestPasswordReset(request));
    }

    /**
     * Resetea la contraseña con el token.
     * POST /api/auth/password/reset
     */
    @PostMapping(APIConstants.PASSWORD_RESET)
    public ResponseEntity<PasswordResetResponse> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request
    ) {
        return ResponseEntity.ok(passwordResetService.resetPassword(request));
    }

    /**
     * Valida un token de reset (para verificar antes de mostrar form).
     * GET /api/auth/password/validate?token=xxx
     */
    @GetMapping("/validate")
    public ResponseEntity<Map<String, Boolean>> validateToken(
            @RequestParam String token
    ) {
        boolean valid = passwordResetService.validateResetToken(token);
        return ResponseEntity.ok(Map.of("valid", valid));
    }
}