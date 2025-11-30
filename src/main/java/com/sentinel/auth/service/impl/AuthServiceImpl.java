package com.sentinel.auth.service.impl;

import com.sentinel.auth.constants.ErrorMessages;
import com.sentinel.auth.dto.request.LoginRequest;
import com.sentinel.auth.dto.request.LoginWith2FARequest;
import com.sentinel.auth.dto.request.RefreshTokenRequest;
import com.sentinel.auth.dto.request.RegisterRequest;
import com.sentinel.auth.dto.response.AuthResponse;
import com.sentinel.auth.entity.RefreshTokenEntity;
import com.sentinel.auth.entity.UserEntity;
import com.sentinel.auth.enums.AuditAction;
import com.sentinel.auth.exception.types.TwoFactorAuthException;
import com.sentinel.auth.exception.types.UserNotFoundException;
import com.sentinel.auth.repository.RefreshTokenRepository;
import com.sentinel.auth.repository.UserRepository;
import com.sentinel.auth.service.JWTService;
import com.sentinel.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;

    @Value("${jwt.refresh.expiration:604800000}") // 7 días por defecto
    private long refreshTokenExpiration;

    @Override
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        
        // Validar si el usuario ya existe
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exists");
        }

        // Crear usuario
        UserEntity user = UserEntity.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .tenantId(request.getTenantId() != null ? UUID.fromString(request.getTenantId()) : null)
                .build();

        userRepository.save(user);

        // Generar tokens
        String accessToken = jwtService.generateToken(user);
        String refreshToken = createRefreshToken(user);

        return AuthResponse.builder()
                .token(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .build();
    }

    @Override
    @Transactional
    public AuthResponse login(LoginRequest request) {
        
        // Autenticar
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        // Buscar usuario
        UserEntity user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Revocar tokens anteriores (opcional - para single session)
        // refreshTokenRepository.deleteByUserId(user.getId());

        // Generar nuevos tokens
        String accessToken = jwtService.generateToken(user);
        String refreshToken = createRefreshToken(user);

        return AuthResponse.builder()
                .token(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .build();
    }

    @Override
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        
        // Buscar refresh token
        RefreshTokenEntity refreshToken = refreshTokenRepository
                .findByToken(request.getRefreshToken())
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        // Validar que no esté revocado
        if (refreshToken.isRevoked()) {
            throw new RuntimeException("Refresh token has been revoked");
        }

        // Validar que no esté expirado
        if (refreshToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Refresh token has expired");
        }

        // Buscar usuario
        UserEntity user = userRepository.findById(refreshToken.getUserId())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Generar nuevo access token
        String newAccessToken = jwtService.generateToken(user);

        return AuthResponse.builder()
                .token(newAccessToken)
                .refreshToken(request.getRefreshToken()) // Reusar el mismo refresh token
                .tokenType("Bearer")
                .build();
    }

    /**
     * Crea y persiste un refresh token para el usuario
     */
    private String createRefreshToken(UserEntity user) {
        String token = UUID.randomUUID().toString();
        
        RefreshTokenEntity refreshToken = RefreshTokenEntity.builder()
                .token(token)
                .userId(user.getId())
                .revoked(false)
                .expiresAt(LocalDateTime.now().plusSeconds(refreshTokenExpiration / 1000))
                .build();

        refreshTokenRepository.save(refreshToken);
        
        return token;
    }

    public AuthResponse loginWith2FA(LoginWith2FARequest request) {
    log.info("Login with 2FA attempt for user: {}", request.getEmail());
    
    // Autenticar credenciales básicas
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            request.getEmail(),
            request.getPassword()
        )
    );
    
    UserEntity user = userRepository.findByEmail(request.getEmail())
            .orElseThrow(() -> new UserNotFoundException(ErrorMessages.USER_NOT_FOUND));
    
    // Verificar 2FA si está habilitado
    if (user.isTwoFactorEnabled()) {
        if (!twoFactorAuthService.verify2FACode(user.getId(), request.getTwoFactorCode())) {
            auditLogService.logAction(
                user.getId(),
                user.getTenantId(),
                AuditAction.USER_LOGIN_FAILED,
                "Invalid 2FA code",
                getClientIP(),
                request.getHeader("User-Agent"),
                false,
                "2FA verification failed"
            );
            throw new TwoFactorAuthException(ErrorMessages.TWO_FACTOR_CODE_INVALID);
        }
    }
    
    // Generar tokens
    String accessToken = jwtService.generateToken(user);
    String refreshToken = createRefreshToken(user);
    
    // Audit log
    auditLogService.logAction(
        user.getId(),
        user.getTenantId(),
        AuditAction.USER_LOGIN,
        "User logged in with 2FA",
        getClientIP(),
        request.getHeader("User-Agent"),
        true,
        null
    );
    
    return AuthResponse.builder()
            .token(accessToken)
            .refreshToken(refreshToken)
            .tokenType("Bearer")
            .build();
}
}