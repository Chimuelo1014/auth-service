package com.sentinel.auth.service.impl;

import com.sentinel.auth.client.TenantServiceClient;
import com.sentinel.auth.client.dto.TenantCreationRequest;
import com.sentinel.auth.client.dto.TenantDTO;
import com.sentinel.auth.constants.ErrorMessages;
import com.sentinel.auth.dto.request.LoginRequest;
import com.sentinel.auth.dto.request.LoginWith2FARequest;
import com.sentinel.auth.dto.request.RefreshTokenRequest;
import com.sentinel.auth.dto.request.RegisterRequest;
import com.sentinel.auth.dto.response.AuthResponse;
import com.sentinel.auth.entity.RefreshTokenEntity;
import com.sentinel.auth.entity.UserEntity;
import com.sentinel.auth.enums.*;
import com.sentinel.auth.exception.types.InvalidCredentialsException;
import com.sentinel.auth.exception.types.TokenValidationException;
import com.sentinel.auth.exception.types.TwoFactorAuthException;
import com.sentinel.auth.exception.types.UserAlreadyExistsException;
import com.sentinel.auth.exception.types.UserNotFoundException;
import com.sentinel.auth.repository.RefreshTokenRepository;
import com.sentinel.auth.repository.UserRepository;
import com.sentinel.auth.service.AuditLogService;
import com.sentinel.auth.service.AuthService;
import com.sentinel.auth.service.JWTService;
import com.sentinel.auth.service.TwoFactorAuthService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;
    private final TenantServiceClient tenantServiceClient;
    private final AuditLogService auditLogService;
    private final HttpServletRequest request;
    private final TwoFactorAuthService twoFactorAuthService;

    @Value("${jwt.refresh.expiration:2592000000}")
    private long refreshTokenExpiration;

    @Override
    @Transactional
    public AuthResponse register(RegisterRequest req) {
        log.info("Registering new user: {}", req.getEmail());
        
        if (userRepository.existsByEmail(req.getEmail())) {
            throw new UserAlreadyExistsException(
                String.format(ErrorMessages.USER_ALREADY_EXISTS, req.getEmail())
            );
        }

        UserEntity user = UserEntity.builder()
                .email(req.getEmail())
                .password(passwordEncoder.encode(req.getPassword()))
                .globalRole(GlobalRole.valueOf(req.getRole()))
                .authProvider(AuthProvider.LOCAL)
                .status(UserStatus.ACTIVE)
                .emailVerified(true)
                .build();

        userRepository.save(user);
        log.info("User created with ID: {}", user.getId());

        // Crear tenant automáticamente
        try {
            TenantCreationRequest tenantReq = TenantCreationRequest.builder()
                    .name(req.getEmail() + "'s Workspace")
                    .ownerId(user.getId())
                    .ownerEmail(user.getEmail())
                    .plan("FREE")
                    .autoGenerateName(true)
                    .build();

            TenantDTO tenant = tenantServiceClient.createTenant(tenantReq);
            
            user.setTenantId(tenant.getId());
            userRepository.save(user);
            
            log.info("Tenant created with ID: {}", tenant.getId());
        } catch (Exception e) {
            log.error("Failed to create tenant for user {}: {}", user.getId(), e.getMessage());
        }

        String accessToken = jwtService.generateToken(user);
        String refreshToken = createRefreshToken(user);

        auditLogService.logAction(
            user.getId(),
            user.getTenantId(),
            AuditAction.USER_REGISTERED,
            "User registered successfully",
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

    @Override
    @Transactional
    public AuthResponse login(LoginRequest req) {
        log.info("Login attempt for user: {}", req.getEmail());
        
        UserEntity user = userRepository.findByEmail(req.getEmail())
                .orElseThrow(() -> new BadCredentialsException(ErrorMessages.INVALID_CREDENTIALS));

        if (user.isLocked()) {
            auditLogService.logAction(
                user.getId(),
                user.getTenantId(),
                AuditAction.USER_LOGIN_FAILED,
                "Account is locked",
                getClientIP(),
                request.getHeader("User-Agent"),
                false,
                "Account locked"
            );
            throw new InvalidCredentialsException(ErrorMessages.USER_LOCKED);
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            req.getEmail(),
                            req.getPassword()
                    )
            );
            
            user.resetFailedAttempts();
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);
            
        } catch (BadCredentialsException e) {
            user.incrementFailedAttempts();
            
            if (user.getFailedLoginAttempts() >= 5) {
                user.lockAccount(900000);
                userRepository.save(user);
                
                auditLogService.logAction(
                    user.getId(),
                    user.getTenantId(),
                    AuditAction.USER_LOGIN_FAILED,
                    "Too many failed attempts - account locked",
                    getClientIP(),
                    request.getHeader("User-Agent"),
                    false,
                    "Max attempts exceeded"
                );
                
                throw new InvalidCredentialsException(ErrorMessages.USER_LOCKED);
            }
            
            userRepository.save(user);
            
            auditLogService.logAction(
                user.getId(),
                user.getTenantId(),
                AuditAction.USER_LOGIN_FAILED,
                "Invalid credentials",
                getClientIP(),
                request.getHeader("User-Agent"),
                false,
                "Bad credentials"
            );
            
            throw new BadCredentialsException(ErrorMessages.INVALID_CREDENTIALS);
        }

        String accessToken = jwtService.generateToken(user);
        String refreshToken = createRefreshToken(user);

        auditLogService.logAction(
            user.getId(),
            user.getTenantId(),
            AuditAction.USER_LOGIN,
            "User logged in successfully",
            getClientIP(),
            request.getHeader("User-Agent"),
            true,
            null
        );

        log.info("User logged in successfully: {}", user.getId());

        return AuthResponse.builder()
                .token(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .build();
    }

    @Override
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest req) {
        log.info("Refresh token request received");
        
        String tokenHash = hashToken(req.getRefreshToken());
        
        RefreshTokenEntity refreshToken = refreshTokenRepository
                .findByTokenHash(tokenHash)
                .orElseThrow(() -> new TokenValidationException(ErrorMessages.TOKEN_INVALID));

        if (refreshToken.getStatus() == TokenStatus.REVOKED) {
            throw new TokenValidationException(ErrorMessages.TOKEN_REVOKED);
        }

        if (refreshToken.getStatus() == TokenStatus.USED) {
            throw new TokenValidationException(ErrorMessages.TOKEN_USED);
        }

        if (refreshToken.isExpired()) {
            refreshToken.setStatus(TokenStatus.EXPIRED);
            refreshTokenRepository.save(refreshToken);
            throw new TokenValidationException(ErrorMessages.TOKEN_EXPIRED);
        }

        UserEntity user = userRepository.findById(refreshToken.getUserId())
                .orElseThrow(() -> new UserNotFoundException(
                    String.format(ErrorMessages.USER_NOT_FOUND, "ID: " + refreshToken.getUserId())
                ));

        String newAccessToken = jwtService.generateToken(user);

        auditLogService.logAction(
            user.getId(),
            user.getTenantId(),
            AuditAction.TOKEN_REFRESHED,
            "Access token refreshed",
            getClientIP(),
            request.getHeader("User-Agent"),
            true,
            null
        );

        log.info("Access token refreshed for user: {}", user.getId());

        return AuthResponse.builder()
                .token(newAccessToken)
                .refreshToken(req.getRefreshToken())
                .tokenType("Bearer")
                .build();
    }

    public AuthResponse loginWith2FA(LoginWith2FARequest req) {
        log.info("Login with 2FA attempt for user: {}", req.getEmail());
        
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                req.getEmail(),
                req.getPassword()
            )
        );
        
        UserEntity user = userRepository.findByEmail(req.getEmail())
                .orElseThrow(() -> new UserNotFoundException(ErrorMessages.USER_NOT_FOUND));
        
        if (user.isTwoFactorEnabled()) {
            if (!twoFactorAuthService.verify2FACode(user.getId(), req.getTwoFactorCode())) {
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
        
        String accessToken = jwtService.generateToken(user);
        String refreshToken = createRefreshToken(user);
        
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

    private String createRefreshToken(UserEntity user) {
        String token = UUID.randomUUID().toString();
        String tokenHash = hashToken(token);
        
        RefreshTokenEntity refreshToken = RefreshTokenEntity.builder()
                .tokenHash(tokenHash)
                .userId(user.getId())
                .status(TokenStatus.ACTIVE)
                .expiresAt(LocalDateTime.now().plusSeconds(refreshTokenExpiration / 1000))
                .ipAddress(getClientIP())
                .userAgent(request.getHeader("User-Agent"))
                .build();

        refreshTokenRepository.save(refreshToken);
        
        return token;
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash token", e);
        }
    }

    private String getClientIP() {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}