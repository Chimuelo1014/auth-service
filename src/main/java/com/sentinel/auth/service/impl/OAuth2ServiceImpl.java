package com.sentinel.auth.service.impl;

import com.sentinel.auth.client.TenantServiceClient;
import com.sentinel.auth.client.dto.TenantCreationRequest;
import com.sentinel.auth.client.dto.TenantDTO;
import com.sentinel.auth.dto.response.AuthResponse;
import com.sentinel.auth.dto.response.OAuth2UserInfo;
import com.sentinel.auth.entity.RefreshTokenEntity;
import com.sentinel.auth.entity.UserEntity;
import com.sentinel.auth.enums.*;
import com.sentinel.auth.repository.RefreshTokenRepository;
import com.sentinel.auth.repository.UserRepository;
import com.sentinel.auth.service.AuditLogService;
import com.sentinel.auth.service.JWTService;
import com.sentinel.auth.service.OAuth2Service;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnProperty(name = "app.oauth2.enabled", havingValue = "true")
public class OAuth2ServiceImpl implements OAuth2Service {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JWTService jwtService;
    private final TenantServiceClient tenantServiceClient;
    private final AuditLogService auditLogService;
    private final HttpServletRequest request;
    private final ClientRegistrationRepository clientRegistrationRepository;

    @Value("${jwt.refresh.expiration:2592000000}")
    private long refreshTokenExpiration;

    @Override
    @Transactional
    public AuthResponse processOAuth2Login(OAuth2UserInfo userInfo, String provider) {
        log.info("Processing OAuth2 login for email: {} via {}", userInfo.getEmail(), provider);

        AuthProvider authProvider = AuthProvider.valueOf(provider.toUpperCase());

        // Buscar usuario por email o provider ID
        UserEntity user = userRepository.findByEmail(userInfo.getEmail())
                .or(() -> userRepository.findByAuthProviderAndProviderUserId(
                        authProvider,
                        userInfo.getProviderId()
                ))
                .orElse(null);

        boolean isNewUser = false;

        if (user == null) {
            // Crear nuevo usuario
            isNewUser = true;
            user = createOAuth2User(userInfo, authProvider);
        } else {
            // Actualizar información si es necesario
            updateOAuth2User(user, userInfo, authProvider);
        }

        // Generar tokens
        String accessToken = jwtService.generateToken(user);
        String refreshToken = createRefreshToken(user);

        // Audit log
        auditLogService.logAction(
            user.getId(),
            user.getTenantId(),
            isNewUser ? AuditAction.USER_REGISTERED : AuditAction.OAUTH2_LOGIN_SUCCESS,
            String.format("OAuth2 login via %s", provider),
            getClientIP(),
            request.getHeader("User-Agent"),
            true,
            null
        );

        log.info("OAuth2 login successful for user: {}", user.getId());

        return AuthResponse.builder()
                .token(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .build();
    }

    @Override
    public String getAuthorizationUrl(String provider) {
        ClientRegistration registration = clientRegistrationRepository.findByRegistrationId(provider);
        
        if (registration == null) {
            throw new IllegalArgumentException("Unknown OAuth2 provider: " + provider);
        }

        // Generar state para CSRF protection
        String state = UUID.randomUUID().toString();
        
        // Construir URL de autorización
        return String.format(
            "%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s",
            registration.getProviderDetails().getAuthorizationUri(),
            registration.getClientId(),
            registration.getRedirectUri(),
            String.join(" ", registration.getScopes()),
            state
        );
    }

    // Helper methods
    private UserEntity createOAuth2User(OAuth2UserInfo userInfo, AuthProvider provider) {
        UserEntity user = UserEntity.builder()
                .email(userInfo.getEmail())
                .password(UUID.randomUUID().toString()) // Password dummy para OAuth2
                .globalRole(GlobalRole.USER)
                .authProvider(provider)
                .providerUserId(userInfo.getProviderId())
                .status(UserStatus.ACTIVE)
                .emailVerified(userInfo.isEmailVerified())
                .build();

        userRepository.save(user);
        log.info("New OAuth2 user created with ID: {}", user.getId());

        // Crear tenant automáticamente
        try {
            String workspaceName = userInfo.getName() != null 
                ? userInfo.getName() + "'s Workspace"
                : userInfo.getEmail() + "'s Workspace";

            TenantCreationRequest tenantReq = TenantCreationRequest.builder()
                    .name(workspaceName)
                    .ownerId(user.getId())
                    .ownerEmail(user.getEmail())
                    .plan("FREE")
                    .autoGenerateName(true)
                    .build();

            TenantDTO tenant = tenantServiceClient.createTenant(tenantReq);
            
            user.setTenantId(tenant.getId());
            userRepository.save(user);
            
            log.info("Tenant created for OAuth2 user: {}", tenant.getId());
        } catch (Exception e) {
            log.error("Failed to create tenant for OAuth2 user {}: {}", user.getId(), e.getMessage());
        }

        return user;
    }

    private void updateOAuth2User(UserEntity user, OAuth2UserInfo userInfo, AuthProvider provider) {
        boolean updated = false;

        if (user.getAuthProvider() == AuthProvider.LOCAL) {
            // Vincular cuenta local con OAuth2
            user.setAuthProvider(provider);
            user.setProviderUserId(userInfo.getProviderId());
            updated = true;
        }

        if (userInfo.isEmailVerified() && !user.isEmailVerified()) {
            user.setEmailVerified(true);
            updated = true;
        }

        if (updated) {
            userRepository.save(user);
            log.info("OAuth2 user updated: {}", user.getId());
        }
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