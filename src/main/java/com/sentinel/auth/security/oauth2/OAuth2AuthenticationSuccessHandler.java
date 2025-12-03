package com.sentinel.auth.security.oauth2;

import com.sentinel.auth.entity.RefreshTokenEntity;
import com.sentinel.auth.entity.UserEntity;
import com.sentinel.auth.enums.AuthProvider;
import com.sentinel.auth.enums.GlobalRole;
import com.sentinel.auth.enums.TokenStatus;
import com.sentinel.auth.enums.UserStatus;
import com.sentinel.auth.events.AuthEventPublisher;
import com.sentinel.auth.repository.RefreshTokenRepository;
import com.sentinel.auth.repository.UserRepository;
import com.sentinel.auth.service.JWTService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

/**
 * Custom OAuth2 Success Handler.
 * Genera JWT + RefreshToken y redirige al frontend con el token.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTService jwtService;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuthEventPublisher authEventPublisher;

    @Value("${jwt.refresh.expiration:2592000000}")
    private long refreshTokenExpiration;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {
        
        log.info("🔐 OAuth2 authentication successful");

        try {
            // ✅ Cast a OAuth2AuthenticationToken para obtener el provider
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            String provider = oauthToken.getAuthorizedClientRegistrationId(); // "google" o "microsoft"
            
            OAuth2User oauth2User = oauthToken.getPrincipal();
            Map<String, Object> attributes = oauth2User.getAttributes();
            
            log.info("📧 OAuth2 Provider: {}, Attributes: {}", provider, attributes.keySet());
            
            // Extraer email y providerId según el provider
            String email = extractEmail(attributes, provider);
            String providerId = extractProviderId(attributes, provider);
            
            if (email == null || providerId == null) {
                log.error("❌ Failed to extract email or providerId from OAuth2 response");
                redirectToError(request, response, "missing_user_info");
                return;
            }
            
            log.info("✅ OAuth2 login - Provider: {}, Email: {}, ProviderId: {}", provider, email, providerId);
            
            // Buscar o crear usuario
            UserEntity user = findOrCreateUser(email, providerId, provider, attributes, request);
            
            // ✅ Generar JWT + RefreshToken
            String accessToken = jwtService.generateToken(user);
            String refreshToken = createRefreshToken(user, request);
            
            log.info("✅ JWT + RefreshToken generated for user: {}", user.getId());
            
            // Publicar evento de login
            authEventPublisher.publishUserLogin(
                user.getId(),
                user.getEmail(),
                getClientIP(request)
            );
            
            // ✅ Redirigir al frontend con AMBOS tokens
            String targetUrl = UriComponentsBuilder.fromUriString("http://localhost:3000/auth/callback")
                    .queryParam("token", accessToken)
                    .queryParam("refreshToken", refreshToken)
                    .queryParam("success", "true")
                    .build()
                    .toUriString();
            
            log.info("🔀 Redirecting to: {}", targetUrl);
            
            getRedirectStrategy().sendRedirect(request, response, targetUrl);
            
        } catch (Exception e) {
            log.error("❌ Error during OAuth2 success handling: {}", e.getMessage(), e);
            redirectToError(request, response, "processing_failed");
        }
    }

    private UserEntity findOrCreateUser(
            String email, 
            String providerId, 
            String provider,
            Map<String, Object> attributes,
            HttpServletRequest request
    ) {
        AuthProvider authProvider = AuthProvider.valueOf(provider.toUpperCase());
        
        // Buscar por email o providerId
        UserEntity user = userRepository.findByEmail(email)
                .or(() -> userRepository.findByAuthProviderAndProviderUserId(authProvider, providerId))
                .orElse(null);
        
        if (user == null) {
            // Crear nuevo usuario
            user = UserEntity.builder()
                    .email(email)
                    .password(UUID.randomUUID().toString()) // Password dummy para OAuth2
                    .globalRole(GlobalRole.USER)
                    .authProvider(authProvider)
                    .providerUserId(providerId)
                    .status(UserStatus.ACTIVE)
                    .emailVerified(true)
                    .build();
            
            userRepository.save(user);
            
            log.info("✅ New OAuth2 user created: {}", user.getId());
            
            // ✅ Publicar evento para crear tenant
            authEventPublisher.publishUserRegistered(
                user.getId(),
                user.getEmail(),
                user.getGlobalRole().name()
            );
        } else {
            // Actualizar provider si es necesario
            if (user.getAuthProvider() == AuthProvider.LOCAL) {
                user.setAuthProvider(authProvider);
                user.setProviderUserId(providerId);
                userRepository.save(user);
                log.info("🔗 Linked OAuth2 account to existing user: {}", user.getId());
            }
            
            // Actualizar last login
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);
        }
        
        return user;
    }

    /**
     * ✅ Crea un RefreshToken y lo guarda en la BD
     */
    private String createRefreshToken(UserEntity user, HttpServletRequest request) {
        String token = UUID.randomUUID().toString();
        String tokenHash = hashToken(token);
        
        RefreshTokenEntity refreshToken = RefreshTokenEntity.builder()
                .tokenHash(tokenHash)
                .userId(user.getId())
                .status(TokenStatus.ACTIVE)
                .expiresAt(LocalDateTime.now().plusSeconds(refreshTokenExpiration / 1000))
                .ipAddress(getClientIP(request))
                .userAgent(request.getHeader("User-Agent"))
                .build();

        refreshTokenRepository.save(refreshToken);
        
        return token; // ← Retornar el token sin hashear
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

    /**
     * ✅ Extrae email según el provider
     */
    private String extractEmail(Map<String, Object> attributes, String provider) {
        if ("google".equals(provider)) {
            return (String) attributes.get("email");
        } else if ("microsoft".equals(provider)) {
            // Microsoft puede usar "mail" o "userPrincipalName"
            String email = (String) attributes.get("mail");
            if (email == null) {
                email = (String) attributes.get("userPrincipalName");
            }
            return email;
        }
        log.warn("⚠️ Unknown provider: {}", provider);
        return null;
    }

    /**
     * ✅ Extrae providerId según el provider
     */
    private String extractProviderId(Map<String, Object> attributes, String provider) {
        if ("google".equals(provider)) {
            return (String) attributes.get("sub");
        } else if ("microsoft".equals(provider)) {
            return (String) attributes.get("id");
        }
        log.warn("⚠️ Unknown provider: {}", provider);
        return null;
    }

    /**
     * ✅ Redirige al frontend con error
     */
    private void redirectToError(HttpServletRequest request, HttpServletResponse response, String error) 
            throws IOException {
        String errorUrl = UriComponentsBuilder.fromUriString("http://localhost:3000/login")
                .queryParam("error", "oauth2_" + error)
                .build()
                .toUriString();
        
        getRedirectStrategy().sendRedirect(request, response, errorUrl);
    }

    /**
     * ✅ Obtiene la IP del cliente
     */
    private String getClientIP(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}