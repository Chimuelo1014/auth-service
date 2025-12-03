package com.sentinel.auth.security.oauth2;

import com.sentinel.auth.entity.UserEntity;
import com.sentinel.auth.enums.AuthProvider;
import com.sentinel.auth.enums.GlobalRole;
import com.sentinel.auth.enums.UserStatus;
import com.sentinel.auth.events.AuthEventPublisher;
import com.sentinel.auth.repository.UserRepository;
import com.sentinel.auth.service.JWTService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;

/**
 * Custom OAuth2 Success Handler.
 * Genera JWT y redirige al frontend con el token.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTService jwtService;
    private final UserRepository userRepository;
    private final AuthEventPublisher authEventPublisher;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {
        
        log.info("OAuth2 authentication successful");

        try {
            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
            Map<String, Object> attributes = oauth2User.getAttributes();
            
            // Detectar provider (Google o Microsoft)
            String provider = detectProvider(request);
            String email = extractEmail(attributes, provider);
            String providerId = extractProviderId(attributes, provider);
            
            log.info("OAuth2 login - Provider: {}, Email: {}", provider, email);
            
            // Buscar o crear usuario
            UserEntity user = findOrCreateUser(email, providerId, provider, attributes);
            
            // Generar JWT
            String token = jwtService.generateToken(user);
            
            log.info("JWT generated for user: {}", user.getId());
            
            // Publicar evento de login
            authEventPublisher.publishUserLogin(
                user.getId(),
                user.getEmail(),
                request.getRemoteAddr()
            );
            
            // ✅ Redirigir al frontend con el token en la URL
            String targetUrl = UriComponentsBuilder.fromUriString("http://localhost:3000/auth/callback")
                    .queryParam("token", token)
                    .queryParam("success", "true")
                    .build()
                    .toUriString();
            
            getRedirectStrategy().sendRedirect(request, response, targetUrl);
            
        } catch (Exception e) {
            log.error("Error during OAuth2 success handling: {}", e.getMessage(), e);
            
            String errorUrl = UriComponentsBuilder.fromUriString("http://localhost:3000/login")
                    .queryParam("error", "oauth2_processing_failed")
                    .build()
                    .toUriString();
            
            getRedirectStrategy().sendRedirect(request, response, errorUrl);
        }
    }

    private UserEntity findOrCreateUser(
            String email, 
            String providerId, 
            String provider,
            Map<String, Object> attributes
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
            
            log.info("New OAuth2 user created: {}", user.getId());
            
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
                log.info("Linked OAuth2 account to existing user: {}", user.getId());
            }
        }
        
        return user;
    }

    private String detectProvider(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        if (requestUri.contains("google")) {
            return "google";
        } else if (requestUri.contains("microsoft")) {
            return "microsoft";
        }
        return "unknown";
    }

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
        return null;
    }

    private String extractProviderId(Map<String, Object> attributes, String provider) {
        if ("google".equals(provider)) {
            return (String) attributes.get("sub");
        } else if ("microsoft".equals(provider)) {
            return (String) attributes.get("id");
        }
        return null;
    }
}