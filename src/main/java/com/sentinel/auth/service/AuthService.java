package com.sentinel.auth.service;

import com.sentinel.auth.dto.request.LoginRequest;
import com.sentinel.auth.dto.request.RefreshTokenRequest;
import com.sentinel.auth.dto.request.RegisterRequest;
import com.sentinel.auth.dto.response.AuthResponse;

/**
 * Authentication Service contract.
 * Defines the operations available for registering, logging in,
 * and refreshing authentication tokens.
 */
public interface AuthService {

    AuthResponse register(RegisterRequest request);

    AuthResponse login(LoginRequest request);

    AuthResponse refreshToken(RefreshTokenRequest request);
}
