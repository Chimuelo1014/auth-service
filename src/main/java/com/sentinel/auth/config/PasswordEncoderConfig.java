package com.sentinel.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Configures the password encoder used across the authentication module.
 *
 * <p>We use BCrypt because it is currently one of the most secure
 * hashing algorithms for passwords. It includes salting and is
 * computationally expensive, helping protect against brute-force attacks.</p>
 */
@Configuration
public class PasswordEncoderConfig {

    /**
     * Provides a PasswordEncoder bean using BCrypt.
     *
     * @return PasswordEncoder instance based on BCrypt
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
