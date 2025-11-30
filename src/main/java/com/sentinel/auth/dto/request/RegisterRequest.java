package com.sentinel.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for user registration.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {

    @Email(message = "Invalid email format")
    @NotBlank(message = "Email is required")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    private String password;

    /**
     * Role to assign to the user (e.g. TENANT_ADMIN, TENANT_USER).
     * You can ignore this in the UI and default it server-side if you prefer.
     */
    @NotBlank(message = "Role is required")
    private String role;

    /**
     * Optional tenant id when creating a user for a specific tenant.
     * Keep as String for DTO convenience; convert to UUID in service if needed.
     */
    private String tenantId;
}
