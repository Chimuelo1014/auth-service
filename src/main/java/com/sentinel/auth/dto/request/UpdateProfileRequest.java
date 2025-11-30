package com.sentinel.auth.dto.request;

import jakarta.validation.constraints.Email;
import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateProfileRequest {
    
    @Email(message = "Invalid email format")
    private String email;
    
    private String firstName;
    
    private String lastName;
}