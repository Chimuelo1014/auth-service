package com.sentinel.auth.dto.response;

import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2UserInfo {
    
    private String providerId;
    private String email;
    private String name;
    private String firstName;
    private String lastName;
    private String profilePictureUrl;
    private boolean emailVerified;
}
