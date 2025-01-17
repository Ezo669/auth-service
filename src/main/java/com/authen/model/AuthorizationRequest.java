package com.authen.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthorizationRequest {
    private String codeChallenge;
    private String codeVerifier;
    private String username;
    private String password;
    private String codeChallengeMethod;  // Thường là "S256"
    private String redirectUri;
    private String state;  // Optional
    private String scope;  // Optional
}

