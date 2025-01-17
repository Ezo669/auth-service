package com.authen.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TokenRequest {
    private String code;
    private String redirectUri;
    private String codeVerifier;
    private String grantType;
}
