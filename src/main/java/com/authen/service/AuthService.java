package com.authen.service;

import com.authen.model.*;
import com.authen.utils.PKCEUtil;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.concurrent.ConcurrentHashMap;

import static com.authen.utils.PKCEUtil.cacheCodeChallenge;

@Service
@Slf4j
public class AuthService {

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;
    @Value("${keycloak.realm}")
    private String realm;
    @Value("${keycloak.resource}")
    private String clientId;
    @Value("${keycloak.credentials.secret}")
    private String secretId;

    @Autowired
    private RestTemplate restTemplate;

    public AuthorizationResponse initiateAuthorization(AuthorizationRequest request, String username, String passwd) {
        String authUrl = String.format("%s/realms/%s/protocol/openid-connect/auth", authServerUrl, realm);
        cacheCodeChallenge.put(request.getState(), request.getCodeVerifier());

        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(authUrl)
                .queryParam("response_type", "code")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", request.getRedirectUri())
                .queryParam("code_challenge", request.getCodeChallenge())
                .queryParam("code_challenge_method", request.getCodeChallengeMethod());


        if (request.getState() != null) {
            builder.queryParam("state", request.getState());
        }

        if (request.getScope() != null) {
            builder.queryParam("scope", request.getScope());
        }

        return AuthorizationResponse.builder()
                .authorizationUrl(builder.toUriString())
                .build();
    }

    @PostConstruct
    public String getTokenUsingClientCredentials() {
        String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token", authServerUrl, realm);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "client_credentials");
        params.add("client_id", clientId);
        params.add("client_secret", secretId);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        ResponseEntity<String> response = restTemplate.exchange(
                tokenUrl,
                HttpMethod.POST,
                request,
                String.class
        );

        return response.getBody();

    }

    public TokenResponse getToken(TokenRequest tokenRequest) {
        String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token", authServerUrl, realm);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", tokenRequest.getGrantType());
        params.add("client_id", clientId);
        params.add("client_secret", secretId);
        params.add("code", tokenRequest.getCode());
        params.add("redirect_uri", tokenRequest.getRedirectUri());
        params.add("code_verifier", tokenRequest.getCodeVerifier());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        try {
            ResponseEntity<TokenResponse> response = restTemplate.exchange(
                    tokenUrl,
                    HttpMethod.POST,
                    request,
                    TokenResponse.class
            );
            return response.getBody();
        } catch (Exception e) {
            log.error("Error getting token from Keycloak", e);
            throw new RuntimeException("Failed to get token from Keycloak");
        }
    }
}