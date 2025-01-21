package com.authen.controller;

import com.authen.model.*;
import com.authen.service.AuthService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

import static com.authen.utils.PKCEUtil.generateCodeChallenge;
import static com.authen.utils.PKCEUtil.generateCodeVerifier;

@RestController
@RequestMapping("/api")
@Slf4j
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/public/authorize")
    public ResponseEntity<Object> initiateAuthorization(
            @RequestBody AuthorizationRequest request) {
        try {
            var response = authService.initiateAuthorization(request, null, null);
            // xử lý bypass keycloark bằng hàm getTokenUsingClientCredentials
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping("/public/token")
    public ResponseEntity<TokenResponse> getToken(@RequestBody TokenRequest tokenRequest) {
        log.info("Get token request: {}", tokenRequest);
        try {
            TokenResponse tokenResponse = authService.getToken(tokenRequest);
            return ResponseEntity.ok(tokenResponse);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping("/public/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        // TokenResponse tokenResponse = authService.login(loginRequest);
        var codeVerifier = generateCodeVerifier(loginRequest.getUsername(), loginRequest.getPassword());
        var codeChallenge = generateCodeChallenge(codeVerifier);
        return ResponseEntity.ok(Map.of(
                "codeVerifier", codeVerifier,
                "codeChallenge", codeChallenge,
                "state", "random_user_state_1"
        ));
    }
}
