package com.authen.controller;


import com.authen.model.TokenRequest;
import com.authen.service.AuthService;
import com.authen.utils.PKCEUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static com.authen.utils.PKCEUtil.cacheCodeChallenge;

@RestController
@RequestMapping("/callback")
@Slf4j
public class CallbackController {

    @Autowired
    private AuthService authService;

    @Autowired
    private HttpServletRequest r;

    @GetMapping
    public ResponseEntity<Object> handleCallback(
            @RequestParam("code") String code,
            @RequestParam(value = "state", required = false) String state) {
        try {
            // Log thông tin nhận được
            log.info("Authorization code: {}", code);
            log.info("State: {}", state);

            // Gửi mã code này đến Keycloak để đổi lấy access token
            TokenRequest request = TokenRequest.builder()
                    .redirectUri(getHost() + "/callback")
                    .code(code)
                    .codeVerifier(cacheCodeChallenge.get(state))
                    .grantType("authorization_code")
                    .build();

            // Hoặc xử lý thêm tùy vào yêu cầu của bạn
            return ResponseEntity.ok(authService.getToken(request));
        } catch (Exception e) {
            log.error("Error handling callback", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Callback failed");
        }
    }

    private String getHost() {
        String scheme = r.getScheme(); // http hoặc https
        String serverName = r.getServerName(); // Tên host hoặc địa chỉ IP
        int serverPort = r.getServerPort(); // Cổng

        return String.format("%s://%s:%d", scheme, serverName, serverPort);
    }
}
