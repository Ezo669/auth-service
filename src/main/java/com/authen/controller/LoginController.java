package com.authen.controller;

import com.authen.model.AuthorizationResponse;
import com.authen.service.AuthService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@Slf4j
@RequestMapping("/auth")
public class LoginController {

    @Autowired
    private AuthService authService;

    @GetMapping("/login")
    public String loginPage(Model model) {

        model.addAttribute("message", "Welcome to the login page!");
        return "login";
    }

    @PostMapping("/login")
    public ResponseEntity<AuthorizationResponse> processLogin(@RequestParam("username") String username,
                                                              @RequestParam("password") String password) {
        try {
            AuthorizationResponse response = authService.initiateAuthorization(null, username, password);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Login failed", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}