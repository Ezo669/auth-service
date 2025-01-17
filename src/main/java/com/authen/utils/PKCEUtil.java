package com.authen.utils;

import lombok.experimental.UtilityClass;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

@UtilityClass
public class PKCEUtil {
    public static final ConcurrentHashMap<String, String > cacheCodeChallenge = new ConcurrentHashMap<>();

    public static String generateCodeVerifier(String username, String password) {
        try {
            // Kết hợp username và password thành một chuỗi duy nhất
            String combined = username + ":" + password;

            // Mã hóa chuỗi kết hợp thành một byte array
            byte[] bytes = combined.getBytes(StandardCharsets.UTF_8);

            // Sinh ra chuỗi ngẫu nhiên từ byte array
            byte[] randomBytes = new byte[32];
            new SecureRandom().nextBytes(randomBytes);

            // Kết hợp randomBytes với byte array của username và password
            byte[] combinedBytes = new byte[randomBytes.length + bytes.length];
            System.arraycopy(randomBytes, 0, combinedBytes, 0, randomBytes.length);
            System.arraycopy(bytes, 0, combinedBytes, randomBytes.length, bytes.length);

            // Tạo code verifier từ chuỗi byte đã kết hợp
            return Base64.getUrlEncoder().withoutPadding().encodeToString(combinedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error generating code verifier", e);
        }
    }

    public static String generateCodeChallenge(String codeVerifier) {
        try {
            byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            md.update(bytes, 0, bytes.length);
            byte[] digest = md.digest();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception ex) {
            throw new RuntimeException("Error generating code challenge", ex);
        }
    }

}

