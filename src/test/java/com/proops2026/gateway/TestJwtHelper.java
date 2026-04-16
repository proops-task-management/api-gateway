package com.proops2026.gateway;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

public final class TestJwtHelper {

    public static final String SECRET = "this-is-a-test-secret-that-is-at-least-32-chars-long";
    private static final SecretKey KEY = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));

    private TestJwtHelper() {
    }

    public static String validToken(String userId, String role) {
        return Jwts.builder()
            .claim("userId", userId)
            .claim("email", "test@example.com")
            .claim("role", role)
            .id(UUID.randomUUID().toString())
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + 86_400_000))
            .signWith(KEY)
            .compact();
    }

    public static String validTokenWithJti(String userId, String role, String jti) {
        return Jwts.builder()
            .claim("userId", userId)
            .claim("email", "test@example.com")
            .claim("role", role)
            .id(jti)
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + 86_400_000))
            .signWith(KEY)
            .compact();
    }

    public static String expiredToken(String userId, String role) {
        return Jwts.builder()
            .claim("userId", userId)
            .claim("email", "test@example.com")
            .claim("role", role)
            .id(UUID.randomUUID().toString())
            .issuedAt(new Date(System.currentTimeMillis() - 172_800_000))
            .expiration(new Date(System.currentTimeMillis() - 86_400_000))
            .signWith(KEY)
            .compact();
    }

    public static String tokenSignedWithWrongSecret(String userId, String role) {
        SecretKey wrongKey = Keys.hmacShaKeyFor(
            "wrong-secret-that-is-also-at-least-32-characters".getBytes(StandardCharsets.UTF_8));
        return Jwts.builder()
            .claim("userId", userId)
            .claim("email", "test@example.com")
            .claim("role", role)
            .id(UUID.randomUUID().toString())
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + 86_400_000))
            .signWith(wrongKey)
            .compact();
    }
}
