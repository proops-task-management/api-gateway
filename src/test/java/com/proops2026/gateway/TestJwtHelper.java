package com.proops2026.gateway;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import io.jsonwebtoken.Jwts;

/**
 * RS256 test-token factory (D7). Mints tokens exactly like user-service (D6): RS256, header
 * {@code kid=proops-v1}, claims {@code userId/email/role/jti/iat/exp}. The gateway under test is
 * wired with {@link #PUBLIC_KEY_PEM} as {@code JWT_PUBLIC_KEYS} — verify-only, so these tokens
 * prove the real verification path without any shared secret.
 */
public final class TestJwtHelper {

    // Mirrors user-service's signing key id (ADR-005) — informational until full JWKS lands.
    private static final String KEY_ID = "proops-v1";

    private static final KeyPair KEY_PAIR = generateRsaKeyPair();
    private static final KeyPair WRONG_KEY_PAIR = generateRsaKeyPair();

    /** X.509 (SubjectPublicKeyInfo) PEM of the signing key — inject as {@code jwt.public-keys} in tests. */
    public static final String PUBLIC_KEY_PEM = toPem(KEY_PAIR);

    private TestJwtHelper() {
    }

    public static String validToken(String userId, String role) {
        return signed(userId, role, UUID.randomUUID().toString(),
            new Date(), new Date(System.currentTimeMillis() + 86_400_000), KEY_PAIR.getPrivate());
    }

    public static String validTokenWithJti(String userId, String role, String jti) {
        return signed(userId, role, jti,
            new Date(), new Date(System.currentTimeMillis() + 86_400_000), KEY_PAIR.getPrivate());
    }

    public static String expiredToken(String userId, String role) {
        return signed(userId, role, UUID.randomUUID().toString(),
            new Date(System.currentTimeMillis() - 172_800_000),
            new Date(System.currentTimeMillis() - 86_400_000), KEY_PAIR.getPrivate());
    }

    /** Signed by a DIFFERENT RSA private key — the gateway's public key must reject it (→ 401). */
    public static String tokenSignedWithWrongKey(String userId, String role) {
        return signed(userId, role, UUID.randomUUID().toString(),
            new Date(), new Date(System.currentTimeMillis() + 86_400_000), WRONG_KEY_PAIR.getPrivate());
    }

    private static String signed(String userId, String role, String jti,
                                 Date issuedAt, Date expiration, PrivateKey key) {
        return Jwts.builder()
            .header().keyId(KEY_ID).and()
            .claim("userId", userId)
            .claim("email", "test@example.com")
            .claim("role", role)
            .id(jti)
            .issuedAt(issuedAt)
            .expiration(expiration)
            .signWith(key, Jwts.SIG.RS256)
            .compact();
    }

    private static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate test RSA key pair", e);
        }
    }

    private static String toPem(KeyPair pair) {
        String base64 = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----";
    }
}
