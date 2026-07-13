package com.proops2026.gateway.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Date;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Direct unit tests for the RS256 verify-only {@link JwtUtil} — covers the rotation, PEM-parsing,
 * and fail-fast branches that the gateway's {@code @SpringBootTest} filter tests never exercise
 * (single banner PEM, valid token only). Constructs {@code JwtUtil} without Spring, so it invokes
 * {@link JwtUtil#init()} explicitly (the {@code @PostConstruct} hook Spring would call).
 */
class JwtUtilTest {

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String pem(KeyPair kp) {
        String b64 = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----";
    }

    private static String bareBase64(KeyPair kp) {
        // Banner-less SubjectPublicKeyInfo — exercises JwtUtil's foundBanner==false fallback.
        return Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
    }

    private static String token(KeyPair kp, long expiryOffsetMs) {
        Date now = new Date();
        return Jwts.builder()
            .header().keyId("proops-v1").and()
            .claim("userId", "u1")
            .claim("role", "member")
            .id("jti-1")
            .issuedAt(now)
            .expiration(new Date(now.getTime() + expiryOffsetMs))
            .signWith(kp.getPrivate(), Jwts.SIG.RS256)
            .compact();
    }

    private static JwtUtil initialized(String keysPem) {
        JwtUtil util = new JwtUtil(keysPem);
        util.init();
        return util;
    }

    @Test
    void validToken_verifiesAndReturnsClaims() throws Exception {
        KeyPair kp = rsaKeyPair();
        Claims claims = initialized(pem(kp)).parseAndValidate(token(kp, 3_600_000));
        assertThat(claims.get("userId", String.class)).isEqualTo("u1");
        assertThat(claims.getId()).isEqualTo("jti-1");
    }

    @Test
    void tokenSignedWithWrongKey_throwsJwtException() throws Exception {
        KeyPair signer = rsaKeyPair();
        KeyPair gatewayKey = rsaKeyPair();
        JwtUtil util = initialized(pem(gatewayKey));
        assertThatThrownBy(() -> util.parseAndValidate(token(signer, 3_600_000)))
            .isInstanceOf(JwtException.class);
    }

    @Test
    void expiredToken_shortCircuitsWithExpiredJwtException() throws Exception {
        KeyPair kp = rsaKeyPair();
        JwtUtil util = initialized(pem(kp));
        assertThatThrownBy(() -> util.parseAndValidate(token(kp, -3_600_000)))
            .isInstanceOf(ExpiredJwtException.class);
    }

    @Test
    void keyRotation_tokenSignedByOlderKeyInListStillVerifies() throws Exception {
        // Newest-first list; a token signed by the OLDER (second) key must still verify —
        // this is what makes a 24h dual-key rotation window non-disruptive (ADR-005).
        KeyPair newKey = rsaKeyPair();
        KeyPair oldKey = rsaKeyPair();
        String keys = pem(newKey) + "\n" + pem(oldKey);
        Claims claims = initialized(keys).parseAndValidate(token(oldKey, 3_600_000));
        assertThat(claims.get("role", String.class)).isEqualTo("member");
    }

    @Test
    void bannerlessPem_isParsedAndVerifies() throws Exception {
        KeyPair kp = rsaKeyPair();
        Claims claims = initialized(bareBase64(kp)).parseAndValidate(token(kp, 3_600_000));
        assertThat(claims.get("userId", String.class)).isEqualTo("u1");
    }

    @Test
    void blankKeys_failFastAtInit() {
        assertThatThrownBy(() -> new JwtUtil("   ").init())
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void malformedKey_failsToLoadAtInit() {
        // Valid base64 but not a valid X.509 SubjectPublicKeyInfo -> KeyFactory rejects it.
        String bad = "-----BEGIN PUBLIC KEY-----\nAAAAAAAA\n-----END PUBLIC KEY-----";
        assertThatThrownBy(() -> new JwtUtil(bad).init())
            .isInstanceOf(IllegalStateException.class);
    }
}
