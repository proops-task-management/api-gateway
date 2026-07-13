package com.proops2026.gateway.util;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * RS256 verify-only (amended 2026-07-07 — IRD-003 / ADR-005).
 *
 * <p>The gateway holds ONLY public keys via {@code JWT_PUBLIC_KEYS} — it can verify tokens
 * signed by user-service's private key (D6) but can never sign one, so a compromised gateway
 * cannot forge identities. The list is newest-first: trying each key in turn lets a 24 h
 * dual-key rotation window keep the outgoing key valid until it expires (full JWKS/{@code kid}
 * selection deferred — ADR-005).
 */
@Component
public class JwtUtil {

    // Matches each PEM public-key block; DOTALL so the base64 body may span newlines.
    private static final Pattern PEM_BLOCK =
        Pattern.compile("-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----", Pattern.DOTALL);

    private final String publicKeysPem;

    private List<PublicKey> publicKeys;

    public JwtUtil(@Value("${jwt.public-keys}") String publicKeysPem) {
        this.publicKeysPem = publicKeysPem;
    }

    @PostConstruct
    void init() {
        this.publicKeys = parsePublicKeys(publicKeysPem);
        if (publicKeys.isEmpty()) {
            throw new IllegalStateException("JWT_PUBLIC_KEYS contained no usable RSA public key");
        }
    }

    /**
     * Verify RS256 against the newest-first key list; the first key that validates wins.
     * Trying each key in turn is what makes a dual-key rotation window non-disruptive.
     */
    public Claims parseAndValidate(String token) {
        JwtException lastError = null;
        for (PublicKey key : publicKeys) {
            try {
                return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            } catch (ExpiredJwtException ex) {
                throw ex;         // signature already matched this key → definitively expired; no other key helps
            } catch (JwtException ex) {
                lastError = ex;   // wrong key for this token — try the next (older) key in the rotation window
            }
        }
        throw lastError != null ? lastError
            : new SignatureException("no configured public key verified the token");
    }

    private List<PublicKey> parsePublicKeys(String raw) {
        List<PublicKey> keys = new ArrayList<>();
        Matcher matcher = PEM_BLOCK.matcher(raw);
        boolean foundBanner = false;
        while (matcher.find()) {
            foundBanner = true;
            keys.add(toPublicKey(matcher.group(1)));
        }
        // Banner-less fallback: a '|'-separated list of bare base64 SubjectPublicKeyInfo blocks.
        if (!foundBanner) {
            for (String part : raw.split("\\|")) {
                if (!part.isBlank()) {
                    keys.add(toPublicKey(part));
                }
            }
        }
        return keys;
    }

    private PublicKey toPublicKey(String pemBody) {
        // Keep only base64 chars (drops banners, whitespace, stray delimiters) — same hardening as user-service.
        String base64 = pemBody.replaceAll("[^A-Za-z0-9+/=]", "");
        byte[] der = Base64.getDecoder().decode(base64);
        try {
            return KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load RS256 JWT public key", e);
        }
    }
}
