package com.excelabs.appgateway.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class JwtUtil {

    private final PublicKey publicKey;
    private final long expirationMs;
    private final String issuer;

    public JwtUtil(String publicKey, long expirationMs, String issuer) {
        this.publicKey = parsePublicKey(publicKey);
        this.expirationMs = expirationMs;
        this.issuer = issuer;
    }

    private PublicKey parsePublicKey(String publicKeyPair){

        try {
            String publicKeyPEM = publicKeyPair
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);

            return KeyFactory.getInstance("RSA").generatePublic(keySpec);
        } catch (Exception e){
            log.error("Error parsing public key: {}", e.getMessage());
            throw new IllegalArgumentException("Invalid public key format", e);
        }
    }

    public String generateToken(Long userId, String username, List<? extends GrantedAuthority> authorities) {
        throw new UnsupportedOperationException(
                "The API gateway must not issue authentication tokens");
    }

    public String extractUsername(String token) {
        return extractClaims(token).get("preferred_username", String.class);
    }

    public Long extractUserId(String token) {
        return extractClaims(token).get("userId", Long.class);
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        Map<String, Object> resourceAccess = extractClaims(token).get("resource_access", Map.class);
        if (resourceAccess != null) {
            Map<String, Object> clientRoles = (Map<String, Object>) resourceAccess.get("account"); // Replace with actual client ID
            if (clientRoles != null) {
                return (List<String>) clientRoles.get("roles");
            }
        }
        return Collections.emptyList();
    }

    public boolean validateToken(String token) {
        try {
            extractClaims(token);
            return true;
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            log.error("JWT validation error: {}", e.getMessage());
        }
        return false;
    }

    private Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
