package com.spring.backend.module.security.util;

import com.spring.backend.module.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Utility class for generating, extracting, and validating JSON Web Tokens (JWT).
 *
 * <p>Uses the configured secret key to sign and verify tokens and obtains
 * token expiration settings from {@link JwtProperties}.
 *
 * <p>The user's username, which represents their email in this application,
 * is stored as the token subject.
 */
@Component
@RequiredArgsConstructor
public class JwtUtil {

    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);
    private final JwtProperties jwtProperties;

    /**
     * Creates the secret key used to sign and verify JWTs.
     *
     * <p>The configured secret is converted to bytes using UTF-8 encoding.
     *
     * @return the HMAC signing key
     */
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(
                jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8)
        );
    }

    /**
     * Generates an access token for the specified user.
     *
     * @param userDetails the authenticated user's details
     * @return the signed JWT access token
     */
    public String generateAccessToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails.getUsername(), jwtProperties.getAccessTokenExpiration());
    }

    /**
     * Builds and signs a JWT with the supplied claims, subject, and expiration duration.
     *
     * @param extraClaims additional claims to include in the token
     * @param subject the token subject, typically the user's email
     * @param expiration the token's validity duration in milliseconds
     * @return the compact, signed JWT string
     */
    private String generateToken(Map<String, Object> extraClaims, String subject, long expiration) {

        // → Set the token subject, issue time, expiration time, and signature.
        return Jwts.builder()
                .claims(extraClaims)
                .subject(subject)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Parses a JWT and extracts all its claims after verifying its signature.
     *
     * @param token the JWT to parse
     * @return the claims contained in the token
     * @throws JwtException if the token is invalid, expired, or cannot be parsed
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Extracts a specific claim from a JWT using the provided resolver.
     *
     * @param token the JWT containing the claim
     * @param claimsResolver the function used to retrieve the desired claim
     * @param <T> the type of the claim value
     * @return the resolved claim value
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        return claimsResolver.apply(extractAllClaims(token));
    }

    /**
     * Extracts the subject from a JWT, which represents the user's email.
     *
     * @param token the JWT to inspect
     * @return the email stored in the token subject
     */
    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extracts the expiration timestamp from a JWT.
     *
     * @param token the JWT to inspect
     * @return the expiration time as an {@link Instant}
     */
    public Instant extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration).toInstant();
    }

    /**
     * Checks whether a JWT has expired.
     *
     * @param token the JWT to inspect
     * @return {@code true} if the token's expiration time is before the current time
     */
    public boolean isTokenExpired(String token) {
        return extractExpiration(token).isBefore(Instant.now());
    }

    /**
     * Validates a JWT against the supplied user details.
     *
     * <p>The token is considered valid when its subject matches the user's
     * username and its expiration time has not passed.
     *
     * @param token the JWT to validate
     * @param userDetails the user details to compare against the token subject
     * @return {@code true} if the token matches the user and has not expired;
     *         {@code false} if validation fails
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            String email = extractEmail(token);

            // → Ensure the token belongs to the expected user and remains unexpired.
            return email.equals(userDetails.getUsername()) && !isTokenExpired(token);
        } catch (JwtException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            return false;
        }
    }
}