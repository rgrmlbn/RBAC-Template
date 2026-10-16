package com.spring.backend.module.security.filter;

import com.spring.backend.module.security.util.JwtUtil;
import com.spring.backend.module.user.token.service.interfaces.TokenBlacklistService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filter that validates JWT access tokens for incoming HTTP requests.
 *
 * <p>Extracts the bearer token from the Authorization header, rejects
 * blacklisted or invalid tokens, and establishes the authenticated user's
 * security context when the token is valid.
 *
 * <p>Runs once per request to avoid processing the same request multiple
 * times within the filter chain.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final TokenBlacklistService tokenBlacklistService;

    /**
     * Processes the request's JWT and establishes authentication when valid.
     *
     * <p>If the Authorization header is missing or the token is invalid,
     * expired, or blacklisted, the request continues through the filter chain
     * without authentication being established by this filter.
     *
     * @param request the incoming HTTP request
     * @param response the HTTP response
     * @param filterChain the filter chain to continue processing the request
     * @throws ServletException if an error occurs while processing the request
     * @throws IOException if an input or output error occurs
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String authorizationHeader = request.getHeader("Authorization");
        final String jwt;
        final String email;

        // → Continue without JWT authentication if the request has no bearer token.
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // → Remove the "Bearer " prefix to obtain the raw JWT.
        jwt = authorizationHeader.substring(7);

        // → Reject tokens that have been revoked through the token blacklist.
        if (tokenBlacklistService.isBlacklisted(jwt)) {
            log.warn("Rejected request with blacklisted JWT for URI: {}", request.getRequestURI());
            filterChain.doFilter(request, response);
            return;
        }

        // → Extract the user's email from the token, handling invalid token formats and expiration.
        try {
            email = jwtUtil.extractEmail(jwt);
        } catch (ExpiredJwtException e) {
            log.warn("JWT token is expired: {}", e.getMessage());
            filterChain.doFilter(request, response);
            return;
        } catch (MalformedJwtException | SignatureException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            filterChain.doFilter(request, response);
            return;
        } catch (Exception e) {
            log.error("Error parsing JWT token: {}", e.getMessage());
            filterChain.doFilter(request, response);
            return;
        }

        // → Authenticate only when the token contains an email and no authentication exists yet.
        if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(email);

            // → Validate the token against the loaded user details before establishing authentication.
            if (jwtUtil.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                jwt,
                                userDetails.getAuthorities()
                        );

                // → Attach request-specific details and store authentication in the security context.
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // → Continue processing the request with the current security context.
        filterChain.doFilter(request, response);
    }
}