package dev.aib.broker.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * v1 admin authentication: one static bearer token from the environment. A known
 * weakness, listed in the threat model; the roadmap replaces it with OIDC login.
 */
class AdminTokenFilter extends OncePerRequestFilter {

    private static final String BEARER = "Bearer ";

    private final byte[] adminToken;

    AdminTokenFilter(String adminToken) {
        this.adminToken = adminToken.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith(BEARER)) {
            byte[] presented = header.substring(BEARER.length()).getBytes(StandardCharsets.UTF_8);
            if (MessageDigest.isEqual(presented, adminToken)) {
                SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                        "admin", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))));
            }
        }
        chain.doFilter(request, response);
    }
}
