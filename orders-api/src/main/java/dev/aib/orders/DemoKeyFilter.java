package dev.aib.orders;

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
 * How agents are usually wired today: one long-lived key that can do everything. It exists
 * only for the demo's --no-broker mode, to show what a prompt injection does without the
 * broker, and is off unless ORDERS_DEMO_API_KEY is set.
 *
 * <p>Requests send {@code Authorization: ApiKey <key>}, which the bearer-token filter ignores.
 */
class DemoKeyFilter extends OncePerRequestFilter {

    static final String CALLER_NAME = "static-api-key";
    private static final String PREFIX = "ApiKey ";

    private static final List<SimpleGrantedAuthority> EVERYTHING = List.of(
            new SimpleGrantedAuthority("ROLE_DEMO"),
            new SimpleGrantedAuthority("SCOPE_orders:read"),
            new SimpleGrantedAuthority("SCOPE_orders:refund"),
            new SimpleGrantedAuthority("SCOPE_orders:cancel"),
            new SimpleGrantedAuthority("SCOPE_orders:delete"));

    private final byte[] key;

    DemoKeyFilter(String key) {
        this.key = key.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith(PREFIX)
                && MessageDigest.isEqual(header.substring(PREFIX.length()).getBytes(StandardCharsets.UTF_8), key)) {
            SecurityContextHolder.getContext().setAuthentication(
                    UsernamePasswordAuthenticationToken.authenticated(CALLER_NAME, null, EVERYTHING));
        }
        chain.doFilter(request, response);
    }
}
