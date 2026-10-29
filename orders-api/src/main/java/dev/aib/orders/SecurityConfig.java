package dev.aib.orders;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
class SecurityConfig {

    /**
     * @param clientId and clientSecret authenticate this API to the broker's introspection endpoint
     * @param demoApiKey enables the all-access static key used by the demo's --no-broker mode; blank disables it
     */
    @ConfigurationProperties("orders")
    record OrdersProperties(
            String issuer,
            String audience,
            String jwkSetUri,
            String introspectionUri,
            String clientId,
            String clientSecret,
            String demoApiKey) {}

    @Bean
    SecurityFilterChain api(HttpSecurity http, OrdersProperties properties) throws Exception {
        http.authorizeHttpRequests(a -> a
                        // Error responses (401, 409, 422, ...) are rendered by /error; denying it would turn them all into 403
                        .requestMatchers("/error").permitAll()
                        .requestMatchers(HttpMethod.GET, "/orders", "/orders/*").hasAuthority("SCOPE_orders:read")
                        .requestMatchers(HttpMethod.POST, "/orders/*/refund").hasAuthority("SCOPE_orders:refund")
                        .requestMatchers(HttpMethod.POST, "/orders/*/cancel").hasAuthority("SCOPE_orders:cancel")
                        .requestMatchers(HttpMethod.DELETE, "/orders/*").hasAuthority("SCOPE_orders:delete")
                        .requestMatchers(HttpMethod.POST, "/admin/reset").hasRole("DEMO")
                        .anyRequest().denyAll())
                .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(c -> c.disable());
        if (properties.demoApiKey() != null && !properties.demoApiKey().isBlank()) {
            http.addFilterBefore(new DemoKeyFilter(properties.demoApiKey()), BearerTokenAuthenticationFilter.class);
        }
        return http.build();
    }

    /**
     * Accepts only RFC 9068 access tokens from the broker: ES256, typ at+jwt, our issuer,
     * our audience, unexpired, with sub, client_id, iat and jti. Delegation tokens fail on
     * both type and audience.
     */
    @Bean
    JwtDecoder jwtDecoder(OrdersProperties properties) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(properties.jwkSetUri())
                .jwsAlgorithm(SignatureAlgorithm.ES256)
                .validateType(false) // typ is checked by the RFC 9068 validator below
                .build();
        decoder.setJwtValidator(JwtValidators.createAtJwtValidator()
                .issuer(properties.issuer())
                .audience(properties.audience())
                .build());
        return decoder;
    }

    /** Asks the broker whether a token is still active before every write (RFC 7662). */
    @Bean
    OpaqueTokenIntrospector introspector(OrdersProperties properties) {
        return SpringOpaqueTokenIntrospector.withIntrospectionUri(properties.introspectionUri())
                .clientId(properties.clientId())
                .clientSecret(properties.clientSecret())
                .build();
    }
}
