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
import org.springframework.security.web.SecurityFilterChain;

@Configuration
class SecurityConfig {

    @ConfigurationProperties("orders")
    record OrdersProperties(String issuer, String audience, String jwkSetUri) {}

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a
                        .requestMatchers(HttpMethod.GET, "/orders", "/orders/*").hasAuthority("SCOPE_orders:read")
                        .requestMatchers(HttpMethod.POST, "/orders/*/refund").hasAuthority("SCOPE_orders:refund")
                        .requestMatchers(HttpMethod.POST, "/orders/*/cancel").hasAuthority("SCOPE_orders:cancel")
                        .requestMatchers(HttpMethod.DELETE, "/orders/*").hasAuthority("SCOPE_orders:delete")
                        .anyRequest().denyAll())
                .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(c -> c.disable());
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
}
