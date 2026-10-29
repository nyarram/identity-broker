package dev.aib.broker.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import dev.aib.broker.agents.AgentAssertionDecoderFactory;
import dev.aib.broker.tokens.DenialAuditor;
import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

@Configuration
class SecurityConfig {

    /** Admin API: agent registry and delegations, protected by the admin token. */
    @Bean
    @Order(1)
    SecurityFilterChain adminChain(HttpSecurity http, BrokerProperties properties) throws Exception {
        http.securityMatcher("/admin/**", "/delegations", "/delegations/**")
                .authorizeHttpRequests(a -> a.anyRequest().hasRole("ADMIN"))
                .addFilterBefore(new AdminTokenFilter(properties.adminToken()), AuthorizationFilter.class)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(c -> c.disable())
                .exceptionHandling(e -> e.authenticationEntryPoint((request, response, ex) -> {
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    response.getWriter().write("{\"error\":\"unauthorized\",\"error_description\":\"Admin token required\"}");
                }));
        return http.build();
    }

    /** OAuth endpoints: token, JWKS, introspection, revocation and metadata. */
    @Bean
    @Order(2)
    SecurityFilterChain authorizationServerChain(
            HttpSecurity http, AgentAssertionDecoderFactory assertionDecoders, DenialAuditor denialAuditor)
            throws Exception {
        http.oauth2AuthorizationServer(as -> as
                        .clientAuthentication(clientAuth -> clientAuth
                                .authenticationProviders(providers -> providers.forEach(provider -> {
                                    if (provider instanceof JwtClientAssertionAuthenticationProvider jwtProvider) {
                                        jwtProvider.setJwtDecoderFactory(assertionDecoders);
                                    }
                                }))
                                .authenticationSuccessHandler(DenialAuditor.rememberAuthenticatedAgent())
                                .errorResponseHandler(denialAuditor))
                        .tokenEndpoint(token -> token.errorResponseHandler(denialAuditor)))
                // /error stays open so server faults surface as 500s, not as a misleading 401
                .authorizeHttpRequests(a -> a.requestMatchers("/error").permitAll().anyRequest().authenticated())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

    @Bean
    JWKSource<SecurityContext> jwkSource(BrokerProperties properties) {
        return new ImmutableJWKSet<>(new JWKSet(SigningKeys.load(properties.signingKeyFile())));
    }

    @Bean
    JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings(BrokerProperties properties) {
        return AuthorizationServerSettings.builder().issuer(properties.issuer()).build();
    }

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}
