package dev.aib.broker.tokens;

import com.nimbusds.jose.util.JSONObjectUtils;
import dev.aib.broker.approvals.Approval;
import dev.aib.broker.audit.AuditLog;
import dev.aib.broker.audit.AuditLog.EventType;
import dev.aib.broker.audit.AuditLog.NewEvent;
import dev.aib.broker.config.BrokerProperties;
import dev.aib.broker.delegations.Delegation;
import dev.aib.broker.delegations.DelegationRepository;
import dev.aib.broker.support.Ids;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ErrorAuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

/**
 * Records every refused request to the OAuth endpoints (failed client authentication,
 * invalid delegation, policy denial, ...) in the audit log, then sends the standard OAuth
 * error response.
 *
 * <p>Denials are audited best-effort: if the audit write fails the request is still
 * refused, because failing safe here means denying. Issuance is the opposite; see
 * {@link BrokerAuthorizationService#save}.
 */
@Component
public class DenialAuditor implements AuthenticationFailureHandler {

    private static final Logger log = LoggerFactory.getLogger(DenialAuditor.class);
    private static final int MAX_PARAMETER_LENGTH = 4096;
    /** Request attribute naming the agent once it has proved its identity. */
    private static final String AUTHENTICATED_AGENT = DenialAuditor.class.getName() + ".agent";
    /** Seconds the agent should wait between polls of a pending approval (as in RFC 8628). */
    static final int POLL_INTERVAL_SECONDS = 2;

    private final AuditLog audit;
    private final DelegationRepository delegations;
    private final String issuer;
    private final Clock clock;
    private final AuthenticationFailureHandler errorResponse = new OAuth2ErrorAuthenticationFailureHandler();
    private final OAuth2ErrorHttpMessageConverter errorConverter = new OAuth2ErrorHttpMessageConverter();

    DenialAuditor(AuditLog audit, DelegationRepository delegations, BrokerProperties properties, Clock clock) {
        this.audit = audit;
        this.delegations = delegations;
        this.issuer = properties.issuer();
        this.clock = clock;
    }

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException, ServletException {
        try {
            audit.append(denial(request, exception));
        } catch (RuntimeException e) {
            log.error("Could not audit a denied request to {}", request.getRequestURI(), e);
        }
        sendError(request, response, exception);
    }

    /**
     * Replaces Spring's client-authentication success handler: does what it does (set the
     * security context) and also remembers the agent on the request, because Spring clears
     * the security context before a token-endpoint error reaches this class.
     */
    public static AuthenticationSuccessHandler rememberAuthenticatedAgent() {
        return (request, response, authentication) -> {
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
            if (authentication instanceof OAuth2ClientAuthenticationToken client && client.getRegisteredClient() != null) {
                request.setAttribute(AUTHENTICATED_AGENT, client.getRegisteredClient().getClientId());
            }
        };
    }

    /**
     * Failed client authentication gets 401 with only the error code, as Spring does by
     * default, so callers learn nothing about which agents exist. Other errors get 400 with
     * a description.
     */
    private void sendError(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException, ServletException {
        if (exception instanceof ApprovalPendingException pending) {
            sendPending(response, pending);
            return;
        }
        if (exception instanceof OAuth2AuthenticationException oauth
                && OAuth2ErrorCodes.INVALID_CLIENT.equals(oauth.getError().getErrorCode())) {
            ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
            httpResponse.setStatusCode(HttpStatus.UNAUTHORIZED);
            errorConverter.write(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT), null, httpResponse);
            return;
        }
        errorResponse.onAuthenticationFailure(request, response, exception);
    }

    /** Like RFC 8628's authorization_pending, plus where to poll for the decision. */
    private void sendPending(HttpServletResponse response, ApprovalPendingException pending) throws IOException {
        Approval approval = pending.approval();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "authorization_pending");
        body.put("error_description", pending.getError().getDescription());
        body.put("approval_id", approval.id());
        body.put("approval_uri", issuer + "/approvals/" + approval.id());
        body.put("expires_in", Math.max(0, Duration.between(clock.instant(), approval.expiresAt()).toSeconds()));
        body.put("interval", POLL_INTERVAL_SECONDS);
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.getWriter().write(JSONObjectUtils.toJSONString(body));
    }

    private NewEvent denial(HttpServletRequest request, AuthenticationException exception) {
        OAuth2Error error = exception instanceof OAuth2AuthenticationException oauth
                ? oauth.getError()
                : new OAuth2Error("server_error");

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("endpoint", request.getRequestURI());
        for (String name : new String[] {"grant_type", "client_id", "resource", "scope", "authorization_details", "approval_id"}) {
            String value = request.getParameter(name);
            if (value != null) {
                summary.put(name, truncate(value));
            }
        }

        Optional<Delegation> delegation = Optional.ofNullable(request.getParameter("subject_token"))
                .flatMap(token -> delegations.findByTokenHash(Ids.sha256(token)));
        String reason = error.getDescription() == null
                ? error.getErrorCode()
                : error.getErrorCode() + ": " + error.getDescription();
        boolean pending = exception instanceof ApprovalPendingException;
        if (pending) {
            reason += " (" + ((ApprovalPendingException) exception).approval().id() + ")";
        }

        return new NewEvent(
                EventType.TOKEN_DENIED,
                (String) request.getAttribute(AUTHENTICATED_AGENT), // the claimed client_id stays in the request summary
                delegation.map(Delegation::userId).orElse(null),
                delegation.map(Delegation::id).orElse(null),
                null,
                summary,
                pending ? "pending" : "deny",
                reason);
    }

    private static String truncate(String value) {
        return value.length() <= MAX_PARAMETER_LENGTH ? value : value.substring(0, MAX_PARAMETER_LENGTH) + "...";
    }
}
