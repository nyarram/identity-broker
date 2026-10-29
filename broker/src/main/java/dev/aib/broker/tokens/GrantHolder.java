package dev.aib.broker.tokens;

import dev.aib.broker.tokens.ExchangeRules.Grant;
import java.util.Optional;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * Carries the policy decision from {@link AccessTokenCustomizer}, where it is made, to
 * {@link BrokerAuthorizationService#save}, where the issued token is recorded and audited.
 * Both run within the same token request, but Spring passes no state between them.
 */
final class GrantHolder {

    private static final String ATTRIBUTE = GrantHolder.class.getName();

    private GrantHolder() {}

    static void set(Grant grant) {
        RequestContextHolder.currentRequestAttributes().setAttribute(ATTRIBUTE, grant, RequestAttributes.SCOPE_REQUEST);
    }

    static Optional<Grant> get() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        return attributes == null
                ? Optional.empty()
                : Optional.ofNullable((Grant) attributes.getAttribute(ATTRIBUTE, RequestAttributes.SCOPE_REQUEST));
    }
}
