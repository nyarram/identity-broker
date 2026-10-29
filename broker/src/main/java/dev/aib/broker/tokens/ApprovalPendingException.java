package dev.aib.broker.tokens;

import dev.aib.broker.approvals.Approval;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

/** {@code authorization_pending}: carries the approval so the response can tell the agent where to poll. */
class ApprovalPendingException extends OAuth2AuthenticationException {

    private final transient Approval approval;

    ApprovalPendingException(Approval approval, String description) {
        super(new OAuth2Error("authorization_pending", description, null));
        this.approval = approval;
    }

    Approval approval() {
        return approval;
    }
}
