package dev.aib.broker.policy;

import com.cedarpolicy.BasicAuthorizationEngine;
import com.cedarpolicy.model.AuthorizationRequest;
import com.cedarpolicy.model.AuthorizationResponse;
import com.cedarpolicy.model.AuthorizationSuccessResponse;
import com.cedarpolicy.model.ValidationRequest;
import com.cedarpolicy.model.ValidationResponse;
import com.cedarpolicy.model.exception.AuthException;
import com.cedarpolicy.model.policy.Policy;
import com.cedarpolicy.model.policy.PolicySet;
import com.cedarpolicy.model.schema.Schema;
import com.cedarpolicy.model.schema.Schema.JsonOrCedar;
import com.cedarpolicy.value.CedarList;
import com.cedarpolicy.value.EntityTypeName;
import com.cedarpolicy.value.EntityUID;
import com.cedarpolicy.value.PrimBool;
import com.cedarpolicy.value.PrimLong;
import com.cedarpolicy.value.Value;
import dev.aib.broker.config.BrokerProperties;
import dev.aib.broker.delegations.Delegation.TaskScope;
import dev.aib.broker.policy.ActionRequest.Action;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Evaluates agent requests against the Cedar policies in {@code policies/}. Policies are
 * validated against the schema at startup; the broker refuses to start if they are invalid.
 */
@Component
public class PolicyEngine {

    private static final Logger log = LoggerFactory.getLogger(PolicyEngine.class);

    private static final EntityTypeName AGENT = type("Agent");
    private static final EntityTypeName ORDER = type("Order");
    private static final EntityTypeName CUSTOMER = type("Customer");
    private static final EntityTypeName ACTION = type("Action");

    public enum Outcome { PERMIT, APPROVAL_REQUIRED, DENY }

    /** The outcome, and the policy ids or explanation recorded in the audit log. */
    public record Decision(Outcome outcome, String reason) {}

    private final BasicAuthorizationEngine engine = new BasicAuthorizationEngine();
    private final Schema schema;
    private final PolicySet policies;

    @Autowired
    PolicyEngine(BrokerProperties properties) {
        this(Path.of(properties.policyDir()));
    }

    public PolicyEngine(Path policyDir) {
        try {
            this.schema = Schema.parse(JsonOrCedar.Cedar, Files.readString(policyDir.resolve("schema.cedarschema")));
            this.policies = loadPolicies(policyDir);
            validate();
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read policies from " + policyDir.toAbsolutePath(), e);
        } catch (AuthException e) {
            throw new IllegalStateException("Invalid Cedar policies in " + policyDir.toAbsolutePath(), e);
        }
        log.info("Loaded {} Cedar policies from {}", policies.getNumPolicies(), policyDir.toAbsolutePath());
    }

    /**
     * Evaluates first without human approval. If that is denied but approval would permit
     * it, the request needs approval; otherwise it is denied.
     */
    public Decision evaluate(String agentId, ActionRequest request, TaskScope task) {
        Optional<AuthorizationSuccessResponse> withoutApproval = authorize(agentId, request, task, false);
        if (withoutApproval.isEmpty()) {
            return new Decision(Outcome.DENY, "Policy evaluation failed; denied by default");
        }
        if (withoutApproval.get().isAllowed()) {
            return new Decision(Outcome.PERMIT, "Permitted by " + ids(withoutApproval.get()));
        }
        Optional<AuthorizationSuccessResponse> withApproval = authorize(agentId, request, task, true);
        if (withApproval.isPresent() && withApproval.get().isAllowed()) {
            return new Decision(Outcome.APPROVAL_REQUIRED, "Needs human approval (" + ids(withApproval.get()) + ")");
        }
        Set<String> forbidding = withoutApproval.get().getReason();
        return new Decision(Outcome.DENY, forbidding.isEmpty()
                ? "No policy permits: " + request.describe()
                : "Forbidden by " + String.join(", ", new TreeSet<>(forbidding)));
    }

    /** Re-checks a request a human has approved: permitted only if policy allows it with approval. */
    public Decision evaluateApproved(String agentId, ActionRequest request, TaskScope task) {
        Optional<AuthorizationSuccessResponse> response = authorize(agentId, request, task, true);
        if (response.isPresent() && response.get().isAllowed()) {
            return new Decision(Outcome.PERMIT, "Permitted with human approval by " + ids(response.get()));
        }
        return new Decision(Outcome.DENY, "Policy no longer permits: " + request.describe());
    }

    private Optional<AuthorizationSuccessResponse> authorize(
            String agentId, ActionRequest request, TaskScope task, boolean humanApproved) {
        Map<String, Value> context = new HashMap<>();
        context.put("human_approved", new PrimBool(humanApproved));
        EntityUID resource;
        if (request.action() == Action.LIST) {
            resource = CUSTOMER.of(request.customerId());
            context.put("task_customer", CUSTOMER.of(task.customerId()));
        } else {
            resource = ORDER.of(request.orderId());
            context.put("task_orders", new CedarList(task.orderIds().stream().map(id -> (Value) ORDER.of(id)).toList()));
            context.put("amount_cents", new PrimLong(request.amountCents()));
        }
        AuthorizationRequest cedarRequest = new AuthorizationRequest(
                AGENT.of(agentId), ACTION.of(request.action().type()), resource,
                Optional.of(context), Optional.of(schema), true);
        try {
            AuthorizationResponse response = engine.isAuthorized(cedarRequest, policies, Set.of());
            if (response.success.isEmpty()) {
                log.error("Cedar rejected the request {}: {}", request, response.errors);
                return Optional.empty();
            }
            AuthorizationSuccessResponse success = response.success.get();
            if (!success.getErrors().isEmpty()) {
                // Cedar skips erroring policies, which can silently deny. Fail closed, but loudly.
                log.error("Cedar policy errors for {}: {}", request, success.getErrors());
                return Optional.empty();
            }
            return Optional.of(success);
        } catch (AuthException e) {
            log.error("Cedar evaluation failed for {}", request, e);
            return Optional.empty();
        }
    }

    /** Reads every .cedar file and keys each policy by its required @id annotation. */
    private static PolicySet loadPolicies(Path dir) throws IOException, AuthException {
        String source;
        try (Stream<Path> files = Files.list(dir)) {
            List<Path> cedarFiles = files.filter(p -> p.toString().endsWith(".cedar")).sorted().toList();
            StringBuilder all = new StringBuilder();
            for (Path file : cedarFiles) {
                all.append(Files.readString(file)).append('\n');
            }
            source = all.toString();
        }
        Set<Policy> named = new HashSet<>();
        Set<String> ids = new HashSet<>();
        for (Policy policy : PolicySet.parsePolicies(source).policies) {
            String id = policy.getAnnotation("id");
            if (id == null || id.isBlank()) {
                throw new IllegalStateException("Every policy needs an @id annotation:\n" + policy.getSource());
            }
            if (!ids.add(id)) {
                throw new IllegalStateException("Duplicate policy @id: " + id);
            }
            named.add(new Policy(policy.getSource(), id));
        }
        return new PolicySet(named);
    }

    private void validate() throws AuthException {
        ValidationResponse response = engine.validate(new ValidationRequest(schema, policies));
        if (!response.validationPassed()) {
            throw new IllegalStateException("Cedar policies do not match the schema: " + response);
        }
    }

    private static String ids(AuthorizationSuccessResponse response) {
        return response.getReason().stream().sorted().collect(Collectors.joining(", "));
    }

    private static EntityTypeName type(String name) {
        return EntityTypeName.parse(name).orElseThrow();
    }
}
