package dev.aib.broker.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.aib.broker.delegations.Delegation.TaskScope;
import dev.aib.broker.policy.ActionRequest.Action;
import dev.aib.broker.policy.PolicyEngine.Decision;
import dev.aib.broker.policy.PolicyEngine.Outcome;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Each rule in policies/orders.cedar, with at least one permit and one deny case. */
class PolicyEngineTest {

    static final Path POLICIES = Path.of("../policies");
    static final PolicyEngine engine = new PolicyEngine(POLICIES);
    static final TaskScope TASK = new TaskScope("cust_alice", List.of("1042", "1043"));

    static Decision decide(Action action, String orderId, long amountCents) {
        return engine.evaluate("agt_1", new ActionRequest(action, orderId, null, amountCents), TASK);
    }

    @Nested
    class Read {
        @Test
        void permitsTaskOrders() {
            assertThat(decide(Action.READ, "1042", 0)).isEqualTo(
                    new Decision(Outcome.PERMIT, "Permitted by read-task-orders"));
        }

        @Test
        void deniesOrdersOutsideTheTask() {
            Decision decision = decide(Action.READ, "1050", 0);
            assertThat(decision.outcome()).isEqualTo(Outcome.DENY);
            assertThat(decision.reason()).isEqualTo("No policy permits: read order 1050");
        }
    }

    @Nested
    class List_ {
        @Test
        void permitsTheTaskCustomer() {
            Decision decision = engine.evaluate("agt_1", new ActionRequest(Action.LIST, null, "cust_alice", 0), TASK);
            assertThat(decision.outcome()).isEqualTo(Outcome.PERMIT);
            assertThat(decision.reason()).contains("list-task-customer");
        }

        @Test
        void deniesOtherCustomers() {
            Decision decision = engine.evaluate("agt_1", new ActionRequest(Action.LIST, null, "cust_bob", 0), TASK);
            assertThat(decision.outcome()).isEqualTo(Outcome.DENY);
        }
    }

    @Nested
    class Refund {
        @Test
        void permitsUpToFiftyDollarsAutomatically() {
            assertThat(decide(Action.REFUND, "1042", 3000).outcome()).isEqualTo(Outcome.PERMIT);
            assertThat(decide(Action.REFUND, "1042", 5000).outcome()).isEqualTo(Outcome.PERMIT);
        }

        @Test
        void needsApprovalAboveFiftyDollars() {
            Decision decision = decide(Action.REFUND, "1042", 5001);
            assertThat(decision.outcome()).isEqualTo(Outcome.APPROVAL_REQUIRED);
            assertThat(decision.reason()).contains("refund-task-orders");
        }

        @Test
        void deniesOrdersOutsideTheTaskEvenWithApproval() {
            assertThat(decide(Action.REFUND, "1050", 3000).outcome()).isEqualTo(Outcome.DENY);
            assertThat(decide(Action.REFUND, "1050", 12000).outcome()).isEqualTo(Outcome.DENY);
        }
    }

    @Nested
    class Cancel {
        @Test
        void needsApprovalForTaskOrders() {
            assertThat(decide(Action.CANCEL, "1042", 0).outcome()).isEqualTo(Outcome.APPROVAL_REQUIRED);
        }

        @Test
        void deniesOrdersOutsideTheTask() {
            assertThat(decide(Action.CANCEL, "1050", 0).outcome()).isEqualTo(Outcome.DENY);
        }
    }

    @Nested
    class Delete {
        @Test
        void isForbiddenEvenForTaskOrdersAndWithApproval() {
            Decision decision = decide(Action.DELETE, "1042", 0);
            // Not APPROVAL_REQUIRED: a forbid cannot be overridden by a human
            assertThat(decision).isEqualTo(new Decision(Outcome.DENY, "Forbidden by never-delete"));
        }
    }

    @Nested
    class Loading {
        @Test
        void rejectsPoliciesThatDoNotMatchTheSchema(@TempDir Path dir) throws IOException {
            copySchema(dir);
            // The bug from the original spec: entity ids are not attributes
            Files.writeString(dir.resolve("bad.cedar"), """
                    @id("bad")
                    permit (principal is Agent, action == Action::"read", resource is Order)
                    when { context.task_orders.contains(resource.id) };
                    """);
            assertThatThrownBy(() -> new PolicyEngine(dir)).hasMessageContaining("do not match the schema");
        }

        @Test
        void requiresAnIdOnEveryPolicy(@TempDir Path dir) throws IOException {
            copySchema(dir);
            Files.writeString(dir.resolve("anon.cedar"), "forbid (principal, action, resource);");
            assertThatThrownBy(() -> new PolicyEngine(dir)).hasMessageContaining("@id");
        }

        private static void copySchema(Path dir) throws IOException {
            Files.copy(POLICIES.resolve("schema.cedarschema"), dir.resolve("schema.cedarschema"));
        }
    }
}
