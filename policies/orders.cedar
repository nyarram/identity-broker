// Agent permissions for the Orders API. Every policy needs an @id; it is recorded in the
// audit log as the reason for each decision.
//
// The broker evaluates each request with human_approved = false. If that is denied but
// the same request with human_approved = true would be permitted, the request needs a
// human's approval instead of being denied outright.

// Reads are limited to orders in the delegated task
@id("read-task-orders")
permit (principal is Agent, action == Action::"read", resource is Order)
when { context.task_orders.contains(resource) };

// Listing is limited to the task's customer
@id("list-task-customer")
permit (principal is Agent, action == Action::"list", resource is Customer)
when { resource == context.task_customer };

// Refunds on task orders: automatic up to $50, above that only with human approval
@id("refund-task-orders")
permit (principal is Agent, action == Action::"refund", resource is Order)
when {
    context.task_orders.contains(resource) &&
    (context.amount_cents <= 5000 || context.human_approved)
};

// Cancelling a task order always needs a human
@id("cancel-task-orders-with-approval")
permit (principal is Agent, action == Action::"cancel", resource is Order)
when { context.task_orders.contains(resource) && context.human_approved };

// Agents may never delete, whatever else is permitted
@id("never-delete")
forbid (principal, action == Action::"delete", resource);
