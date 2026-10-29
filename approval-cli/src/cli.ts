#!/usr/bin/env -S npx tsx
// The human in the loop: list, approve or deny agent requests that policy sends for approval.
//
//   approval-cli list
//   approval-cli approve <approval_id> [--as <name>]
//   approval-cli deny <approval_id> [--as <name>]
//
// Env: BROKER_URL (default http://localhost:9000), BROKER_ADMIN_TOKEN.

const BROKER = process.env.BROKER_URL ?? "http://localhost:9000";
const ADMIN_TOKEN = process.env.BROKER_ADMIN_TOKEN ?? "dev-admin-token-not-for-production";

interface ApprovalView {
  approval_id: string;
  status: string;
  agent_id: string;
  agent_name: string | null;
  user_id: string;
  task_description: string | null;
  action: { type: string; order_id?: string; customer_id?: string; max_amount_cents?: number };
  policy_reason: string | null;
  created_at: string;
  expires_at: string;
  decided_by: string | null;
}

/** Says in plain words what approving would allow, which is what makes the approval meaningful. */
export function describeAction(action: ApprovalView["action"]): string {
  switch (action.type) {
    case "refund":
      return `Refund up to $${((action.max_amount_cents ?? 0) / 100).toFixed(2)} on order ${action.order_id}`;
    case "list":
      return `List all orders of customer ${action.customer_id}`;
    default:
      return `${action.type[0].toUpperCase()}${action.type.slice(1)} order ${action.order_id}`;
  }
}

function minutesLeft(expiresAt: string): string {
  const seconds = Math.max(0, Math.round((Date.parse(expiresAt) - Date.now()) / 1000));
  return `${Math.floor(seconds / 60)}m${String(seconds % 60).padStart(2, "0")}s`;
}

async function admin(method: string, path: string, body?: object): Promise<unknown> {
  const response = await fetch(`${BROKER}${path}`, {
    method,
    headers: { Authorization: `Bearer ${ADMIN_TOKEN}`, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await response.json();
  if (!response.ok) {
    throw new Error(`${response.status} ${json.error ?? ""}: ${json.error_description ?? JSON.stringify(json)}`);
  }
  return json;
}

function print(a: ApprovalView): void {
  console.log(`${a.approval_id}  [${a.status}]  expires in ${minutesLeft(a.expires_at)}`);
  console.log(`  ${describeAction(a.action)}`);
  console.log(`  requested by agent ${a.agent_name ?? "?"} (${a.agent_id}) acting for user ${a.user_id}`);
  if (a.task_description) {
    console.log(`  task: "${a.task_description}"`);
  }
  if (a.policy_reason) {
    console.log(`  policy: ${a.policy_reason}`);
  }
}

async function main(args: string[]): Promise<void> {
  const [command, id] = args;
  const asIndex = args.indexOf("--as");
  const decidedBy = asIndex >= 0 ? args[asIndex + 1] : process.env.USER;

  switch (command) {
    case "list": {
      const pending = (await admin("GET", "/admin/approvals")) as ApprovalView[];
      if (pending.length === 0) {
        console.log("No pending approvals.");
      }
      pending.forEach((a, i) => {
        if (i > 0) console.log();
        print(a);
      });
      return;
    }
    case "approve":
    case "deny": {
      if (!id) {
        throw new Error(`Usage: approval-cli ${command} <approval_id> [--as <name>]`);
      }
      const decided = (await admin("POST", `/admin/approvals/${encodeURIComponent(id)}/${command}`, {
        decided_by: decidedBy,
      })) as ApprovalView;
      console.log(`${command === "approve" ? "Approved" : "Denied"}: ${describeAction(decided.action)} (${decided.approval_id})`);
      return;
    }
    default:
      console.log("Usage: approval-cli list | approve <approval_id> | deny <approval_id> [--as <name>]");
      process.exitCode = command ? 1 : 0;
  }
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("cli.ts")) {
  main(process.argv.slice(2)).catch((error: Error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
