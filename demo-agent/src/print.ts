import type { Action, BrokerError } from "@aib/agent-sdk";
import type { ToolResult } from "./tools.ts";

const useColor = !process.env.NO_COLOR && process.stdout.isTTY;
const paint = (code: number) => (text: string) => (useColor ? `\x1b[${code}m${text}\x1b[0m` : text);
const bold = paint(1);
const dim = paint(2);
const red = paint(31);
const green = paint(32);
const yellow = paint(33);
const cyan = paint(36);

function describe(action: Action): string {
  switch (action.type) {
    case "refund":
      return `refund up to $${(action.max_amount_cents / 100).toFixed(2)} on order ${action.order_id}`;
    case "list":
      return `list orders of ${action.customer_id}`;
    default:
      return `${action.type} order ${action.order_id}`;
  }
}

function shorten(text: string, max = 160): string {
  const oneLine = text.replace(/\s+/g, " ");
  return oneLine.length > max ? `${oneLine.slice(0, max)}...` : oneLine;
}

/** A readable transcript of what the agent, the broker and the API did. */
export class Printer {
  heading(text: string): void {
    console.log(`\n${bold(text)}`);
  }

  info(text: string): void {
    console.log(dim(`  ${text}`));
  }

  agentSays(text: string): void {
    for (const line of text.trim().split("\n")) {
      console.log(`  ${cyan("agent")}  ${line}`);
    }
  }

  toolCall(name: string, input: Record<string, unknown>): void {
    console.log(`  ${bold("tool")}   ${name} ${JSON.stringify(input)}`);
  }

  tokenIssued(action: Action, expiresAt: Date): void {
    const seconds = Math.round((expiresAt.getTime() - Date.now()) / 1000);
    console.log(`         ${green("broker: token issued")} for ${describe(action)} ${dim(`(expires in ${seconds}s)`)}`);
  }

  tokenDenied(error: BrokerError): void {
    console.log(`         ${red(`broker: DENIED ${error.code}`)} ${error.description}`);
  }

  approvalPending(approvalId: string): void {
    console.log(`         ${yellow("broker: needs human approval")} ${approvalId}`);
  }

  approvalNote(text: string): void {
    console.log(`         ${yellow(text)}`);
  }

  apiResult(result: ToolResult): void {
    const label = result.isError ? red("api:") : dim("api:");
    console.log(`         ${label} ${dim(shorten(result.content))}`);
  }

  verdict(ok: boolean, text: string): void {
    console.log(`  ${ok ? green("✔") : red("✘")} ${text}`);
  }
}
