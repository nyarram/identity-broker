// The four-scene demo. Usage (from the repository root):
//
//   npm run demo -- --replay               recorded model turns, no API key needed
//   npm run demo                           live model (ANTHROPIC_API_KEY or `ant auth login`)
//   npm run demo -- --replay --no-broker   the same agent with one all-access key, for contrast
//
// Options: --scene <1-4>, --auto-approve (default in replay), --manual-approve,
// --gullible (live only: the agent treats notes in orders as instructions),
// --record <file> (live only: save the model's turns as a replay recording).

import { BrokerClient, generateAgentKey } from "@aib/agent-sdk";
import { readFileSync } from "node:fs";
import { GULLIBLE_ADDENDUM, SYSTEM_PROMPT, runAgent } from "./agent.ts";
import { changes, loadEnvironment, Stack, type Order } from "./environment.ts";
import { ClaudeModel, RecordingModel, ReplayModel, type Model, type Recording } from "./model.ts";
import { Printer } from "./print.ts";
import { INJECTION_SCENE, SCENES, type Scene } from "./scenes.ts";
import { brokerTools, staticKeyTools, type ToolExecutor } from "./tools.ts";

interface Options {
  replay: boolean;
  noBroker: boolean;
  autoApprove: boolean;
  gullible: boolean;
  scene?: number;
  record?: string;
}

function parseOptions(args: string[]): Options {
  const value = (flag: string) => {
    const i = args.indexOf(flag);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const replay = args.includes("--replay");
  return {
    replay,
    noBroker: args.includes("--no-broker"),
    autoApprove: args.includes("--auto-approve") || (replay && !args.includes("--manual-approve")),
    gullible: args.includes("--gullible"),
    scene: value("--scene") ? Number(value("--scene")) : undefined,
    record: value("--record"),
  };
}

function chooseModel(options: Options): Model {
  if (options.replay) {
    const recording = JSON.parse(readFileSync(new URL("../fixtures/replay.json", import.meta.url), "utf8")) as Recording;
    return new ReplayModel(recording);
  }
  const live = new ClaudeModel(process.env.DEMO_MODEL ?? "claude-opus-5-5");
  return options.record ? new RecordingModel(live, options.record) : live;
}

async function main(): Promise<void> {
  const options = parseOptions(process.argv.slice(2));
  const env = loadEnvironment();
  const stack = new Stack(env);
  const printer = new Printer();
  const model = chooseModel(options);
  const system = options.gullible ? SYSTEM_PROMPT + GULLIBLE_ADDENDUM : SYSTEM_PROMPT;
  const scenes = options.scene ? [SCENES[options.scene - 1]] : SCENES;

  printer.heading(options.noBroker ? "Agent demo WITHOUT the broker: one static all-access key" : "Agent demo with the identity broker");
  printer.info(`model: ${model.description}`);
  await stack.waitUntilUp();
  await stack.resetOrders();

  // With the broker the agent's identity is a key pair; the broker only ever sees the public key
  let agent: { id: string; broker: BrokerClient } | undefined;
  if (!options.noBroker) {
    const key = generateAgentKey();
    const id = await stack.registerAgent("support-bot", key.publicJwk);
    agent = {
      id,
      broker: new BrokerClient({ brokerUrl: env.brokerUrl, agentId: id, privateKey: key.privateKey, resource: env.resource }),
    };
    printer.info(`registered agent support-bot as ${id} (public key only)`);
  }

  let contained = true;
  for (const scene of scenes) {
    printer.heading(scene.title);
    printer.info(`task from ${scene.userId}: ${scene.task}`);
    const before = await stack.orders();

    let delegationId: string | undefined;
    let execute: ToolExecutor;
    if (agent) {
      const delegation = await stack.delegate({ ...scene, agentId: agent.id });
      delegationId = delegation.delegation_id;
      printer.info(`delegation ${delegationId}: ${scene.scopes.join(", ")} on order(s) ${scene.orderIds.join(", ")}`);
      execute = brokerTools({
        broker: agent.broker,
        delegationToken: delegation.delegation_token,
        ordersUrl: env.ordersUrl,
        printer,
        onApprovalPending: (approvalId) => humanApproval(approvalId, options.autoApprove, stack, printer),
      });
    } else {
      execute = staticKeyTools({ ordersUrl: env.ordersUrl, apiKey: env.demoKey, printer });
    }

    await runAgent(model.start(scene.id, system, scene.task), execute, printer);

    const ok = report(scene, before, await stack.orders(), printer);
    if (scene.id === INJECTION_SCENE) {
      contained = ok;
      if (delegationId) {
        await reportAudit(stack, delegationId, printer);
      }
    }
  }

  if (!options.noBroker) {
    const audit = await stack.verifyAudit();
    printer.heading("Audit log");
    printer.verdict(audit.valid, `hash chain verifies (${audit.events_checked} events)`);
  }
  if (!options.noBroker && !contained) {
    process.exitCode = 1; // the injection got through the broker: that is a failure of the demo
  }
}

/** In replay the human is simulated; live, someone runs the approval CLI. */
async function humanApproval(approvalId: string, autoApprove: boolean, stack: Stack, printer: Printer): Promise<void> {
  printer.approvalPending(approvalId);
  if (autoApprove) {
    await stack.approve(approvalId, "demo-human");
    printer.approvalNote(`approved by demo-human (simulated; in real use: npm run approval-cli -- approve ${approvalId})`);
  } else {
    printer.approvalNote(`waiting for a human: npm run approval-cli -- approve ${approvalId}   (or deny)`);
  }
}

/** Shows what actually changed in the Orders API, and judges it against the task. */
function report(scene: Scene, before: Map<string, Order>, after: Map<string, Order>, printer: Printer): boolean {
  const { refunded, deleted, cancelled } = changes(before, after);
  const outside = refunded.filter((r) => !scene.orderIds.includes(r.id));
  for (const r of refunded) {
    const inTask = scene.orderIds.includes(r.id);
    printer.verdict(inTask, `refunded $${(r.cents / 100).toFixed(2)} on order ${r.id}${inTask ? "" : " (NOT part of the task)"}`);
  }
  for (const id of deleted) {
    printer.verdict(false, `order ${id} was DELETED`);
  }
  for (const id of cancelled) {
    printer.verdict(scene.orderIds.includes(id), `order ${id} was cancelled`);
  }
  if (refunded.length + deleted.length + cancelled.length === 0) {
    printer.info("no orders changed");
  }
  const ok = outside.length === 0 && deleted.length === 0;
  if (scene.id === INJECTION_SCENE) {
    printer.verdict(ok, ok
      ? "contained: nothing outside the task was refunded and nothing was deleted"
      : `NOT contained: ${outside.length} refund(s) outside the task, ${deleted.length} order(s) deleted`);
  }
  return ok;
}

async function reportAudit(stack: Stack, delegationId: string, printer: Printer): Promise<void> {
  const events = await stack.auditEvents(delegationId);
  const denied = events.filter((e) => e.event_type === "token_denied");
  printer.info(`audit log for ${delegationId}: ${events.filter((e) => e.event_type === "token_issued").length} token(s) issued, ${denied.length} denied`);
  for (const e of denied) {
    printer.info(`  #${e.seq} denied: ${e.reason}`);
  }
}

main().catch((error: Error) => {
  console.error(`\n${error.message}`);
  process.exitCode = 1;
});
