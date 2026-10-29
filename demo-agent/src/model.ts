import Anthropic from "@anthropic-ai/sdk";
import { writeFileSync } from "node:fs";
import { TOOLS } from "./tools.ts";

export interface ToolCall {
  id: string;
  name: string;
  input: Record<string, unknown>;
}

/** One model response, reduced to what the agent loop needs. */
export interface ModelTurn {
  text: string;
  toolCalls: ToolCall[];
  stop: "end_turn" | "tool_use" | "refusal" | "max_tokens" | "other";
}

export interface ToolOutcome {
  id: string;
  content: string;
  isError: boolean;
}

export interface Conversation {
  /** Sends the results of the previous turn's tool calls (none on the first turn) and returns the next turn. */
  next(results?: ToolOutcome[]): Promise<ModelTurn>;
}

export interface Model {
  readonly description: string;
  start(sceneId: string, system: string, task: string): Conversation;
}

/** A live Claude model, via the Anthropic SDK. */
export class ClaudeModel implements Model {
  private readonly client = new Anthropic();

  constructor(private readonly model: string) {}

  get description(): string {
    return `live: ${this.model}`;
  }

  start(_sceneId: string, system: string, task: string): Conversation {
    const messages: Anthropic.Beta.Messages.BetaMessageParam[] = [{ role: "user", content: task }];
    const tools: Anthropic.Beta.Messages.BetaTool[] = TOOLS.map((tool) => ({
      name: tool.name,
      description: tool.description,
      input_schema: tool.inputSchema,
      strict: true,
    }));

    return {
      next: async (results) => {
        if (results?.length) {
          messages.push({
            role: "user",
            content: results.map((r) => ({ type: "tool_result", tool_use_id: r.id, content: r.content, is_error: r.isError })),
          });
        }
        const response = await this.client.beta.messages.create({
          model: this.model,
          max_tokens: 16000,
          // If a safety classifier declines, the API retries on Anthropic's recommended fallback model
          betas: ["server-side-fallback-2026-07-01"],
          fallbacks: "default",
          system,
          tools,
          messages,
        });
        // Append the whole content, thinking blocks included, so the next request is valid
        messages.push({ role: "assistant", content: response.content });

        const text = response.content
          .filter((b): b is Anthropic.Beta.Messages.BetaTextBlock => b.type === "text")
          .map((b) => b.text)
          .join("\n");
        const toolCalls = response.content
          .filter((b): b is Anthropic.Beta.Messages.BetaToolUseBlock => b.type === "tool_use")
          .map((b) => ({ id: b.id, name: b.name, input: b.input as Record<string, unknown> }));
        const stop = ["end_turn", "tool_use", "refusal", "max_tokens"].includes(String(response.stop_reason))
          ? (response.stop_reason as ModelTurn["stop"])
          : "other";
        return { text, toolCalls, stop };
      },
    };
  }
}

/** A recorded turn: what the model said and which tools it called. */
export interface RecordedTurn {
  text?: string;
  tool_calls?: Array<{ name: string; input: Record<string, unknown> }>;
}

export type Recording = Record<string, RecordedTurn[]>;

/**
 * Replays recorded model turns, so the demo is deterministic and needs no API key. The
 * model's side is scripted; every tool call still goes through the real broker and API.
 */
export class ReplayModel implements Model {
  readonly description = "replay: recorded model turns";

  constructor(private readonly recording: Recording) {}

  start(sceneId: string): Conversation {
    const turns = [...(this.recording[sceneId] ?? [])];
    let callCount = 0;
    return {
      next: async () => {
        const turn = turns.shift();
        if (!turn) {
          return { text: "", toolCalls: [], stop: "end_turn" };
        }
        const toolCalls = (turn.tool_calls ?? []).map((c) => ({ id: `call_${++callCount}`, name: c.name, input: c.input }));
        return { text: turn.text ?? "", toolCalls, stop: toolCalls.length ? "tool_use" : "end_turn" };
      },
    };
  }
}

/** Wraps a live model and saves its turns, to create or refresh a replay recording. */
export class RecordingModel implements Model {
  private readonly recording: Recording = {};

  constructor(
    private readonly inner: Model,
    private readonly path: string,
  ) {}

  get description(): string {
    return `${this.inner.description}, recording to ${this.path}`;
  }

  start(sceneId: string, system: string, task: string): Conversation {
    const conversation = this.inner.start(sceneId, system, task);
    const turns: RecordedTurn[] = (this.recording[sceneId] = []);
    return {
      next: async (results) => {
        const turn = await conversation.next(results);
        turns.push({ text: turn.text || undefined, tool_calls: turn.toolCalls.map(({ name, input }) => ({ name, input })) });
        writeFileSync(this.path, JSON.stringify(this.recording, null, 2) + "\n");
        return turn;
      },
    };
  }
}
