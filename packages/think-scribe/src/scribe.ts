import { createAnthropic } from "@ai-sdk/anthropic";
import { Think, type ThinkModel } from "@cloudflare/think";

/**
 * Bindings the Scribe needs from its hosting Worker. The app's generated
 * `Env` (wrangler types) must be assignable to this.
 */
export interface ScribeEnv extends Cloudflare.Env {
  /** Anthropic API key (secret: .dev.vars locally, `wrangler secret put` in prod). */
  ANTHROPIC_API_KEY: string;
  /** Model override; defaults to claude-sonnet-5 (plan §11 O2). */
  MODEL_ID?: string;
}

export const DEFAULT_MODEL_ID = "claude-sonnet-5";

/**
 * The Scribe — a per-user Think agent (Option B: one DO instance per user)
 * that will produce a tamper-evident, externally verifiable record of the
 * conversation: the user attests to their input, the agent attests to its
 * own choices and outputs (plan §2).
 *
 * M0: a bare Think DO streaming chat via Anthropic. The Forestrie commitment
 * path (keys/, forestrie/, attestation) lands in M1–M3 through the
 * `onStepFinish` → enqueue → drain seam; nothing is signed or registered
 * inline in the chat loop.
 */
export class Scribe<Env extends ScribeEnv = ScribeEnv> extends Think<Env> {
  /**
   * Anthropic via the AI-SDK provider (plan §11 O2). Swappable by design:
   * subclasses or later milestones may return any AI-SDK `LanguageModel`
   * or a Workers-AI / AI-Gateway model id string.
   *
   * Sonnet 5 note: sampling params (`temperature`/`top_p`) are rejected by
   * the model — steer with the system prompt, not sampling.
   */
  getModel(): ThinkModel {
    const anthropic = createAnthropic({ apiKey: this.env.ANTHROPIC_API_KEY });
    return anthropic(this.env.MODEL_ID ?? DEFAULT_MODEL_ID);
  }

  getSystemPrompt(): string {
    return [
      "You are the Scribe, a careful assistant whose conversation is",
      "committed to a public transparency log: the user signs their input,",
      "and you sign your own choices and outputs. Only hashes are logged —",
      "never the transcript itself. Answer plainly and note, when asked,",
      "that this conversation is being made tamper-evident.",
    ].join(" ");
  }
}
