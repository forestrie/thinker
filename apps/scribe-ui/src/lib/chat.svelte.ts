import { AgentClient } from 'agents/client';
import { buildUserEnvelope, newTurnClaims, workIdOf } from './envelope.ts';
import { postTurn, scribeBase, ScribeApiError } from './scribe-api.ts';
import type { ScribeSession } from './session.svelte.ts';
import type { DemoWallet } from './wallet.svelte.ts';
import type { TurnVault } from './vault.svelte.ts';
import { bytesToB64 } from './utils.ts';

/**
 * The chat protocol constants from `agents/chat` (MessageType). Inlined:
 * the enum is the stable wire protocol `useAgentChat` speaks, and importing
 * the React-adjacent module would drag the whole ai-sdk surface into the
 * client bundle for six strings.
 */
const MSG = {
	CHAT_CLEAR: 'cf_agent_chat_clear',
	CHAT_MESSAGES: 'cf_agent_chat_messages',
	CHAT_RESPONSE: 'cf_agent_use_chat_response',
	MESSAGE_UPDATED: 'cf_agent_message_updated',
	STREAM_RESUMING: 'cf_agent_stream_resuming',
	STREAM_RESUME_NONE: 'cf_agent_stream_resume_none',
	STREAM_PENDING: 'cf_agent_stream_pending',
	CHAT_RECOVERING: 'cf_agent_chat_recovering',
	STREAM_RESUME_ACK: 'cf_agent_stream_resume_ack',
	STREAM_RESUME_REQUEST: 'cf_agent_stream_resume_request'
} as const;

/** A rendered message part — the projection of UIMessage parts we display. */
export interface ChatPart {
	type: 'text' | 'reasoning' | 'tool';
	text?: string;
	toolCallId?: string;
	toolName?: string;
	input?: unknown;
	output?: unknown;
	state?: 'input-streaming' | 'input-available' | 'output-available' | 'output-error';
	errorText?: string;
}

export interface ChatMessage {
	id: string;
	role: 'user' | 'assistant' | 'system';
	parts: ChatPart[];
	/** Set on user messages we submitted attested (local echo only). */
	workId?: string;
	streaming?: boolean;
}

/** One AI-SDK UI stream chunk, as carried in a CHAT_RESPONSE frame body. */
interface StreamChunk {
	type: string;
	id?: string;
	delta?: string;
	messageId?: string;
	toolCallId?: string;
	toolName?: string;
	input?: unknown;
	inputTextDelta?: string;
	output?: unknown;
	errorText?: string;
	[key: string]: unknown;
}

interface ServerUIMessage {
	id: string;
	role: 'user' | 'assistant' | 'system';
	parts?: Array<Record<string, unknown>>;
}

function projectServerMessage(message: ServerUIMessage): ChatMessage {
	const parts: ChatPart[] = [];
	for (const part of message.parts ?? []) {
		const type = String(part.type ?? '');
		if (type === 'text' && typeof part.text === 'string') {
			parts.push({ type: 'text', text: part.text });
		} else if (type === 'reasoning' && typeof part.text === 'string') {
			parts.push({ type: 'reasoning', text: part.text });
		} else if (type.startsWith('tool-') || type === 'dynamic-tool') {
			parts.push({
				type: 'tool',
				toolCallId: typeof part.toolCallId === 'string' ? part.toolCallId : undefined,
				toolName:
					typeof part.toolName === 'string'
						? part.toolName
						: type.startsWith('tool-')
							? type.slice('tool-'.length)
							: 'tool',
				input: part.input,
				output: part.output,
				state: typeof part.state === 'string' ? (part.state as ChatPart['state']) : undefined,
				errorText: typeof part.errorText === 'string' ? part.errorText : undefined
			});
		}
	}
	return { id: message.id, role: message.role, parts };
}

/**
 * Svelte-runes wrapper over the framework-agnostic `agents/client`
 * AgentClient (plan §5.1) — re-implements the slice of `useAgentChat` the
 * Scribe needs. One deliberate divergence from the starter: turns are NEVER
 * sent as `cf_agent_use_chat_request`. The user's input enters via
 * HTTP POST /turn as a signed KS256 envelope (M3 attested admission); the
 * WebSocket is read-mostly — transcript sync on connect, live stream
 * broadcast while the server-admitted turn runs, and the resume handshake
 * (`STREAM_RESUMING` → ACK) for streams that started before we connected.
 */
export class ScribeChat {
	#session: ScribeSession;
	#wallet: DemoWallet;
	#vault: TurnVault;
	#client: AgentClient | null = null;
	/**
	 * In-flight streamed assistant messages, keyed by requestId. Private
	 * bookkeeping, never read from a template: the reactive surface is
	 * `messages`, and each stream mutates the $state message object it points
	 * at. A SvelteMap here would add reactivity nothing subscribes to.
	 */
	// eslint-disable-next-line svelte/prefer-svelte-reactivity
	#streams = new Map<string, ChatMessage>();

	/** The chat session id carried in every envelope's claims. */
	readonly sessionId = crypto.randomUUID();

	messages = $state<ChatMessage[]>([]);
	connection = $state<'idle' | 'connecting' | 'connected' | 'error'>('idle');
	connectionDetail = $state<string | null>(null);
	recovering = $state(false);
	/** True while a turn we submitted is awaiting its stream/completion. */
	awaiting = $state(false);
	turnError = $state<string | null>(null);
	/** Fires after a turn completes — the proof panel refreshes on it. */
	onTurnSettled: (() => void) | null = null;

	constructor(session: ScribeSession, wallet: DemoWallet, vault: TurnVault) {
		this.#session = session;
		this.#wallet = wallet;
		this.#vault = vault;
	}

	get streamingMessages(): ChatMessage[] {
		return [...this.#streams.values()];
	}

	async connect(): Promise<void> {
		if (this.#client) return;
		const token = await this.#session.ensure();
		const sub = this.#session.sub!;
		this.connection = 'connecting';

		// Same-origin (vite proxy / co-deploy) unless PUBLIC_SCRIBE_BASE
		// points elsewhere. partysocket re-evaluates the query factory on
		// every reconnect, so the bearer stays fresh across renewals.
		const client = new AgentClient({
			agent: 'scribe',
			name: `user-${sub}`,
			host: scribeBase() || location.host,
			query: async () => ({ token: await this.#session.ensure() }),
			onConnectionError: (error) => {
				this.connection = 'error';
				this.connectionDetail = `${error.code} ${error.reason || 'connection refused'}`;
			}
		});
		void token;

		client.addEventListener('open', () => {
			this.connection = 'connected';
			this.connectionDetail = null;
			// Ask the server whether a stream is live for us (deploy/reload
			// mid-turn) — it answers STREAM_RESUMING or STREAM_RESUME_NONE.
			client.send(
				JSON.stringify({ type: MSG.STREAM_RESUME_REQUEST, probeId: crypto.randomUUID() })
			);
		});
		client.addEventListener('close', () => {
			if (this.connection !== 'error') this.connection = 'connecting';
		});
		client.addEventListener('message', (event) => {
			if (typeof event.data === 'string') this.#onFrame(event.data);
		});
		this.#client = client;
	}

	disconnect(): void {
		this.#client?.close();
		this.#client = null;
		this.connection = 'idle';
	}

	#onFrame(raw: string): void {
		let frame: Record<string, unknown>;
		try {
			frame = JSON.parse(raw) as Record<string, unknown>;
		} catch {
			return;
		}
		switch (frame.type) {
			case MSG.CHAT_MESSAGES: {
				// Authoritative transcript sync (connect + each persist): our
				// local echoes and finished streams are superseded wholesale.
				const list = (frame.messages ?? []) as ServerUIMessage[];
				this.messages = list.map(projectServerMessage);
				for (const [requestId, msg] of this.#streams)
					if (!msg.streaming) this.#streams.delete(requestId);
				break;
			}
			case MSG.CHAT_RESPONSE: {
				const requestId = String(frame.id ?? '');
				if (frame.error) {
					this.turnError = String(frame.body ?? 'turn failed');
					this.#streams.delete(requestId);
					this.awaiting = false;
					break;
				}
				if (typeof frame.body === 'string' && frame.body.length > 0)
					this.#applyChunkBody(requestId, frame.body);
				if (frame.done) this.#finishStream(requestId);
				break;
			}
			case MSG.MESSAGE_UPDATED: {
				const updated = frame.message as ServerUIMessage | undefined;
				if (!updated) break;
				const projected = projectServerMessage(updated);
				const at = this.messages.findIndex((m) => m.id === projected.id);
				if (at >= 0) this.messages[at] = projected;
				else this.messages.push(projected);
				break;
			}
			case MSG.STREAM_RESUMING: {
				const id = String(frame.id ?? '');
				this.#client?.send(JSON.stringify({ type: MSG.STREAM_RESUME_ACK, id }));
				break;
			}
			case MSG.CHAT_RECOVERING:
				this.recovering = frame.recovering === true;
				break;
			case MSG.CHAT_CLEAR:
				this.messages = [];
				this.#streams.clear();
				break;
			default:
				// STREAM_RESUME_NONE / STREAM_PENDING / unknown: nothing to do.
				break;
		}
	}

	#stream(requestId: string): ChatMessage {
		let msg = this.#streams.get(requestId);
		if (!msg) {
			msg = { id: requestId, role: 'assistant', parts: [], streaming: true };
			this.#streams.set(requestId, msg);
			// Trigger reactivity: #streams is not itself reactive, streaming
			// messages surface through this derived-from state counter.
			this.streamTick++;
		}
		return msg;
	}

	/** Bumped on stream mutation so derived render state re-evaluates. */
	streamTick = $state(0);

	#applyChunkBody(requestId: string, body: string): void {
		let chunk: StreamChunk;
		try {
			chunk = JSON.parse(body) as StreamChunk;
		} catch {
			return;
		}
		const msg = this.#stream(requestId);
		const partId = chunk.id ?? 'default';
		switch (chunk.type) {
			case 'start':
				if (chunk.messageId) msg.id = chunk.messageId;
				break;
			case 'text-start':
				msg.parts.push({ type: 'text', text: '', toolCallId: partId });
				break;
			case 'text-delta': {
				let part = msg.parts.findLast((p) => p.type === 'text' && p.toolCallId === partId);
				part ??= msg.parts.findLast((p) => p.type === 'text');
				if (!part) {
					part = { type: 'text', text: '', toolCallId: partId };
					msg.parts.push(part);
				}
				part.text = (part.text ?? '') + (chunk.delta ?? '');
				break;
			}
			case 'reasoning-start':
				msg.parts.push({ type: 'reasoning', text: '', toolCallId: partId });
				break;
			case 'reasoning-delta': {
				const part = msg.parts.findLast((p) => p.type === 'reasoning');
				if (part) part.text = (part.text ?? '') + (chunk.delta ?? '');
				break;
			}
			case 'tool-input-start':
				msg.parts.push({
					type: 'tool',
					toolCallId: chunk.toolCallId,
					toolName: chunk.toolName,
					state: 'input-streaming'
				});
				break;
			case 'tool-input-available': {
				const part = msg.parts.find((p) => p.type === 'tool' && p.toolCallId === chunk.toolCallId);
				if (part) {
					part.input = chunk.input;
					part.state = 'input-available';
				} else {
					msg.parts.push({
						type: 'tool',
						toolCallId: chunk.toolCallId,
						toolName: chunk.toolName,
						input: chunk.input,
						state: 'input-available'
					});
				}
				break;
			}
			case 'tool-output-available': {
				const part = msg.parts.find((p) => p.type === 'tool' && p.toolCallId === chunk.toolCallId);
				if (part) {
					part.output = chunk.output;
					part.state = 'output-available';
				}
				break;
			}
			case 'tool-output-error': {
				const part = msg.parts.find((p) => p.type === 'tool' && p.toolCallId === chunk.toolCallId);
				if (part) {
					part.state = 'output-error';
					part.errorText = chunk.errorText;
				}
				break;
			}
			case 'error':
				this.turnError = chunk.errorText ?? 'stream error';
				break;
			default:
				// start-step/finish-step/finish/data-*: no visual projection.
				break;
		}
		this.streamTick++;
	}

	#finishStream(requestId: string): void {
		const msg = this.#streams.get(requestId);
		if (msg) {
			msg.streaming = false;
			// Promote to the transcript now; the authoritative CHAT_MESSAGES
			// broadcast that follows persist replaces it by wholesale sync.
			if (!this.messages.some((m) => m.id === msg.id)) this.messages.push(msg);
			this.#streams.delete(requestId);
			this.streamTick++;
		}
		this.awaiting = false;
		this.onTurnSettled?.();
	}

	/**
	 * The attested turn (plan §7, redacted in D1): sign a commitment to the
	 * input client-side, submit `{envelope, input}` over HTTP, and let the
	 * stream arrive over the socket. Returns the turn's workId =
	 * SHA-256(envelope).
	 *
	 * The opening is kept locally BEFORE the submit: what makes the commitment
	 * meaningful is that the user can open it later, and a turn that succeeds
	 * on the server while the browser forgot its plaintext is a proof nobody
	 * can read (D4).
	 */
	async sendTurn(input: string): Promise<string> {
		const token = await this.#session.ensure();
		const sub = this.#session.sub!;
		this.turnError = null;
		this.awaiting = true;

		const claims = newTurnClaims(input, this.sessionId);
		const envelope = buildUserEnvelope(claims, this.#wallet);
		const workId = await workIdOf(envelope);
		const envelopeB64 = bytesToB64(envelope);
		this.#vault.keep({ workId, input, envelopeB64, at: Date.now() });
		this.messages.push({
			id: `local-${workId.slice(0, 12)}`,
			role: 'user',
			parts: [{ type: 'text', text: input }],
			workId
		});
		try {
			const admitted = await postTurn(sub, token, envelopeB64, input);
			if (!admitted.accepted) throw new Error(`turn not accepted: ${admitted.status}`);
			return workId;
		} catch (err) {
			// 402 = prepaid batch spent (W4c): the DO refused the turn and is
			// already re-requesting a grant — the proof panel's poll picks up
			// the fresh challenge (or the top-up button kicks it).
			// 429 = a daily demo-turn cap: a time-boxed bound the wallet cannot top
			// up, so do NOT point at the proof panel.
			if (err instanceof ScribeApiError && err.status === 402) {
				this.turnError = 'Prepaid turns exhausted — top up in the proof panel to continue.';
			} else if (err instanceof ScribeApiError && err.status === 429) {
				this.turnError =
					'Daily demo-turn cap reached — this shared demo is rate-limited today. Please try again tomorrow.';
			} else {
				this.turnError = String(err);
			}
			this.awaiting = false;
			this.onTurnSettled?.();
			throw err;
		}
	}
}
