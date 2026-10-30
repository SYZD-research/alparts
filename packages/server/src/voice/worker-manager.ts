import { availableParallelism } from 'node:os';
import * as mediasoup from 'mediasoup';
import type { types } from 'mediasoup';

/** Delay before replacing a worker that died, doubled after each failed attempt up to the maximum. */
const REPLACE_DELAY_MS = 1_000;
const MAX_REPLACE_DELAY_MS = 60_000;

export type VoiceWorkerFactory = () => Promise<types.Worker>;

const createWorker: VoiceWorkerFactory = () => mediasoup.createWorker({ logLevel: 'warn' });

/**
 * The media worker processes. A worker that dies takes only its own calls
 * down: it is left out of new calls and replaced in the background, and the
 * rest keep running.
 */
export class VoiceWorkerManager {
	private readonly workers: types.Worker[] = [];
	private readonly replacements = new Set<ReturnType<typeof setTimeout>>();
	private nextWorkerIndex = 0;
	private started = false;
	private closed = false;

	constructor(private readonly create: VoiceWorkerFactory = createWorker) {}

	async start(count = availableParallelism()): Promise<void> {
		if (this.started) {
			throw new Error('VOICE_WORKERS_ALREADY_STARTED');
		}

		if (!Number.isSafeInteger(count) || count < 1) {
			throw new Error('INVALID_VOICE_WORKER_COUNT');
		}

		this.started = true;

		try {
			for (let i = 0; i < count; i++) {
				this.add(await this.create());
			}
		} catch (error) {
			this.close();
			throw error;
		}
	}

	getWorker(): types.Worker {
		if (this.workers.length === 0) {
			throw new Error('VOICE_WORKERS_NOT_STARTED');
		}

		this.nextWorkerIndex %= this.workers.length;
		const worker = this.workers[this.nextWorkerIndex];
		this.nextWorkerIndex = (this.nextWorkerIndex + 1) % this.workers.length;

		return worker;
	}

	close(): void {
		this.closed = true;

		for (const timer of this.replacements) {
			clearTimeout(timer);
		}

		this.replacements.clear();

		for (const worker of this.workers) {
			worker.close();
		}

		this.workers.length = 0;
		this.nextWorkerIndex = 0;
	}

	private add(worker: types.Worker): void {
		if (this.closed) {
			worker.close();
			throw new Error('VOICE_WORKERS_CLOSED');
		}

		worker.on('died', (error) => {
			console.error(`Voice worker ${worker.pid} died`, error);
			this.remove(worker);
			this.replace(REPLACE_DELAY_MS);
		});

		this.workers.push(worker);
	}

	private remove(worker: types.Worker): void {
		const index = this.workers.indexOf(worker);

		if (index !== -1) {
			this.workers.splice(index, 1);
		}
	}

	private replace(delay: number): void {
		if (this.closed) {
			return;
		}

		const timer = setTimeout(() => {
			this.replacements.delete(timer);

			if (this.closed) {
				return;
			}

			this.create().then(
				(worker) => {
					try {
						this.add(worker);
					} catch {
						// Closed meanwhile; add() has closed the worker.
					}
				},
				(error) => {
					console.error('Voice worker could not be replaced', error);
					this.replace(Math.min(delay * 2, MAX_REPLACE_DELAY_MS));
				},
			);
		}, delay);

		this.replacements.add(timer);
	}
}
