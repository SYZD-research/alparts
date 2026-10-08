import { availableParallelism } from 'node:os';
import * as mediasoup from 'mediasoup';
import type { types } from 'mediasoup';

export class VoiceWorkerManager {
	private readonly workers: types.Worker[] = [];
	private nextWorkerIndex = 0;

	async start(count = availableParallelism()): Promise<void> {
		if (this.workers.length > 0) {
			throw new Error('VOICE_WORKERS_ALREADY_STARTED');
		}

		if (!Number.isSafeInteger(count) || count < 1) {
			throw new Error('INVALID_VOICE_WORKER_COUNT');
		}

		try {
			for (let i = 0; i < count; i++) {
				const worker = await mediasoup.createWorker({
					logLevel: 'warn',
				});

				worker.on('died', (error) => {
					console.error(`Voice worker ${worker.pid} died`, error);
					process.exitCode = 1;
					process.kill(process.pid, 'SIGTERM');
				});

				this.workers.push(worker);
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

		const worker = this.workers[this.nextWorkerIndex];
		this.nextWorkerIndex = (this.nextWorkerIndex + 1) % this.workers.length;

		return worker;
	}

	close(): void {
		for (const worker of this.workers) {
			worker.close();
		}

		this.workers.length = 0;
		this.nextWorkerIndex = 0;
	}
}
