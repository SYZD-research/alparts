
import type { types } from 'mediasoup';
import { VoiceWorkerManager } from './worker-manager.js';

const AUDIO_CODECS: types.RouterRtpCodecCapability[] = [
	{
		kind: 'audio',
		mimeType: 'audio/opus',
		clockRate: 48000,
		channels: 2,
	},
];

export class VoiceRouterManager {
	private readonly routers = new Map<string, types.Router[]>();
	private readonly pending = new Map<string, Promise<types.Router>>();

	constructor(private readonly workers: VoiceWorkerManager) {}

	async createRouter(channelId: string): Promise<types.Router> {
		if (!channelId) {
			throw new Error('INVALID_VOICE_CHANNEL_ID');
		}

		const worker = this.workers.getWorker();
		const router = await worker.createRouter({
			mediaCodecs: AUDIO_CODECS,
		});

		if (router.closed) {
			throw new Error('VOICE_ROUTER_CLOSED');
		}

		const channelRouters = this.routers.get(channelId) ?? [];
		channelRouters.push(router);
		this.routers.set(channelId, channelRouters);

		router.on('workerclose', () => {
			this.removeRouter(channelId, router);
		});

		return router;
	}

	getRouters(channelId: string): types.Router[] {
		return (this.routers.get(channelId) ?? []).filter(
			(router) => !router.closed,
		);
	}

	async getOrCreateRouter(channelId: string): Promise<types.Router> {
		const existing = this.getRouters(channelId)[0];

		if (existing) {
			return existing;
		}

		const pending = this.pending.get(channelId);

		if (pending) {
			return pending;
		}

		const operation = this.createRouter(channelId);
		this.pending.set(channelId, operation);

		try {
			return await operation;
		} finally {
			if (this.pending.get(channelId) === operation) {
				this.pending.delete(channelId);
			}
		}
	}

	removeRouter(channelId: string, router: types.Router): void {
		const routers = this.routers.get(channelId);

		if (!routers) {
			return;
		}

		const remaining = routers.filter(
			(entry) => entry !== router && !entry.closed,
		);

		if (remaining.length === 0) {
			this.routers.delete(channelId);
		} else {
			this.routers.set(channelId, remaining);
		}
	}

	closeChannel(channelId: string): void {
		const routers = this.routers.get(channelId);

		this.routers.delete(channelId);

		if (!routers) {
			return;
		}

		for (const router of routers) {
			router.close();
		}
	}

	close(): void {
		for (const channelId of this.routers.keys()) {
			this.closeChannel(channelId);
		}
	}
}
