
import type { types } from 'mediasoup';

export interface VoiceWebRtcServerConfig {
	bindAddress: string;
	announcedAddress: string;
	basePort: number;
}

export class VoiceWebRtcServerManager {
	private readonly servers = new Map<types.Worker, types.WebRtcServer>();
	private readonly pending = new Map<types.Worker, Promise<types.WebRtcServer>>();
	private readonly bindAddress: string;
	private readonly announcedAddress: string;
	private nextPort: number;
	private closed = false;

	constructor(config: VoiceWebRtcServerConfig) {
		if (!config.bindAddress.trim() || !config.announcedAddress.trim()) {
			throw new Error('INVALID_VOICE_LISTEN_ADDRESS');
		}
		if (!Number.isSafeInteger(config.basePort) || config.basePort < 1024 || config.basePort > 65535) {
			throw new Error('INVALID_VOICE_BASE_PORT');
		}

		this.bindAddress = config.bindAddress;
		this.announcedAddress = config.announcedAddress;
		this.nextPort = config.basePort;
	}

	async getOrCreate(worker: types.Worker): Promise<types.WebRtcServer> {
		if (this.closed || worker.closed) {
			throw new Error('VOICE_WEBRTC_SERVER_CLOSED');
    }

		const existing = this.servers.get(worker);
		if (existing && !existing.closed) {
			return existing;
		}

		const pending = this.pending.get(worker);
		if (pending) {
			return pending;
		}

		const operation = this.createServer(worker);
		this.pending.set(worker, operation);

		try {
			return await operation;
		} finally {
			if (this.pending.get(worker) === operation) {
				this.pending.delete(worker);
			}
		}
	}

	private async createServer(worker: types.Worker): Promise<types.WebRtcServer> {
		if (this.nextPort > 65535) {
			throw new Error('VOICE_WEBRTC_PORT_EXHAUSTED');
		}
		const port = this.nextPort++;
		const listenInfos: types.TransportListenInfo[] = [
			{
				protocol: 'udp',
				ip: this.bindAddress,
				announcedAddress: this.announcedAddress,
				port,
			},
			{
				protocol: 'tcp',
				ip: this.bindAddress,
				announcedAddress: this.announcedAddress,
				port,
			},
		];
		const server = await worker.createWebRtcServer({
			listenInfos,
		});
		if (this.closed || worker.closed || server.closed) {
			server.close();
			throw new Error('VOICE_WEBRTC_SERVER_CREATION_CANCELLED');
		}
		this.servers.set(worker, server);
		server.observer.on('close', () => {
			if (this.servers.get(worker) === server) {
				this.servers.delete(worker);
			}
		});

		return server;
	}

	close(): void {
		if (this.closed) {
			return;
		}
		this.closed = true;
		for (const server of this.servers.values()) {
			server.close();
		}
		this.servers.clear();
	}
}
