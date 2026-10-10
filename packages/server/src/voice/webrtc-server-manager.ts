
import type { types } from 'mediasoup';

export interface VoiceWebRtcServerConfig {
	bindAddress: string;
	announcedAddress: string;
	basePort: number;
}

export class VoiceWebRtcServerManager {
	private readonly servers = new Map<types.Worker, types.WebRtcServer>();
	private readonly pending = new Map<types.Worker, Promise<types.WebRtcServer>>();
	/** The port of each worker: basePort plus its slot, kept when an attempt fails (the port may be busy for a moment). */
	private readonly ports = new Map<types.Worker, number>();
	private readonly bindAddress: string;
	private readonly announcedAddress: string;
	private readonly basePort: number;
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
		this.basePort = config.basePort;
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

	/** The lowest port from basePort that no other open worker listens on, once per worker. */
	private portOf(worker: types.Worker): number {
		const assigned = this.ports.get(worker);
		if (assigned !== undefined) {
			return assigned;
		}
		for (const [other] of this.ports) {
			if (other.closed) {
				this.ports.delete(other);
			}
		}
		const taken = new Set(this.ports.values());
		let port = this.basePort;
		while (taken.has(port)) {
			port += 1;
		}
		if (port > 65535) {
			throw new Error('VOICE_WEBRTC_PORT_EXHAUSTED');
		}
		this.ports.set(worker, port);
		return port;
	}

	private async createServer(worker: types.Worker): Promise<types.WebRtcServer> {
		const port = this.portOf(worker);
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
