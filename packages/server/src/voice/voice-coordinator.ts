import type { types } from 'mediasoup';
import { VoiceWorkerManager } from './worker-manager.js';
import { VoiceRouterManager } from './router-manager.js';
import { VoiceWebRtcServerManager, type VoiceWebRtcServerConfig } from './webrtc-server-manager.js';
import {
	VoiceTransportManager,
	type VoiceTransportDirection,
	type VoiceTransportParameters,
} from './transport-manager.js';
import { VoiceProducerManager } from './producer-manager.js';
import { VoiceConsumerManager } from './consumer-manager.js';

const MAX_VOICE_PARTICIPANTS = 10_000;
const CHANNEL_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PARTICIPANT_ID = /^[A-Za-z0-9_-]{1,128}$/;

export interface VoiceCoordinatorConfig extends VoiceWebRtcServerConfig {
	workerCount?: number;
	/** Speakers per channel and streams per listener (the defaults let everyone in a call speak and hear everyone). */
	maxProducersPerChannel?: number;
	maxConsumersPerParticipant?: number;
}

export interface VoiceConsumerParameters {
	id: string;
	producerId: string;
	kind: types.MediaKind;
	rtpParameters: types.RtpParameters;
}

export interface VoiceProducerInfo {
	participantId: string;
	producerId: string;
}

interface VoiceSession {
	channelId: string;
	router: types.Router | null;
}

type ReadyVoiceSession = VoiceSession & {
	router: types.Router;
};

export class VoiceCoordinator {
	private readonly workers = new VoiceWorkerManager();
	private readonly webRtcServers: VoiceWebRtcServerManager;
	private readonly routers: VoiceRouterManager;
	private readonly transports = new VoiceTransportManager();
	private readonly producers: VoiceProducerManager;
	private readonly consumers: VoiceConsumerManager;
	private readonly sessions = new Map<string, VoiceSession>();
	private readonly channels = new Map<string, Set<string>>();
	private readonly pendingJoins = new Set<Promise<types.Router>>();
	private readonly workerCount: number | undefined;
	private startPromise: Promise<void> | null = null;
	private closePromise: Promise<void> | null = null;
	private ready = false;
	private closed = false;

	constructor(config: VoiceCoordinatorConfig) {
		this.workerCount = config.workerCount;
		this.producers = new VoiceProducerManager(this.transports, config.maxProducersPerChannel);
		this.consumers = new VoiceConsumerManager(this.transports, this.producers, config.maxConsumersPerParticipant);
		this.webRtcServers = new VoiceWebRtcServerManager(config);
		this.routers = new VoiceRouterManager(this.workers, this.webRtcServers);
	}

	async start(): Promise<void> {
		if (this.closed) {
			throw new Error('VOICE_COORDINATOR_CLOSED');
		}

		if (!this.startPromise) {
			this.startPromise = this.workers.start(this.workerCount).then(() => {
				this.ready = true;
			});
		}

		await this.startPromise;

		if (this.closed) {
			throw new Error('VOICE_COORDINATOR_CLOSED');
		}
	}

	async joinParticipant(
		channelId: string,
		participantId: string,
	): Promise<types.RtpCapabilities> {
		this.assertReady();

		if (!CHANNEL_ID.test(channelId) || !PARTICIPANT_ID.test(participantId)) {
			throw new Error('INVALID_VOICE_PARTICIPANT');
		}

		if (this.sessions.has(participantId)) {
			throw new Error('VOICE_PARTICIPANT_ALREADY_JOINED');
		}

		const members = this.channels.get(channelId) ?? new Set<string>();

		if (members.size >= MAX_VOICE_PARTICIPANTS) {
			throw new Error('VOICE_CHANNEL_FULL');
		}

		const session: VoiceSession = {
			channelId,
			router: null,
		};

		members.add(participantId);
		this.channels.set(channelId, members);
		this.sessions.set(participantId, session);

		const operation = this.routers.getOrCreateRouter(channelId);
		this.pendingJoins.add(operation);

		try {
			const router = await operation;

			if (
				this.closed
				|| this.sessions.get(participantId) !== session
				|| router.closed
			) {
				throw new Error('VOICE_JOIN_CANCELLED');
			}

			session.router = router;
			return router.rtpCapabilities;
		} catch (error) {
			if (this.sessions.get(participantId) === session) {
				this.leaveParticipant(participantId);
			} else if (!this.channels.has(channelId)) {
				this.routers.closeChannel(channelId);
			}

			throw error;
		} finally {
			this.pendingJoins.delete(operation);
		}
	}

	async createTransport(
		channelId: string,
		participantId: string,
		direction: VoiceTransportDirection,
	): Promise<VoiceTransportParameters> {
		const session = this.requireSession(channelId, participantId);

		const webRtcServer = this.routers.getWebRtcServer(session.router);

		const result = await this.transports.createTransport(
			participantId,
			direction,
			session.router,
			{ webRtcServer },
		);

		this.assertCurrentSession(participantId, session);
		return result;
	}

	async connectTransport(
		channelId: string,
		participantId: string,
		direction: VoiceTransportDirection,
		transportId: string,
		dtlsParameters: types.DtlsParameters,
	): Promise<void> {
		const session = this.requireSession(channelId, participantId);
		const transport = this.transports.getTransport(participantId, direction);

		if (!transport || transport.id !== transportId) {
			throw new Error('VOICE_TRANSPORT_NOT_FOUND');
		}

		await this.transports.connectTransport(
			participantId,
			direction,
			dtlsParameters,
		);

		this.assertCurrentSession(participantId, session);
	}

	async createProducer(
		channelId: string,
		participantId: string,
		rtpParameters: types.RtpParameters,
	): Promise<string> {
		const session = this.requireSession(channelId, participantId);

		const producer = await this.producers.createProducer(
			channelId,
			participantId,
			rtpParameters,
		);

		try {
			this.assertCurrentSession(participantId, session);
			return producer.id;
		} catch (error) {
			producer.close();
			throw error;
		}
	}

	getProducers(channelId: string): VoiceProducerInfo[] {
		return this.producers.getProducers(channelId).flatMap((producer) => {
			const participantId = producer.appData.participantId;

			if (typeof participantId !== 'string') {
				return [];
			}

			if (this.sessions.get(participantId)?.channelId !== channelId) {
				return [];
			}

			return [{
				participantId,
				producerId: producer.id,
			}];
		});
	}

	async createConsumer(
		channelId: string,
		participantId: string,
		sourceParticipantId: string,
		rtpCapabilities: types.RtpCapabilities,
	): Promise<VoiceConsumerParameters> {
		const session = this.requireSession(channelId, participantId);
		const source = this.requireSession(channelId, sourceParticipantId);

		if (participantId === sourceParticipantId) {
			throw new Error('VOICE_SELF_CONSUME_NOT_ALLOWED');
		}

		if (session.router !== source.router) {
			throw new Error('VOICE_ROUTER_PIPE_REQUIRED');
		}

		const consumer = await this.consumers.createConsumer(
			channelId,
			participantId,
			sourceParticipantId,
			session.router,
			rtpCapabilities,
		);

		try {
			this.assertCurrentSession(participantId, session);
			this.assertCurrentSession(sourceParticipantId, source);

			return {
				id: consumer.id,
				producerId: consumer.producerId,
				kind: consumer.kind,
				rtpParameters: consumer.rtpParameters,
			};
		} catch (error) {
			consumer.close();
			throw error;
		}
	}

	async resumeConsumer(
		channelId: string,
		participantId: string,
		consumerId: string,
	): Promise<void> {
		const session = this.requireSession(channelId, participantId);

		await this.consumers.resumeConsumer(
			channelId,
			participantId,
			consumerId,
		);

		this.assertCurrentSession(participantId, session);
	}

	closeProducer(channelId: string, participantId: string): void {
		this.requireSession(channelId, participantId);
		this.producers.closeProducer(channelId, participantId);
	}

	getParticipantCount(channelId: string): number {
		return this.channels.get(channelId)?.size ?? 0;
	}

	leaveParticipant(participantId: string): void {
		const session = this.sessions.get(participantId);

		if (!session) {
			return;
		}

		this.sessions.delete(participantId);
		const members = this.channels.get(session.channelId);
		members?.delete(participantId);

		this.consumers.closeParticipant(session.channelId, participantId);
		this.producers.closeProducer(session.channelId, participantId);
		this.transports.closeParticipant(participantId);

		if (members && members.size === 0) {
			this.channels.delete(session.channelId);
			this.consumers.closeChannel(session.channelId);
			this.producers.closeChannel(session.channelId);
			this.routers.closeChannel(session.channelId);
		}
	}

	close(): Promise<void> {
		if (this.closePromise) {
			return this.closePromise;
		}

		this.closed = true;

		this.closePromise = (async () => {
			if (this.startPromise) {
				await this.startPromise.catch(() => undefined);
			}

			for (const participantId of this.sessions.keys()) {
        this.leaveParticipant(participantId);
      }

			await Promise.allSettled(this.pendingJoins);

			this.consumers.close();
			this.producers.close();
			this.transports.close();
			this.routers.close();
			this.webRtcServers.close();
			this.workers.close();
			this.ready = false;
		})();

		return this.closePromise;
	}

	private assertReady(): void {
		if (this.closed || !this.ready) {
			throw new Error('VOICE_COORDINATOR_NOT_READY');
		}
	}

	private requireSession(
		channelId: string,
		participantId: string,
	): ReadyVoiceSession {
		this.assertReady();

		const session = this.sessions.get(participantId);

		if (
			!session
			|| session.channelId !== channelId
			|| !session.router
			|| session.router.closed
		) {
			throw new Error('VOICE_SESSION_NOT_FOUND');
		}

		return session as ReadyVoiceSession;
	}

	private assertCurrentSession(
		participantId: string,
		session: VoiceSession,
	): void {
		if (
			this.closed
			|| this.sessions.get(participantId) !== session
			|| !session.router
			|| session.router.closed
		) {
			throw new Error('VOICE_SESSION_ENDED');
		}
	}
}
