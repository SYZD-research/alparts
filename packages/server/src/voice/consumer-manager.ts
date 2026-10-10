
import type { types } from 'mediasoup';
import { MAX_VOICE_PARTICIPANTS } from '@alparts/shared';
import { VoiceTransportManager } from './transport-manager.js';
import { VoiceProducerManager } from './producer-manager.js';

/** Every participant hears every other participant. */
export const MAX_VOICE_CONSUMERS = MAX_VOICE_PARTICIPANTS - 1;
const CHANNEL_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PARTICIPANT_ID = /^[A-Za-z0-9_-]{1,128}$/;

interface ParticipantConsumerState {
	consumers: Map<string, types.Consumer>;
	pending: Map<string, symbol>;
}

type ChannelConsumerState = Map<string, ParticipantConsumerState>;

export class VoiceConsumerManager {
	private readonly channels = new Map<string, ChannelConsumerState>();
	private closed = false;

	constructor(
		private readonly transports: VoiceTransportManager,
		private readonly producers: VoiceProducerManager,
		private readonly maxConsumers = MAX_VOICE_CONSUMERS,
	) {
		if (!Number.isSafeInteger(maxConsumers) || maxConsumers < 1) throw new Error('INVALID_VOICE_CONSUMER_LIMIT');
	}

	async createConsumer(
		channelId: string,
		participantId: string,
		sourceParticipantId: string,
		router: types.Router,
		rtpCapabilities: types.RtpCapabilities,
	): Promise<types.Consumer> {
		if (
			!CHANNEL_ID.test(channelId)
			|| !PARTICIPANT_ID.test(participantId)
			|| !PARTICIPANT_ID.test(sourceParticipantId)
		) {
			throw new Error('INVALID_VOICE_CONSUMER_REQUEST');
		}

		if (this.closed || router.closed) {
			throw new Error('VOICE_CONSUMER_MANAGER_CLOSED');
		}

		if (participantId === sourceParticipantId) {
			throw new Error('VOICE_SELF_CONSUME_NOT_ALLOWED');
		}

		const transport = this.transports.getTransport(participantId, 'recv');

		if (
			!transport
			|| transport.appData.participantId !== participantId
			|| transport.appData.direction !== 'recv'
		) {
			throw new Error('VOICE_RECV_TRANSPORT_NOT_FOUND');
		}

		const producer = this.producers.getProducer(channelId, sourceParticipantId);

		if (!producer || producer.kind !== 'audio') {
			throw new Error('VOICE_PRODUCER_NOT_FOUND');
		}

		if (!router.canConsume({
			producerId: producer.id,
			rtpCapabilities,
		})) {
			throw new Error('VOICE_CANNOT_CONSUME');
		}

		const channel = this.channels.get(channelId) ?? new Map<string, ParticipantConsumerState>();
		const state = channel.get(participantId) ?? {
			consumers: new Map<string, types.Consumer>(),
			pending: new Map<string, symbol>(),
		};

		if (state.consumers.has(sourceParticipantId) || state.pending.has(sourceParticipantId)) {
			throw new Error('VOICE_CONSUMER_ALREADY_EXISTS');
		}

		if (state.consumers.size + state.pending.size >= this.maxConsumers) {
			throw new Error('VOICE_CONSUMER_LIMIT_REACHED');
		}

		this.channels.set(channelId, channel);
		channel.set(participantId, state);

		const reservation = Symbol(sourceParticipantId);
		state.pending.set(sourceParticipantId, reservation);

		try {
			const consumer = await transport.consume({
				producerId: producer.id,
				rtpCapabilities,
				paused: true,
				appData: {
					channelId,
					participantId,
					sourceParticipantId,
				},
			});

			if (
				this.closed
				|| router.closed
				|| transport.closed
				|| producer.closed
				|| consumer.closed
				|| this.channels.get(channelId) !== channel
				|| channel.get(participantId) !== state
				|| state.pending.get(sourceParticipantId) !== reservation
				|| this.transports.getTransport(participantId, 'recv') !== transport
				|| this.producers.getProducer(channelId, sourceParticipantId) !== producer
			) {
				consumer.close();
				throw new Error('VOICE_CONSUMER_CREATION_CANCELLED');
			}

			state.consumers.set(sourceParticipantId, consumer);

			consumer.observer.on('close', () => {
				if (state.consumers.get(sourceParticipantId) === consumer) {
					state.consumers.delete(sourceParticipantId);
					this.pruneParticipant(channelId, channel, participantId, state);
				}
			});

			return consumer;
		} finally {
			if (state.pending.get(sourceParticipantId) === reservation) {
				state.pending.delete(sourceParticipantId);
			}

			this.pruneParticipant(channelId, channel, participantId, state);
		}
	}

	getConsumer(
		channelId: string,
		participantId: string,
		sourceParticipantId: string,
	): types.Consumer | null {
		const consumer = this.channels.get(channelId)
			?.get(participantId)
			?.consumers.get(sourceParticipantId);

		return consumer && !consumer.closed ? consumer : null;
	}

	getConsumers(channelId: string, participantId: string): types.Consumer[] {
		const state = this.channels.get(channelId)?.get(participantId);

		if (!state) {
			return [];
		}

		return [...state.consumers.values()].filter((consumer) => !consumer.closed);
	}

	async resumeConsumer(
		channelId: string,
		participantId: string,
		consumerId: string,
	): Promise<void> {
		const consumer = this.getConsumers(channelId, participantId)
			.find((entry) => entry.id === consumerId);

		if (!consumer) {
			throw new Error('VOICE_CONSUMER_NOT_FOUND');
		}

		await consumer.resume();
	}

	closeConsumer(
		channelId: string,
		participantId: string,
		sourceParticipantId: string,
	): void {
		const channel = this.channels.get(channelId);
		const state = channel?.get(participantId);

		if (!channel || !state) {
			return;
		}

		state.pending.delete(sourceParticipantId);

		const consumer = state.consumers.get(sourceParticipantId);
		state.consumers.delete(sourceParticipantId);

		consumer?.close();
		this.pruneParticipant(channelId, channel, participantId, state);
	}

	closeParticipant(channelId: string, participantId: string): void {
		const channel = this.channels.get(channelId);
		const state = channel?.get(participantId);

		if (!channel || !state) {
			return;
		}

		channel.delete(participantId);
		state.pending.clear();

		const consumers = [...state.consumers.values()];
		state.consumers.clear();

		for (const consumer of consumers) {
			consumer.close();
		}

		if (channel.size === 0 && this.channels.get(channelId) === channel) {
			this.channels.delete(channelId);
		}
	}

	closeChannel(channelId: string): void {
		const channel = this.channels.get(channelId);

		if (!channel) {
			return;
		}

		this.channels.delete(channelId);

		for (const state of channel.values()) {
			state.pending.clear();

			for (const consumer of state.consumers.values()) {
				consumer.close();
			}

			state.consumers.clear();
		}

		channel.clear();
	}

	close(): void {
		if (this.closed) {
			return;
		}

		this.closed = true;

		for (const channelId of this.channels.keys()) {
			this.closeChannel(channelId);
		}
	}

	private pruneParticipant(
		channelId: string,
		channel: ChannelConsumerState,
		participantId: string,
		state: ParticipantConsumerState,
	): void {
		if (
			state.consumers.size !== 0
			|| state.pending.size !== 0
			|| this.channels.get(channelId) !== channel
			|| channel.get(participantId) !== state
		) {
			return;
		}

		channel.delete(participantId);

		if (channel.size === 0) {
			this.channels.delete(channelId);
		}
	}
}
