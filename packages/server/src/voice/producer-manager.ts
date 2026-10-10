import type { types } from 'mediasoup';
import { MAX_VOICE_PARTICIPANTS } from '@alparts/shared';
import { VoiceTransportManager } from './transport-manager.js';

/** Every participant of a call may speak. */
export const MAX_VOICE_PRODUCERS = MAX_VOICE_PARTICIPANTS;
const CHANNEL_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PARTICIPANT_ID = /^[A-Za-z0-9_-]{1,128}$/;

interface ChannelProducerState {
	producers: Map<string, types.Producer>;
	pending: Map<string, symbol>;
}

export class VoiceProducerManager {
	private readonly channels = new Map<string, ChannelProducerState>();
	private closed = false;

	constructor(
		private readonly transports: VoiceTransportManager,
		private readonly maxProducers = MAX_VOICE_PRODUCERS,
	) {
		if (!Number.isSafeInteger(maxProducers) || maxProducers < 1) throw new Error('INVALID_VOICE_PRODUCER_LIMIT');
	}

	async createProducer(
		channelId: string,
		participantId: string,
		rtpParameters: types.RtpParameters,
	): Promise<types.Producer> {
		if (!CHANNEL_ID.test(channelId) || !PARTICIPANT_ID.test(participantId)) {
			throw new Error('INVALID_VOICE_PRODUCER_REQUEST');
		}

		if (this.closed) {
			throw new Error('VOICE_PRODUCER_MANAGER_CLOSED');
		}

		const transport = this.transports.getTransport(participantId, 'send');

		if (!transport) {
			throw new Error('VOICE_SEND_TRANSPORT_NOT_FOUND');
		}

		let state = this.channels.get(channelId);

		if (!state) {
			state = {
				producers: new Map(),
				pending: new Map(),
			};
			this.channels.set(channelId, state);
		}

		if (state.producers.has(participantId) || state.pending.has(participantId)) {
			throw new Error('VOICE_PRODUCER_ALREADY_EXISTS');
		}
		if (state.producers.size + state.pending.size >= this.maxProducers) {
			throw new Error('VOICE_SPEAKER_LIMIT_REACHED');
		}

		const reservation = Symbol(participantId);
		state.pending.set(participantId, reservation);

		try {
			const producer = await transport.produce({
				kind: 'audio',
				rtpParameters,
				appData: { channelId, participantId },
      });
			
			if (
				this.closed
				|| transport.closed
				|| producer.closed
				|| this.channels.get(channelId) !== state
				|| state.pending.get(participantId) !== reservation
			) {
				producer.close();
				throw new Error('VOICE_PRODUCER_CREATION_CANCELLED');
			}

			state.producers.set(participantId, producer);
			producer.observer.on('close', () => {
				if (state.producers.get(participantId) === producer) {
					state.producers.delete(participantId);
					this.pruneChannel(channelId, state);
				}
			});

			return producer;
		} finally {
			if (state.pending.get(participantId) === reservation) {
				state.pending.delete(participantId);
			}
			this.pruneChannel(channelId, state);
		}
	}

	getProducer(channelId: string, participantId: string): types.Producer | null {
		const producer = this.channels.get(channelId)?.producers.get(participantId);
		return producer && !producer.closed ? producer : null;
	}

	getProducers(channelId: string): types.Producer[] {
		const state = this.channels.get(channelId);

		if (!state) {
			return [];
		}

		return [...state.producers.values()].filter((producer) => !producer.closed);
	}

	closeProducer(channelId: string, participantId: string): void {
		const state = this.channels.get(channelId);

		if (!state) {
			return;
		}

		state.pending.delete(participantId);

		const producer = state.producers.get(participantId);
		state.producers.delete(participantId);

		producer?.close();
		this.pruneChannel(channelId, state);
	}

	closeChannel(channelId: string): void {
		const state = this.channels.get(channelId);

		if (!state) {
			return;
		}

		this.channels.delete(channelId);
		state.pending.clear();
		const producers = [...state.producers.values()];
		state.producers.clear();
		for (const producer of producers) {
			producer.close();
		}
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

	private pruneChannel(channelId: string, state: ChannelProducerState): void {
		if (
			state.producers.size === 0
			&& state.pending.size === 0
			&& this.channels.get(channelId) === state
		) {
			this.channels.delete(channelId);
		}
	}
}
