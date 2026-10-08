import type { types } from 'mediasoup';

export type VoiceTransportDirection = 'send' | 'recv';
export type VoiceTransportListenOptions =
	| {
		webRtcServer: types.WebRtcServer;
		listenInfos?: never;
	}
	| {
		listenInfos: types.TransportListenInfo[];
		webRtcServer?: never;
	};

export interface VoiceTransportParameters {
	id: string;
	iceParameters: types.IceParameters;
	iceCandidates: types.IceCandidate[];
	dtlsParameters: types.DtlsParameters;
}

interface ParticipantTransports {
	send?: types.WebRtcTransport;
	recv?: types.WebRtcTransport;
	pending: Set<VoiceTransportDirection>;
	closed: boolean;
}

export class VoiceTransportManager {
	private readonly participants = new Map<string, ParticipantTransports>();
	private closed = false;

	async createTransport(
		participantId: string,
		direction: VoiceTransportDirection,
		router: types.Router,
		listenOptions: VoiceTransportListenOptions,
	): Promise<VoiceTransportParameters> {
    if (!participantId || participantId.length > 128)
      throw new Error('INVALID_VOICE_PARTICIPANT_ID');

		if (this.closed || router.closed) throw new Error('VOICE_TRANSPORT_MANAGER_CLOSED');

		const state = this.participants.get(participantId) ?? {
			pending: new Set<VoiceTransportDirection>(),
			closed: false,
		};

		if (state[direction] || state.pending.has(direction))
			throw new Error('VOICE_TRANSPORT_ALREADY_EXISTS');

		this.participants.set(participantId, state);
		state.pending.add(direction);

		try {
			const transport = await router.createWebRtcTransport({
				...listenOptions,
				enableSctp: false,
				appData: { participantId, direction },
			});

			if (this.closed || state.closed || router.closed || transport.closed) {
				transport.close();
				throw new Error('VOICE_TRANSPORT_CREATION_CANCELLED');
			}

			state[direction] = transport;

			transport.observer.on('close', () => {
				if (state[direction] === transport) {
					state[direction] = undefined;
					this.pruneParticipant(participantId, state);
				}
			});

			return {
				id: transport.id,
				iceParameters: transport.iceParameters,
				iceCandidates: transport.iceCandidates,
				dtlsParameters: transport.dtlsParameters,
			};
		} finally {
			state.pending.delete(direction);
			this.pruneParticipant(participantId, state);
		}
	}

	async connectTransport(
		participantId: string,
		direction: VoiceTransportDirection,
		dtlsParameters: types.DtlsParameters,
	): Promise<void> {
		const transport = this.getTransport(participantId, direction);

		if (!transport) {
			throw new Error('VOICE_TRANSPORT_NOT_FOUND');
		}

		await transport.connect({ dtlsParameters });
	}

	getTransport(
		participantId: string,
		direction: VoiceTransportDirection,
	): types.WebRtcTransport | null {
		const transport = this.participants.get(participantId)?.[direction];

		return transport && !transport.closed ? transport : null;
	}

	closeParticipant(participantId: string): void {
		const state = this.participants.get(participantId);

		if (!state) {
			return;
		}

		state.closed = true;
		this.participants.delete(participantId);

		const send = state.send;
		const recv = state.recv;

		state.send = undefined;
		state.recv = undefined;

		send?.close();
		recv?.close();
	}

	close(): void {
		if (this.closed) {
			return;
		}

		this.closed = true;

		for (const participantId of this.participants.keys()) {
			this.closeParticipant(participantId);
		}
	}

	private pruneParticipant(
		participantId: string,
		state: ParticipantTransports,
	): void {
		if (
			!state.send
			&& !state.recv
			&& state.pending.size === 0
			&& this.participants.get(participantId) === state
		) {
			this.participants.delete(participantId);
		}
	}
}
