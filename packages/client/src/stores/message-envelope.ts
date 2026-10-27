import { referencesOtherMessages, type Message, type SignedMessageEnvelope } from '@alparts/shared';

/**
 * The envelope a served event would have been signed as, in the v3/v4 layout
 * and in v5. The layout follows the channel type (the channel id is signed),
 * so a server cannot pick v3 or v4 by adding a field; v5 also carries what
 * the event's references name, as the server serves it.
 */
export function signedEnvelopeLayouts(message: Message, forumChannel: boolean): { older: SignedMessageEnvelope; bound: SignedMessageEnvelope } {
  const older: SignedMessageEnvelope = {
    type: message.type as SignedMessageEnvelope['type'],
    channelId: message.channelId,
    authorId: message.authorId,
    deviceId: message.deviceId!,
    keyVersion: message.keyVersion,
    idempotencyKey: message.idempotencyKey,
    refMessageId: message.refMessageId,
    broadcastMention: message.broadcastMention ?? null,
    encryptedContent: message.encryptedContent,
    contentNonce: message.contentNonce,
    ...(forumChannel ? { postId: message.postId ?? null } : {}),
  };
  return {
    older,
    bound: {
      ...older,
      refBinding: message.refBinding ?? null,
      ...(forumChannel ? { postBinding: message.postBinding ?? null } : {}),
    },
  };
}

/**
 * The v6 envelope a served event would have been signed as: v5 plus its
 * number, the heads it saw and the version an edit replaces, as served.
 */
export function sequencedEnvelopeLayout(message: Message, forumChannel: boolean): SignedMessageEnvelope {
  return {
    ...signedEnvelopeLayouts(message, forumChannel).bound,
    deviceSeq: message.deviceSeq!,
    seenHeads: message.seenHeads as SignedMessageEnvelope['seenHeads'],
    supersedes: message.supersedes ?? null,
  };
}

/**
 * The layouts a served event may verify in, in the order they are tried. An
 * event served with a number verifies only in v6: dropping the number cannot
 * make it verify in an older layout, which never shares bytes with v6. An
 * event that names another message (an edit, a deletion, a quote, or a forum
 * event inside a post) counts only in v5 or v6: the older layouts name the
 * target by server id only, which a server can serve another message under,
 * so they are refused (the server refuses them too). Other events written
 * before v6 are usually signed in the older layout.
 */
export function signedEnvelopeCandidates(message: Message, forumChannel: boolean): SignedMessageEnvelope[] {
  if (message.deviceSeq !== null && message.deviceSeq !== undefined) return [sequencedEnvelopeLayout(message, forumChannel)];
  const { older, bound } = signedEnvelopeLayouts(message, forumChannel);
  return referencesOtherMessages(older) ? [bound] : [older, bound];
}
