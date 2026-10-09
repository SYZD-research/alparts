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
 * The layouts a served event may verify in, in the order they are tried. An
 * event that names another message (an edit, a deletion, a quote, or a forum
 * event inside a post) counts only in v5: the older layouts name the target
 * by server id only, which a server can serve another message under, so they
 * are refused (the server refuses them too). Other events are usually signed
 * in the older layout; the layouts never share bytes.
 */
export function signedEnvelopeCandidates(message: Message, forumChannel: boolean): SignedMessageEnvelope[] {
  const { older, bound } = signedEnvelopeLayouts(message, forumChannel);
  return referencesOtherMessages(older) ? [bound] : [older, bound];
}
