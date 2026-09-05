import type { Message } from '@alparts/shared';
import { getMessageCryptoVerificationState } from '../../stores/message-projector';
import { userFacingMessageText } from '../../services/message-display';

export const MESSAGE_REPLY_SWIPE_DISTANCE = 64;
export const MESSAGE_EDIT_SWIPE_DISTANCE = 136;

export function canSwipeMessage(message: Message): boolean {
  return (message.type === 'message' || message.type === 'edit')
    && getMessageCryptoVerificationState(message) !== false
    && userFacingMessageText(message.content || '') === (message.content || '');
}

export function messageSwipeAction(distanceX: number, isOwn: boolean): 'reply' | 'edit' | null {
  if (isOwn && distanceX <= -MESSAGE_EDIT_SWIPE_DISTANCE) return 'edit';
  return distanceX <= -MESSAGE_REPLY_SWIPE_DISTANCE ? 'reply' : null;
}
