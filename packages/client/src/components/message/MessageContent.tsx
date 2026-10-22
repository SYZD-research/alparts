import { useMemo } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import type { WorkspaceMember } from '@alparts/shared';
import { createMarkdownMentionPlugin, type MentionMember } from '../../services/mention-model';
import { userFacingMessageText } from '../../services/message-display';
import { useT } from '../../i18n';
import { MessageLink } from './MessageLink';

interface Props {
  content: string;
  members: WorkspaceMember[];
  currentUserId: string | null;
  authenticatedBroadcastMention?: boolean;
}

export function MessageContent({
  content,
  members,
  currentUserId,
  authenticatedBroadcastMention = false,
}: Props) {
  const t = useT();
  const mentionMembers = useMemo<MentionMember[]>(() => members.map((member) => ({
    userId: member.userId,
    displayName: member.user.displayName,
  })), [members]);
  const mentionPlugin = useMemo(() => createMarkdownMentionPlugin(
    mentionMembers,
    currentUserId,
    authenticatedBroadcastMention,
  ), [authenticatedBroadcastMention, currentUserId, mentionMembers]);

  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm, mentionPlugin]}
      components={{
        img: ({ alt }) => (
          <span role="img" aria-label={alt || t('外部画像')} className="text-discord-muted italic">
            {alt ? t('[画像: {alt}]', { alt }) : t('[画像]')}
          </span>
        ),
        // A component of its own, so a link keeps an open confirmation while the message re-renders.
        a: MessageLink,
      }}
    >
      {userFacingMessageText(content)}
    </ReactMarkdown>
  );
}
