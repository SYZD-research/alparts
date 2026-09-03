import { useMemo } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import type { WorkspaceMember } from '@alparts/shared';
import { safeMarkdownHref } from '../../services/url-policy';
import { createMarkdownMentionPlugin, type MentionMember } from '../../services/mention-model';
import { userFacingMessageText } from '../../services/message-display';

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
          <span role="img" aria-label={alt || '外部画像'} className="text-discord-muted italic">
            [画像{alt ? `: ${alt}` : ''}]
          </span>
        ),
        a: ({ href, children }) => {
          const safeHref = safeMarkdownHref(href);
          return safeHref ? (
            <a
              href={safeHref}
              target="_blank"
              rel="noopener noreferrer"
              referrerPolicy="no-referrer"
              title="新しいタブでリンクを開く"
              className="font-medium text-sky-400 underline decoration-sky-400/70 underline-offset-2 hover:text-sky-300 hover:decoration-sky-300"
            >
              {children}<span aria-hidden="true" className="ml-0.5 text-[0.75em]">↗</span>
            </a>
          ) : (
            <span className="border-b border-dotted border-discord-muted" title="このリンクは開けません">
              {children}
            </span>
          );
        },
      }}
    >
      {userFacingMessageText(content)}
    </ReactMarkdown>
  );
}
