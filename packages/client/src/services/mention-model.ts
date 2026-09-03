export interface MentionMember {
  userId: string;
  displayName: string;
}

export interface ActiveMentionQuery {
  start: number;
  end: number;
  query: string;
}

export interface MentionSegment {
  kind: 'text' | 'mention';
  value: string;
  displayName?: string;
  userId?: string;
  broadcast?: 'everyone' | 'here';
  targetsCurrentUser?: boolean;
}

interface MarkdownNode {
  type: string;
  value?: string;
  children?: MarkdownNode[];
  data?: {
    hName?: string;
    hProperties?: Record<string, string | string[]>;
  };
}

const MENTION_WORD_CHARACTER = /[\p{L}\p{N}_]/u;
const ACTIVE_QUERY_FORBIDDEN_CHARACTER = /[\n\r@<>\x5b\x5d{}()`*_~\\]/u;

function normalized(value: string): string {
  return value.normalize('NFKC').toLocaleLowerCase();
}

function isBoundary(value: string | undefined): boolean {
  return value === undefined || !MENTION_WORD_CHARACTER.test(value);
}

function uniqueMembers(members: MentionMember[]): MentionMember[] {
  const byId = new Map<string, MentionMember>();
  for (const member of members) {
    const displayName = member.displayName.trim();
    if (!member.userId || !displayName || /[\u0000-\u001f\u007f]/u.test(displayName)) continue;
    byId.set(member.userId, { userId: member.userId, displayName });
  }
  return [...byId.values()];
}

/** Locate the unfinished @query immediately before the textarea caret. */
export function findActiveMentionQuery(content: string, caret: number): ActiveMentionQuery | null {
  if (!Number.isSafeInteger(caret) || caret < 0 || caret > content.length) return null;
  if (caret === 0) return null;
  const lineStart = Math.max(content.lastIndexOf('\n', caret - 1), content.lastIndexOf('\r', caret - 1)) + 1;
  const at = content.lastIndexOf('@', caret - 1);
  if (at < lineStart || !isBoundary(content[at - 1])) return null;
  const query = content.slice(at + 1, caret);
  if (query.length > 100 || ACTIVE_QUERY_FORBIDDEN_CHARACTER.test(query)) return null;
  return { start: at, end: caret, query };
}

/** Rank prefix matches before looser substring matches and keep the popup bounded. */
export function filterMentionMembers(
  members: MentionMember[],
  query: string,
  limit = 8,
): MentionMember[] {
  const needle = normalized(query);
  return uniqueMembers(members)
    .map((member) => {
      const name = normalized(member.displayName);
      return { member, score: name.startsWith(needle) ? 0 : name.includes(needle) ? 1 : 2, name };
    })
    .filter((entry) => entry.score < 2)
    .sort((left, right) => (
      left.score - right.score
      || left.name.localeCompare(right.name, 'ja')
      || left.member.userId.localeCompare(right.member.userId)
    ))
    .slice(0, Math.max(0, limit))
    .map((entry) => entry.member);
}

export function applyMentionCompletion(
  content: string,
  active: ActiveMentionQuery,
  member: MentionMember,
  useCanonicalId = false,
): { content: string; caret: number } {
  const token = useCanonicalId ? `<@${member.userId}>` : `@${member.displayName.trim()}`;
  const suffix = content.slice(active.end);
  const nextCharacter = suffix[0];
  const trailingSpace = nextCharacter === undefined || MENTION_WORD_CHARACTER.test(nextCharacter) ? ' ' : '';
  const nextContent = `${content.slice(0, active.start)}${token}${trailingSpace}${suffix}`;
  return {
    content: nextContent,
    caret: active.start + token.length + trailingSpace.length,
  };
}

function matchAt(content: string, index: number, pattern: string): boolean {
  return normalized(content.slice(index, index + pattern.length)) === normalized(pattern);
}

/** Split only real workspace member/broadcast tokens, leaving email addresses and unknown @words alone. */
export function splitMentionText(
  content: string,
  members: MentionMember[],
  currentUserId: string | null,
  authenticatedBroadcastMention: boolean,
): MentionSegment[] {
  const availableMembers = uniqueMembers(members);
  const displayNameGroups = new Map<string, MentionMember[]>();
  for (const member of availableMembers) {
    const key = normalized(member.displayName);
    displayNameGroups.set(key, [...(displayNameGroups.get(key) || []), member]);
  }
  const names = [...displayNameGroups.entries()]
    .map(([key, groupedMembers]) => ({
      key,
      displayName: groupedMembers[0].displayName,
      members: groupedMembers,
    }))
    .sort((left, right) => right.displayName.length - left.displayName.length || left.key.localeCompare(right.key));
  const memberById = new Map(availableMembers.map((member) => [normalized(member.userId), member]));
  const segments: MentionSegment[] = [];
  let textStart = 0;
  let index = 0;

  const pushText = (end: number) => {
    if (end > textStart) segments.push({ kind: 'text', value: content.slice(textStart, end) });
  };

  while (index < content.length) {
    let matched: MentionSegment | null = null;
    let matchedLength = 0;

    if (content[index] === '<' && content[index + 1] === '@' && isBoundary(content[index - 1])) {
      const close = content.indexOf('>', index + 2);
      if (close > index + 2) {
        const member = memberById.get(normalized(content.slice(index + 2, close)));
        if (member) {
          matchedLength = close - index + 1;
          matched = {
            kind: 'mention',
            value: `@${member.displayName}`,
            displayName: member.displayName,
            userId: member.userId,
            targetsCurrentUser: member.userId === currentUserId,
          };
        }
      }
    } else if (content[index] === '@' && isBoundary(content[index - 1])) {
      for (const broadcast of ['everyone', 'here'] as const) {
        const pattern = `@${broadcast}`;
        if (matchAt(content, index, pattern) && isBoundary(content[index + pattern.length])) {
          matchedLength = pattern.length;
          matched = {
            kind: 'mention',
            value: content.slice(index, index + pattern.length),
            displayName: broadcast,
            broadcast,
            targetsCurrentUser: authenticatedBroadcastMention,
          };
          break;
        }
      }
      if (!matched) {
        for (const candidate of names) {
          const pattern = `@${candidate.displayName}`;
          if (!matchAt(content, index, pattern) || !isBoundary(content[index + pattern.length])) continue;
          matchedLength = pattern.length;
          const selected = candidate.members.find((member) => member.userId === currentUserId) || candidate.members[0];
          matched = {
            kind: 'mention',
            value: content.slice(index, index + pattern.length),
            displayName: selected.displayName,
            userId: candidate.members.length === 1 ? selected.userId : undefined,
            targetsCurrentUser: candidate.members.some((member) => member.userId === currentUserId),
          };
          break;
        }
      }
    }

    if (!matched) {
      index += 1;
      continue;
    }
    pushText(index);
    segments.push(matched);
    index += matchedLength;
    textStart = index;
  }
  pushText(content.length);
  return segments.length > 0 ? segments : [{ kind: 'text', value: content }];
}

export function messageMentionsCurrentUser(
  content: string,
  members: MentionMember[],
  currentUserId: string | null,
  authenticatedBroadcastMention: boolean,
): boolean {
  if (!currentUserId) return false;
  return splitMentionText(content, members, currentUserId, authenticatedBroadcastMention)
    .some((segment) => segment.kind === 'mention' && segment.targetsCurrentUser);
}

function mentionNode(segment: MentionSegment): MarkdownNode {
  const own = segment.targetsCurrentUser === true;
  const label = segment.value;
  const title = own
    ? `${segment.broadcast ? `@${segment.broadcast}` : segment.displayName}（あなた宛て）`
    : `${segment.broadcast ? `@${segment.broadcast}` : segment.displayName}へのメンション`;
  return {
    type: 'mention',
    children: [{ type: 'text', value: label }],
    data: {
      hName: 'span',
      hProperties: {
        className: own
          ? ['inline', 'rounded', 'bg-orange-500/20', 'px-0.5', 'font-semibold', 'text-orange-300', 'ring-1', 'ring-inset', 'ring-orange-400/30']
          : ['inline', 'rounded', 'bg-sky-400/10', 'px-0.5', 'font-semibold', 'text-sky-400'],
        title,
        ...(segment.userId ? { 'data-mention-user-id': segment.userId } : {}),
        ...(segment.broadcast ? { 'data-mention-broadcast': segment.broadcast } : {}),
        ...(own ? { 'data-mention-self': 'true' } : {}),
      },
    },
  };
}

function decorateNode(
  node: MarkdownNode,
  members: MentionMember[],
  currentUserId: string | null,
  authenticatedBroadcastMention: boolean,
): void {
  if (!node.children || node.type === 'link' || node.type === 'linkReference') return;
  const nextChildren: MarkdownNode[] = [];
  for (const child of node.children) {
    if (child.type === 'text' && typeof child.value === 'string') {
      for (const segment of splitMentionText(
        child.value,
        members,
        currentUserId,
        authenticatedBroadcastMention,
      )) {
        nextChildren.push(segment.kind === 'text' ? { ...child, value: segment.value } : mentionNode(segment));
      }
    } else {
      decorateNode(child, members, currentUserId, authenticatedBroadcastMention);
      nextChildren.push(child);
    }
  }
  node.children = nextChildren;
}

/** Create a remark-compatible plugin without adding another runtime dependency. */
export function createMarkdownMentionPlugin(
  members: MentionMember[],
  currentUserId: string | null,
  authenticatedBroadcastMention: boolean,
) {
  return function markdownMentionPlugin() {
    return (tree: MarkdownNode) => {
      decorateNode(tree, members, currentUserId, authenticatedBroadcastMention);
    };
  };
}
