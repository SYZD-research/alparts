import { isValidElement, useState, type ReactNode } from 'react';
import { describeLink, plainLinkText, type LinkDestination } from '../../services/link-destination';
import { safeMarkdownHref } from '../../services/url-policy';
import { useT } from '../../i18n';
import { Dialog } from '../ui/Dialog';

const LINK_CLASS = 'font-medium text-sky-400 underline decoration-sky-400/70 underline-offset-2 hover:text-sky-300 hover:decoration-sky-300';

/** What a reader sees as the link's text, including the description of an image inside it. */
function textOf(node: ReactNode): string {
  if (typeof node === 'string' || typeof node === 'number') return String(node);
  if (Array.isArray(node)) return node.map(textOf).join('');
  if (isValidElement<{ children?: ReactNode; alt?: unknown }>(node)) {
    return `${typeof node.props.alt === 'string' ? node.props.alt : ''}${textOf(node.props.children)}`;
  }
  return '';
}

export function MessageLink({ href, children }: { href?: string; children?: ReactNode }) {
  const t = useT();
  const [asking, setAsking] = useState(false);
  const safeHref = safeMarkdownHref(href);
  if (!safeHref) {
    return (
      <span className="border-b border-dotted border-muted" title={t('このリンクは開けません')}>
        {children}
      </span>
    );
  }

  const text = textOf(children);
  const destination = describeLink(safeHref, text);
  const shown = (
    <>
      {children}
      <span aria-hidden="true" className="ml-0.5 text-[0.75em]">↗</span>
      {destination?.masked && (
        <span className="ml-1 inline-block break-all rounded-lg bg-hover px-1 text-[0.75em] font-normal text-muted">
          {destination.place}
        </span>
      )}
    </>
  );
  const title = destination?.masked
    ? t('リンク先: {address}', { address: destination.address })
    : t('新しいタブでリンクを開く');

  // Without an address of its own, no click variant (middle click, new window) can skip the question.
  if (destination?.misleading) {
    return (
      <>
        <button type="button" onClick={() => setAsking(true)} title={title} className={`inline cursor-pointer text-left ${LINK_CLASS}`}>
          {shown}
        </button>
        <OpenLinkDialog open={asking} onClose={() => setAsking(false)} text={text} destination={destination} />
      </>
    );
  }
  return (
    <a
      href={safeHref}
      target="_blank"
      rel="noopener noreferrer"
      referrerPolicy="no-referrer"
      title={title}
      className={LINK_CLASS}
    >
      {shown}
    </a>
  );
}

export function OpenLinkDialog({ open, onClose, text, destination }: {
  open: boolean;
  onClose: () => void;
  text: string;
  destination: LinkDestination;
}) {
  const t = useT();
  return (
    <Dialog open={open} onClose={onClose} title={t('リンク先を確認してください')} size="sm">
      <div className="space-y-4">
        <p className="rounded-lg border border-danger/60 bg-danger/10 p-3 text-sm text-ink">
          {t('このリンクは「{text}」と表示されていますが、実際には {place} を開きます。', {
            text: plainLinkText(text),
            place: destination.place,
          })}
        </p>
        <p className="select-all break-all rounded-lg bg-field p-3 font-mono text-xs text-ink">{destination.address}</p>
        <p className="text-sm text-muted">{t('信頼できる場合だけ開いてください。')}</p>
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-lg px-3 py-2 text-sm text-muted hover:bg-hover">{t('キャンセル')}</button>
          {/* A real link to the address shown above, so it opens the way every other link does on web, desktop and Android; tabIndex keeps it in the dialog's focus loop. */}
          <a
            href={destination.address}
            target="_blank"
            rel="noopener noreferrer"
            referrerPolicy="no-referrer"
            tabIndex={0}
            onClick={onClose}
            className="rounded-lg bg-accent px-3 py-2 text-sm font-medium text-on-accent"
          >
            {t('開く')}
          </a>
        </div>
      </div>
    </Dialog>
  );
}
