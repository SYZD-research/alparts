import { useEffect, useId, useRef, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { useT } from '../../i18n';
import { Icon } from './Icon';

interface DialogProps {
  open: boolean;
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
  size?: 'sm' | 'md' | 'lg';
}

const widths = {
  sm: 'max-w-md',
  md: 'max-w-2xl',
  lg: 'max-w-4xl',
};

export function Dialog({ open, title, description, onClose, children, size = 'md' }: DialogProps) {
  const t = useT();
  const titleId = useId();
  const descriptionId = useId();
  const panelRef = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== 'Tab' || !panelRef.current) return;
      const focusable = [...panelRef.current.querySelectorAll<HTMLElement>(
        'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      )];
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKeyDown);
    const bodyAlreadyLocked = document.body.classList.contains('overflow-hidden');
    document.body.classList.add('overflow-hidden');
    requestAnimationFrame(() => {
      const panel = panelRef.current;
      const target = panel?.querySelector<HTMLElement>('[autofocus]')
        || panel?.querySelector<HTMLElement>('button, input, select, textarea');
      target?.focus();
    });
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      if (!bodyAlreadyLocked) document.body.classList.remove('overflow-hidden');
      previous?.focus();
    };
  }, [open]);

  if (!open) return null;
  const content = (
    <div
      data-no-swipe
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-[2px]"
      onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        className={`flex max-h-[90vh] w-full ${widths[size]} flex-col overflow-hidden rounded-2xl border border-line bg-panel shadow-2xl shadow-black/50`}
      >
        <header className="flex items-start justify-between gap-4 border-b border-line py-4 pl-6 pr-4">
          <div className="pt-0.5">
            <h2 id={titleId} className="text-lg font-semibold text-ink-strong">{title}</h2>
            {description && <p id={descriptionId} className="mt-1 text-sm text-muted">{description}</p>}
          </div>
          <button type="button" onClick={onClose} className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-muted transition-colors hover:bg-hover hover:text-ink-strong" aria-label={t('閉じる')}>
            <Icon name="close" />
          </button>
        </header>
        <div className="overflow-y-auto px-6 py-5">{children}</div>
      </div>
    </div>
  );
  // Sliding panes form containing blocks; dialogs must still cover the viewport.
  return typeof document === 'undefined' ? content : createPortal(content, document.body);
}
