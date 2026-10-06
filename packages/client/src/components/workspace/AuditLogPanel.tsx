import { useCallback, useEffect, useRef, useState } from 'react';
import {
  api,
  ApiError,
  type AuditIntegrityStatus,
  type AuditLogEntry,
} from '../../services/api';
import {
  auditActionLabel,
  auditResult,
  auditTargetLabel,
  safeAuditDetails,
} from '../../stores/audit-log-model';
import { t, useT, intlLocale } from '../../i18n';

interface AuditLogPanelProps {
  workspaceId: string;
  canView: boolean;
}

export function AuditLogPanel({ workspaceId, canView }: AuditLogPanelProps) {
  const t = useT();
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [integrity, setIntegrity] = useState<AuditIntegrityStatus | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const requestGeneration = useRef(0);

  const loadInitial = useCallback(async () => {
    if (!canView) return;
    const request = ++requestGeneration.current;
    setLoading(true);
    setLoadingMore(false);
    setError(null);
    setEntries([]);
    setCursor(null);
    setHasMore(false);
    setIntegrity(null);
    try {
      const [pageResult, integrityResult] = await Promise.allSettled([
        api.getWorkspaceAuditLogs(workspaceId, undefined, 50),
        api.getWorkspaceAuditIntegrity(workspaceId),
      ]);
      if (request !== requestGeneration.current) return;
      if (pageResult.status === 'fulfilled') {
        setEntries(pageResult.value.data);
        setCursor(pageResult.value.cursor);
        setHasMore(pageResult.value.hasMore);
      }
      if (integrityResult.status === 'fulfilled') setIntegrity(integrityResult.value);
      const failures = [
        pageResult.status === 'rejected' ? t('履歴: {error}', { error: auditLoadError(pageResult.reason) }) : null,
        integrityResult.status === 'rejected' ? t('状態: {error}', { error: auditLoadError(integrityResult.reason) }) : null,
      ].filter((message): message is string => Boolean(message));
      if (failures.length > 0) setError(failures.join(' / '));
    } catch (loadError) {
      if (request !== requestGeneration.current) return;
      setError(auditLoadError(loadError));
    } finally {
      if (request === requestGeneration.current) setLoading(false);
    }
  }, [canView, workspaceId]);

  useEffect(() => {
    if (!canView) {
      requestGeneration.current += 1;
      setEntries([]);
      setIntegrity(null);
      setCursor(null);
      setHasMore(false);
      setError(null);
      setLoading(false);
      setLoadingMore(false);
      return;
    }
    void loadInitial();
    return () => { requestGeneration.current += 1; };
  }, [canView, loadInitial]);

  const loadMore = async () => {
    if (!canView || !cursor || !hasMore || loadingMore) return;
    const request = requestGeneration.current;
    setLoadingMore(true);
    setError(null);
    try {
      const page = await api.getWorkspaceAuditLogs(workspaceId, cursor, 50);
      if (request !== requestGeneration.current) return;
      setEntries((current) => {
        const seen = new Set(current.map((entry) => entry.id));
        return [...current, ...page.data.filter((entry) => !seen.has(entry.id))];
      });
      setCursor(page.cursor);
      setHasMore(page.hasMore);
    } catch (loadError) {
      if (request === requestGeneration.current) setError(auditLoadError(loadError));
    } finally {
      if (request === requestGeneration.current) setLoadingMore(false);
    }
  };

  if (!canView) return null;

  return (
    <section aria-labelledby="workspace-audit-heading" className="space-y-4">
      <h3 id="workspace-audit-heading" className="font-semibold text-white">{t('操作履歴')}</h3>

      {error && (
        <div role="alert" className="flex items-center justify-between gap-3 rounded bg-discord-red/15 px-3 py-2 text-sm text-discord-red">
          <span>{error}</span>
          <button type="button" onClick={() => { void loadInitial(); }} className="shrink-0 underline">{t('再試行')}</button>
        </div>
      )}

      <div aria-live="polite" className="rounded bg-discord-input px-3 py-2 text-sm">
        <span className="font-medium text-white">{t('記録の状態:')} </span>
        {loading && !integrity ? (
          <span className="text-discord-muted">{t('確認中…')}</span>
        ) : integrity ? (
          <span className={integrity.valid ? 'text-discord-green' : 'text-discord-red'}>
            {integrity.valid ? t('問題ありません') : t('確認が必要です')}
          </span>
        ) : (
          <span className="text-discord-muted">{t('未確認')}</span>
        )}
      </div>

      {loading && entries.length === 0 ? (
        <p role="status" className="py-6 text-center text-discord-muted">{t('操作履歴を読み込み中…')}</p>
      ) : entries.length === 0 ? (
        <p className="py-6 text-center text-discord-muted">{t('表示できる操作履歴はありません。')}</p>
      ) : (
        <ol className="space-y-2" aria-label={t('操作履歴（新しい順）')}>
          {entries.map((entry) => {
            const details = safeAuditDetails(entry.details);
            const result = auditResult(entry);
            const target = auditTargetLabel(entry.targetType);
            return (
              <li key={entry.id} className="rounded border border-discord-hover bg-discord-bg/40 px-3 py-3 text-sm">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <p className="font-medium text-white">{auditActionLabel(entry.action)}</p>
                    {target && <p className="mt-0.5 text-xs text-discord-muted">{t('対象: {target}', { target })}</p>}
                  </div>
                  <div className="text-right text-xs text-discord-muted">
                    <time dateTime={entry.createdAt}>{formatAuditTime(entry.createdAt)}</time>
                    <p className={result === 'failure' ? 'text-discord-red' : result === 'success' ? 'text-discord-green' : ''}>
                      {t('結果: {result}', { result: result === 'success' ? t('成功') : result === 'failure' ? t('失敗') : t('記録なし') })}
                    </p>
                  </div>
                </div>
                {details.length > 0 ? (
                  <dl className="mt-2 grid gap-x-3 gap-y-1 text-xs sm:grid-cols-[max-content_1fr]">
                    {details.map((detail) => (
                      <div key={detail.key} className="contents">
                        <dt className="text-discord-muted">{detail.key}</dt>
                        <dd className="break-all text-discord-text">{detail.value}</dd>
                      </div>
                    ))}
                  </dl>
                ) : null}
              </li>
            );
          })}
        </ol>
      )}

      {hasMore && (
        <div className="text-center">
          <button
            type="button"
            onClick={() => { void loadMore(); }}
            disabled={loadingMore || !cursor}
            className="rounded bg-discord-hover px-4 py-2 text-sm text-white disabled:opacity-40"
          >
            {loadingMore ? t('読み込み中…') : t('さらに古いログを読み込む')}
          </button>
        </div>
      )}
    </section>
  );
}

function auditLoadError(error: unknown): string {
  if (error instanceof ApiError && error.status === 403) {
    return t('操作履歴を閲覧する権限がありません。');
  }
  return t('操作履歴を読み込めませんでした。もう一度お試しください。');
}

function formatAuditTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? t('日時不明') : date.toLocaleString(intlLocale());
}
