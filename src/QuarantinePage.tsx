import { useState, useEffect, useMemo } from '@wordpress/element';
import { InlineConfirmPopover } from './components/InlineConfirmPopover';
import { ConfirmDialog } from './components/ConfirmDialog';
import { EmptyStateCard } from './components/ui/EmptyStateCard';
import {
  Archive,
  RotateCcw,
  Trash2,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  Copy,
  Check,
  RefreshCw,
  Search,
  Filter,
  ArrowLeft,
  Lock,
  FolderLock,
  ShieldAlert,
  Clock,
  HardDrive
} from 'lucide-react';

interface QuarantineRecord {
  id: number;
  scan_id: number;
  issue_id: number;
  original_path: string;
  quarantine_filename: string;
  sha256: string;
  file_size: number;
  file_perms: string;
  status: 'quarantined' | 'restored';
  quarantined_at: string;
  restored_at?: string;
}

interface QuarantinePageProps {
  apiRequest: (options: any) => Promise<any>;
  onNavigateToDashboard?: () => void;
  isEmbedded?: boolean;
}

export const QuarantinePage = ({ apiRequest, onNavigateToDashboard, isEmbedded }: QuarantinePageProps) => {
  const [records, setRecords] = useState<QuarantineRecord[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'quarantined' | 'restored'>('all');
  const [copiedPath, setCopiedPath] = useState<string | null>(null);
  const [actionLoadingId, setActionLoadingId] = useState<number | null>(null);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [confirmClearRestoredOpen, setConfirmClearRestoredOpen] = useState(false);

  const loadRecords = async () => {
    setLoading(true);
    try {
      const res: any = await apiRequest({ path: '/webcare-pro-security/v1/quarantine' });
      if (res && res.success && Array.isArray(res.records)) {
        setRecords(res.records);
      } else {
        setRecords([]);
      }
    } catch (err) {
      console.error('Failed to load quarantine records', err);
      setFeedback({ type: 'error', message: 'Failed to retrieve quarantine records from server.' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRecords();
  }, []);

  const handleRestore = async (record: QuarantineRecord) => {
    setActionLoadingId(record.id);
    try {
      const res: any = await apiRequest({
        path: `/webcare-pro-security/v1/quarantine/${record.id}/restore`,
        method: 'POST',
      });
      if (res && res.success) {
        setFeedback({ type: 'success', message: res.message || 'File successfully decrypted and restored to disk!' });
        loadRecords();
      } else {
        setFeedback({ type: 'error', message: res?.message || 'Failed to restore file.' });
      }
    } catch (err: any) {
      console.error(err);
      setFeedback({ type: 'error', message: err?.message || 'Server error while attempting file restoration.' });
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleClearAllRestored = async () => {
    setLoading(true);
    try {
      const res: any = await apiRequest({
        path: '/webcare-pro-security/v1/quarantine/restored',
        method: 'DELETE',
      });
      if (res && res.success) {
        setFeedback({ type: 'success', message: res.message || 'Restored history records successfully cleared.' });
        loadRecords();
      } else {
        setFeedback({ type: 'error', message: res?.message || 'Failed to clear restored records.' });
      }
    } catch (err: any) {
      console.error(err);
      setFeedback({ type: 'error', message: err?.message || 'Server error while clearing restored records.' });
    } finally {
      setLoading(false);
      setConfirmClearRestoredOpen(false);
    }
  };

  const handleDelete = async (record: QuarantineRecord) => {
    const isRestored = record.status === 'restored';
    setActionLoadingId(record.id);
    try {
      const res: any = await apiRequest({
        path: `/webcare-pro-security/v1/quarantine/${record.id}`,
        method: 'DELETE',
      });
      if (res && res.success) {
        setFeedback({
          type: 'success',
          message:
            res.message ||
            (isRestored
              ? 'Vault history entry removed. (Live site file remains untouched).'
              : 'Quarantined file permanently deleted from vault.'),
        });
        loadRecords();
      } else {
        setFeedback({ type: 'error', message: res?.message || 'Failed to delete quarantined record.' });
      }
    } catch (err: any) {
      console.error(err);
      setFeedback({ type: 'error', message: err?.message || 'Server error while attempting file deletion.' });
    } finally {
      setActionLoadingId(null);
    }
  };

  const copyToClipboard = (text: string) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedPath(text);
      setTimeout(() => setCopiedPath(null), 2000);
    }
  };

  const activeCount = useMemo(() => records.filter((r) => r.status === 'quarantined').length, [records]);
  const restoredCount = useMemo(() => records.filter((r) => r.status === 'restored').length, [records]);

  const filteredRecords = useMemo(() => {
    return records.filter((r) => {
      const matchesStatus = statusFilter === 'all' || r.status === statusFilter;
      const q = searchQuery.toLowerCase().trim();
      const matchesSearch =
        !q ||
        r.original_path.toLowerCase().includes(q) ||
        r.quarantine_filename.toLowerCase().includes(q) ||
        (r.sha256 && r.sha256.toLowerCase().includes(q));
      return matchesStatus && matchesSearch;
    });
  }, [records, statusFilter, searchQuery]);

  return (
    <div className="webcare-container" style={{ width: '100%', maxWidth: '100%', margin: '0', paddingBottom: isEmbedded ? '20px' : '60px' }}>
      {/* Top Header Card */}
      {!isEmbedded && (
        <div className="webcare-card" style={{ marginBottom: '24px', padding: '28px 32px' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '10px' }}>
                  <div style={{ background: 'var(--webcare-badge-clean-bg, #ecfdf5)', padding: '12px', borderRadius: '12px', border: '1px solid var(--webcare-badge-clean-border, #a7f3d0)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <Archive size={28} color="#059669" />
                  </div>
                  <div>
                    <h1 style={{ margin: 0, fontSize: '24px', fontWeight: 800, color: 'inherit', display: 'flex', alignItems: 'center', gap: '12px', letterSpacing: '-0.02em' }}>
                      Quarantine Vault &amp; File Isolation
                    </h1>
                    <p style={{ margin: '4px 0 0 0', fontSize: '14px', color: 'var(--webcare-text-secondary, #64748b)' }}>
                      Cryptographic storage vault for isolated backdoors, neutralized webshells, and quarantined malware.
                    </p>
                  </div>
                </div>

                {/* Security Posture Chips */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', marginTop: '16px' }}>
                  <span className="webcare-badge-clean">
                    <Lock size={13} />
                    AES-256-GCM AEAD Encrypted at Rest
                  </span>
                  <span className="webcare-badge-purple">
                    <FolderLock size={13} />
                    Execution Defanged (__halt_compiler)
                  </span>
                  <span className="webcare-badge-info">
                    <ShieldCheck size={13} />
                    Safety Snapshot Retained for 14 Days
                  </span>
                  <span className="webcare-badge-neutral">
                    Storage: <code>uploads/webcare-pro-security/.vault/</code>
                  </span>
                </div>
              </div>

              {/* Header Right Actions */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                {onNavigateToDashboard && (
                  <button
                    type="button"
                    className="webcare-btn-secondary"
                    onClick={onNavigateToDashboard}
                  >
                    <ArrowLeft size={15} />
                    Dashboard
                  </button>
                )}
                <button
                  type="button"
                  className="webcare-btn-primary"
                  onClick={loadRecords}
                  disabled={loading}
                >
                  <RefreshCw size={15} className={loading ? 'webcare-spin-icon' : ''} />
                  Refresh Vault
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Feedback Banner */}
      {feedback && (
        <div
          style={{
            marginBottom: '20px',
            padding: '14px 20px',
            borderRadius: '10px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            background: feedback.type === 'success' ? '#ecfdf5' : '#fef2f2',
            color: feedback.type === 'success' ? '#065f46' : '#991b1b',
            border: `1px solid ${feedback.type === 'success' ? '#a7f3d0' : '#fecaca'}`,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13.5px', fontWeight: 600 }}>
            {feedback.type === 'success' ? <CheckCircle2 size={18} color="#10b981" /> : <AlertTriangle size={18} color="#ef4444" />}
            <span>{feedback.message}</span>
          </div>
          <button
            type="button"
            onClick={() => setFeedback(null)}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', fontWeight: 700 }}
          >
            ✕
          </button>
        </div>
      )}

      {/* Cyber Metric Cards */}
      <div className="webcare-quarantine-metrics-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '16px', marginBottom: '24px' }}>
        {/* Card 1: Active Quarantined */}
        <div className="webcare-quarantine-kpi-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div className="webcare-quarantine-kpi-label">
                Active Quarantined Files
              </div>
              <div style={{ fontSize: '28px', fontWeight: 800, color: activeCount > 0 ? '#ef4444' : '#10b981', marginTop: '6px' }}>
                {activeCount}
              </div>
              <div className="webcare-quarantine-kpi-sub" style={{ marginTop: '4px' }}>
                {activeCount > 0 ? 'Threats isolated & locked in vault' : 'Zero active quarantined threats'}
              </div>
            </div>
            <div className={`webcare-quarantine-kpi-icon ${activeCount > 0 ? 'is-danger' : 'is-success'}`}>
              <ShieldAlert size={22} color={activeCount > 0 ? '#dc2626' : '#10b981'} />
            </div>
          </div>
        </div>

        {/* Card 2: Restored Files */}
        <div className="webcare-quarantine-kpi-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div className="webcare-quarantine-kpi-label">
                Restored Files
              </div>
              <div style={{ fontSize: '28px', fontWeight: 800, color: '#0284c7', marginTop: '6px' }}>
                {restoredCount}
              </div>
              <div className="webcare-quarantine-kpi-sub" style={{ marginTop: '4px' }}>
                Safely recovered & decrypted to disk
              </div>
            </div>
            <div className="webcare-quarantine-kpi-icon is-info">
              <RotateCcw size={22} color="#0284c7" />
            </div>
          </div>
        </div>

        {/* Card 3: Total Vault Records */}
        <div className="webcare-quarantine-kpi-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div className="webcare-quarantine-kpi-label">
                Total Vault History
              </div>
              <div className="webcare-quarantine-kpi-val" style={{ fontSize: '28px', fontWeight: 800, marginTop: '6px' }}>
                {records.length}
              </div>
              <div className="webcare-quarantine-kpi-sub" style={{ marginTop: '4px' }}>
                All-time historical quarantine events
              </div>
            </div>
            <div className="webcare-quarantine-kpi-icon is-neutral">
              <Archive size={22} color="#64748b" />
            </div>
          </div>
        </div>

        {/* Card 4: Vault Encryption Status */}
        <div className="webcare-quarantine-kpi-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div className="webcare-quarantine-kpi-label">
                Vault Cryptography
              </div>
              <div style={{ fontSize: '20px', fontWeight: 800, color: '#059669', marginTop: '10px' }}>
                AES-256-GCM
              </div>
              <div className="webcare-quarantine-kpi-sub" style={{ marginTop: '4px' }}>
                AEAD cipher with execution barrier
              </div>
            </div>
            <div className="webcare-quarantine-kpi-icon is-success">
              <ShieldCheck size={22} color="#059669" />
            </div>
          </div>
        </div>
      </div>

      {/* Main Table Container Card */}
      <div className="webcare-quarantine-main-card">
        {/* Toolbar: Filter Tabs & Search */}
        <div className="webcare-quarantine-toolbar">
          {/* Status Tabs */}
          <div className="webcare-quarantine-tab-pill-track">
            <button
              type="button"
              onClick={() => setStatusFilter('all')}
              className={`webcare-quarantine-filter-tab ${statusFilter === 'all' ? 'is-active is-all' : ''}`}
            >
              All Records ({records.length})
            </button>
            <button
              type="button"
              onClick={() => setStatusFilter('quarantined')}
              className={`webcare-quarantine-filter-tab ${statusFilter === 'quarantined' ? 'is-active is-quarantined' : ''}`}
            >
              Quarantined ({activeCount})
            </button>
            <button
              type="button"
              onClick={() => setStatusFilter('restored')}
              className={`webcare-quarantine-filter-tab ${statusFilter === 'restored' ? 'is-active is-restored' : ''}`}
            >
              Restored ({restoredCount})
            </button>
          </div>

          {/* Right Toolbar Controls */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: '1', maxWidth: '600px', justifyContent: 'flex-end', flexWrap: 'wrap' }}>
            {restoredCount > 0 && (
              <button
                type="button"
                className="webcare-btn webcare-quarantine-btn-clear"
                onClick={() => setConfirmClearRestoredOpen(true)}
                disabled={loading}
                title="Remove all restored audit log entries. Live website files remain completely untouched."
              >
                <Trash2 size={13} />
                <span>Clear Restored History ({restoredCount})</span>
              </button>
            )}

            {/* Search Box */}
            <div style={{ position: 'relative', minWidth: '260px', flex: '1', maxWidth: '360px' }}>
              <Search size={16} color="#94a3b8" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="text"
                placeholder="Search by path, vault file, or SHA-256..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="webcare-quarantine-search-input"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery('')}
                  style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '12px' }}
                >
                  ✕
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Content Table */}
        {loading ? (
          <div style={{ padding: '60px', textAlign: 'center', color: '#64748b' }}>
            <RefreshCw size={28} className="webcare-spin-icon" style={{ margin: '0 auto 12px auto' }} />
            <div style={{ fontSize: '14px', fontWeight: 600 }}>Loading encrypted vault records...</div>
          </div>
        ) : filteredRecords.length === 0 ? (
          <EmptyStateCard
            icon={ShieldCheck}
            title={searchQuery || statusFilter !== 'all' ? 'No Matching Quarantine Records' : 'Quarantine vault is empty — no isolated files need attention.'}
            description={searchQuery || statusFilter !== 'all'
              ? 'Try clearing your search query or switching status filters to view records.'
              : 'Zero active threats or suspicious scripts are currently quarantined. When suspicious files or webshells are detected, you can safely isolate them with 1-click while retaining 14-day safety snapshots in WebCare Vault.'}
            badge="Vault Clean"
            badgeType="clean"
            actionLabel={(searchQuery || statusFilter !== 'all') ? 'Reset Filters' : undefined}
            onAction={() => {
              setSearchQuery('');
              setStatusFilter('all');
            }}
          />
        ) : (
          <div className="webcare-quarantine-table-wrap">
            <table className="webcare-quarantine-table">
              <thead>
                <tr>
                  <th style={{ padding: '12px 20px', width: 'auto' }}>
                    Quarantined File & Hash
                  </th>
                  <th style={{ padding: '12px 16px', width: '110px' }}>
                    Size
                  </th>
                  <th style={{ padding: '12px 16px', width: '160px' }}>
                    Quarantined At
                  </th>
                  <th style={{ padding: '12px 16px', width: '130px' }}>
                    Status
                  </th>
                  <th style={{ padding: '12px 20px', textAlign: 'right', width: '220px' }}>
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {filteredRecords.map((q, idx) => {
                  const isBusy = actionLoadingId === q.id;
                  return (
                    <tr
                      key={q.id}
                      className={`webcare-quarantine-row is-${q.status}`}
                    >
                      <td style={{ padding: '16px 20px' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                            <div className="webcare-quarantine-path-chip">
                              <span>{q.original_path}</span>
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  copyToClipboard(q.original_path);
                                }}
                                style={{
                                  background: 'none',
                                  border: 'none',
                                  padding: '2px',
                                  cursor: 'pointer',
                                  color: copiedPath === q.original_path ? '#16a34a' : 'inherit',
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                }}
                                title="Copy original file path"
                              >
                                {copiedPath === q.original_path ? <Check size={12} color="#16a34a" /> : <Copy size={12} />}
                              </button>
                            </div>
                          </div>

                          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '11px', color: '#64748b', flexWrap: 'wrap' }}>
                            <span
                              className="webcare-quarantine-vault-file-chip"
                              title={`Isolated Vault Filename: ${q.quarantine_filename}`}
                            >
                              <Archive size={11} color="#64748b" />
                              <span>{q.quarantine_filename}</span>
                            </span>

                            {q.sha256 && (
                              <span
                                style={{
                                  fontFamily: 'monospace',
                                  fontSize: '10px',
                                  background: '#0f172a',
                                  color: '#38bdf8',
                                  padding: '2px 6px',
                                  borderRadius: '4px',
                                }}
                                title={`Cryptographic SHA-256: ${q.sha256}`}
                              >
                                SHA: {q.sha256.substring(0, 16)}...
                              </span>
                            )}
                          </div>
                        </div>
                      </td>

                      <td style={{ padding: '16px 16px', fontSize: '12.5px', color: '#334155', fontWeight: 600, whiteSpace: 'nowrap' }}>
                        {(q.file_size / 1024).toFixed(1)} KB
                      </td>

                      <td style={{ padding: '16px 16px', fontSize: '12px', color: '#64748b', whiteSpace: 'nowrap' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                          <Clock size={12} color="#94a3b8" />
                          <span>{q.quarantined_at}</span>
                        </div>
                        {q.restored_at && (
                          <div style={{ fontSize: '11px', color: '#059669', marginTop: '2px' }}>
                            Restored: {q.restored_at}
                          </div>
                        )}
                      </td>

                      <td style={{ padding: '16px 16px', whiteSpace: 'nowrap' }}>
                        <span className={`webcare-status-chip webcare-status-chip-${q.status === 'quarantined' ? 'quarantined' : 'repaired'}`}>
                          {q.status === 'quarantined' ? (
                            <>
                              <Archive size={11} />
                              <span>QUARANTINED</span>
                            </>
                          ) : (
                            <>
                              <Check size={11} />
                              <span>RESTORED</span>
                            </>
                          )}
                        </span>
                      </td>

                      <td style={{ padding: '16px 20px', textAlign: 'right', whiteSpace: 'nowrap' }}>
                        <div style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', justifyContent: 'flex-end' }}>
                          {q.status === 'quarantined' ? (
                            <>
                              <InlineConfirmPopover
                                buttonLabel="Restore"
                                buttonIcon={<RotateCcw size={12} className={isBusy ? 'webcare-spin-icon' : ''} />}
                                buttonClass="webcare-btn webcare-quarantine-btn-restore"
                                disabled={isBusy}
                                variant="primary"
                                question={`Restore "${q.original_path.split('/').pop() || q.original_path}"?`}
                                consequence={`Will decrypt and write this file back to ${q.original_path}`}
                                confirmLabel="Restore File"
                                onConfirm={() => handleRestore(q)}
                              />

                              <InlineConfirmPopover
                                buttonLabel="Delete"
                                buttonIcon={<Trash2 size={12} />}
                                buttonClass="webcare-btn webcare-quarantine-btn-delete"
                                disabled={isBusy}
                                variant="danger"
                                question={`Delete isolated vault file?`}
                                consequence="This will permanently delete this quarantined file from storage vault. This cannot be undone."
                                confirmLabel="Delete Vault File"
                                onConfirm={() => handleDelete(q)}
                              />
                            </>
                          ) : (
                            <InlineConfirmPopover
                              buttonLabel="Clear Log"
                              buttonIcon={<Trash2 size={12} />}
                              buttonClass="webcare-btn webcare-quarantine-btn-clear-log"
                              disabled={isBusy}
                              variant="warning"
                              question="Remove entry from vault history?"
                              consequence="The restored file on your website will remain active. Only the audit entry is removed."
                              confirmLabel="Remove Entry"
                              onConfirm={() => handleDelete(q)}
                            />
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <ConfirmDialog
        isOpen={confirmClearRestoredOpen}
        title="Clear Restored Vault History"
        message="Are you sure you want to clear all restored records from the vault history? All restored files on your website will remain active and completely untouched. This only cleans up historical audit log records."
        targetItem={`${restoredCount} Restored History Records`}
        confirmLabel="Clear Vault History"
        variant="warning"
        isLoading={loading}
        onConfirm={handleClearAllRestored}
        onClose={() => setConfirmClearRestoredOpen(false)}
      />
    </div>
  );
};

export default QuarantinePage;
