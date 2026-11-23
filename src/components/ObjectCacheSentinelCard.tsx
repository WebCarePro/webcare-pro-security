import { useState, useEffect } from '@wordpress/element';
import {
  Cpu,
  Database,
  HardDrive,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  RefreshCw,
  Zap,
  CheckCircle2,
  AlertTriangle,
  Info,
  Server,
  Lock,
  ArrowRight,
  Layers,
  FileCode,
  Flame
} from 'lucide-react';
import { ConfirmDialog } from './ConfirmDialog';

interface CriticalIssue {
  option_name: string;
  label: string;
  db_value: string;
  ram_value: string;
  threat_type: string;
  forensics: string;
}

interface CacheDivergence {
  type: string;
  option_name: string;
  db_value: string | null;
  ram_value: string | null;
  severity: string;
  message: string;
}

interface SuspiciousSink {
  option_name: string;
  sink_type: string;
  snippet: string;
  message: string;
}

interface CacheAuditReport {
  status: 'clean' | 'diverged' | 'poisoned';
  parity_score: number;
  environment: {
    is_external_cache: boolean;
    dropin_exists: boolean;
    backend_name: string;
    driver: string;
    dropin_meta?: {
      path: string;
      size: number;
      mtime: number;
      mtime_human: string;
    } | null;
    opcache_active: boolean;
  };
  db_autoload_count: number;
  ram_options_count: number | null;
  alloptions_cached: boolean;
  db_hash: string;
  ram_hash: string | null;
  hash_parity: boolean;
  critical_issues: CriticalIssue[];
  divergences: CacheDivergence[];
  suspicious_sinks: SuspiciousSink[];
  scanned_at: string;
  scanned_timestamp: number;
}

interface ObjectCacheSentinelCardProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
}

export const ObjectCacheSentinelCard = ({ apiRequest }: ObjectCacheSentinelCardProps) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [auditing, setAuditing] = useState<boolean>(false);
  const [flushing, setFlushing] = useState<boolean>(false);
  const [report, setReport] = useState<CacheAuditReport | null>(null);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Modal dialog state
  const [confirmDialog, setConfirmDialog] = useState<{
    isOpen: boolean;
    title: string;
    message: string;
    confirmLabel?: string;
    variant?: 'danger' | 'warning' | 'primary';
    onConfirm: () => void;
  }>({
    isOpen: false,
    title: '',
    message: '',
    onConfirm: () => {},
  });

  const fetchStatus = async () => {
    setLoading(true);
    try {
      const response = await apiRequest({
        path: '/webcare-pro-security/v1/integrity/object-cache/status',
        method: 'GET',
      });

      if (response && response.success && response.report) {
        setReport(response.report);
      }
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || 'Failed to fetch Object Cache Sentinel status.',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleRunAudit = async () => {
    setAuditing(true);
    setFeedback(null);

    try {
      const response = await apiRequest({
        path: '/webcare-pro-security/v1/integrity/object-cache/audit',
        method: 'POST',
      });

      if (response && response.success && response.report) {
        setReport(response.report);
        setFeedback({
          type: 'success',
          message: response.report.status === 'clean'
            ? 'Differential audit complete: 100% RAM vs Disk cryptographic parity verified.'
            : 'Audit complete: Divergences detected between live memory and MySQL database.',
        });
      }
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || 'Failed to complete differential audit.',
      });
    } finally {
      setAuditing(false);
    }
  };

  const handleFlushResync = () => {
    setConfirmDialog({
      isOpen: true,
      title: 'Flush Object Cache & Resynchronize from MySQL',
      message: 'Are you sure you want to purge the live In-Memory Object Cache (Redis / Memcached / APCu)? This will flush all cached keys, clear in-memory option dictionaries, reload pristine options directly from MySQL, and reset OPcache. This safely cures any fileless in-memory tampering.',
      confirmLabel: 'Flush & Resynchronize',
      variant: 'primary',
      onConfirm: async () => {
        setConfirmDialog((prev) => ({ ...prev, isOpen: false }));
        setFlushing(true);
        setFeedback(null);

        try {
          const response = await apiRequest({
            path: '/webcare-pro-security/v1/integrity/object-cache/flush',
            method: 'POST',
          });

          if (response && response.success) {
            if (response.audit) {
              setReport(response.audit);
            }
            setFeedback({
              type: 'success',
              message: response.message || 'Object Cache successfully flushed and resynchronized from MySQL truth.',
            });
          }
        } catch (err: any) {
          setFeedback({
            type: 'error',
            message: err?.message || 'Failed to flush and resynchronize object cache.',
          });
        } finally {
          setFlushing(false);
        }
      },
    });
  };

  if (loading && !report) {
    return (
      <div className="webcare-card" style={{ padding: '32px', textAlign: 'center', marginBottom: '24px' }}>
        <RefreshCw size={24} className="webcare-spin" style={{ margin: '0 auto 12px auto', color: '#4f46e5' }} />
        <p style={{ color: 'var(--webcare-text-secondary, #64748b)', margin: 0, fontSize: '14px' }}>
          Analyzing In-Memory Object Cache (Redis / Memcached / APCu) parity...
        </p>
      </div>
    );
  }

  const isPoisoned = report?.status === 'poisoned';
  const isDiverged = report?.status === 'diverged';
  const isClean = report?.status === 'clean';
  const parityScore = report?.parity_score ?? 100;
  const backendName = report?.environment?.backend_name || 'Internal Memory';
  const isExternalCache = report?.environment?.is_external_cache || false;
  const criticalCount = report?.critical_issues?.length || 0;
  const sinkCount = report?.suspicious_sinks?.length || 0;
  const divergenceCount = report?.divergences?.length || 0;

  return (
    <div className="webcare-card" style={{ padding: '24px', marginBottom: '24px' }}>
      {/* Feedback Alert */}
      {feedback && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '12px 16px',
            borderRadius: '8px',
            fontSize: '13px',
            fontWeight: 500,
            marginBottom: '20px',
            background: feedback.type === 'success' ? 'var(--webcare-badge-clean-bg, #ecfdf5)' : 'var(--webcare-badge-danger-bg, #fef2f2)',
            color: feedback.type === 'success' ? 'var(--webcare-badge-clean-text, #047857)' : 'var(--webcare-badge-danger-text, #dc2626)',
            border: `1px solid ${feedback.type === 'success' ? 'var(--webcare-badge-clean-border, #a7f3d0)' : 'var(--webcare-badge-danger-border, #fecaca)'}`,
          }}
        >
          {feedback.type === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
          <span>{feedback.message}</span>
          <button
            type="button"
            onClick={() => setFeedback(null)}
            style={{ marginLeft: 'auto', background: 'transparent', border: 'none', cursor: 'pointer', color: 'inherit', fontSize: '16px' }}
          >
            &times;
          </button>
        </div>
      )}

      {/* Header Row */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '16px', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
          <div
            style={{
              width: '44px',
              height: '44px',
              borderRadius: '10px',
              background: isPoisoned ? 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)' : 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
              color: '#ffffff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
              boxShadow: isPoisoned ? '0 4px 12px rgba(220, 38, 38, 0.25)' : '0 4px 12px rgba(2, 132, 199, 0.25)',
            }}
          >
            <Cpu size={22} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'var(--webcare-text-heading, #0f172a)' }}>
                In-Memory Object Cache (Redis / Memcached / APCu) Sentinel
              </h3>
              {isPoisoned ? (
                <span className="webcare-badge-pill" style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fecaca' }}>
                  <ShieldAlert size={12} style={{ marginRight: '4px', display: 'inline' }} /> Critical In-Memory Poisoning
                </span>
              ) : isDiverged ? (
                <span className="webcare-badge-pill" style={{ background: '#fffbeb', color: '#d97706', border: '1px solid #fde68a' }}>
                  <AlertTriangle size={12} style={{ marginRight: '4px', display: 'inline' }} /> RAM vs Disk Diverged
                </span>
              ) : (
                <span className="webcare-badge-pill" style={{ background: '#ecfdf5', color: '#047857', border: '1px solid #a7f3d0' }}>
                  <ShieldCheck size={12} style={{ marginRight: '4px', display: 'inline' }} /> 100% Cryptographic Parity
                </span>
              )}
              <span className="webcare-badge-pill" style={{ background: '#f1f5f9', color: '#475569', border: '1px solid #cbd5e1' }}>
                <Layers size={12} style={{ marginRight: '4px', display: 'inline' }} /> {backendName}
              </span>
            </div>
            <p style={{ margin: '6px 0 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5, maxWidth: '820px' }}>
              Defeats fileless, memory-resident WordPress attacks. Compares live in-memory options (<code>alloptions</code>, <code>siteurl</code>, <code>active_plugins</code>)
              directly against MySQL disk truth to uncover stealth redirects, phantom plugin backdoors, and rogue privilege escalations persisting solely in RAM.
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            type="button"
            className="webcare-btn webcare-btn-secondary"
            onClick={handleRunAudit}
            disabled={auditing || flushing}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
          >
            <RefreshCw size={14} className={auditing ? 'webcare-spin' : ''} />
            <span>{auditing ? 'Auditing RAM...' : 'Run Parity Audit'}</span>
          </button>

          <button
            type="button"
            className="webcare-btn webcare-btn-primary"
            onClick={handleFlushResync}
            disabled={auditing || flushing}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
          >
            <Flame size={14} className={flushing ? 'webcare-spin' : ''} />
            <span>{flushing ? 'Resyncing...' : 'Flush & Resynchronize'}</span>
          </button>
        </div>
      </div>

      {/* Critical Threat Alert Box (Displayed when poisoning is active) */}
      {isPoisoned && (
        <div
          style={{
            marginTop: '20px',
            padding: '16px 20px',
            borderRadius: '8px',
            background: 'var(--webcare-badge-danger-bg, #fef2f2)',
            border: '1px solid var(--webcare-badge-danger-border, #fca5a5)',
            display: 'flex',
            flexDirection: 'column',
            gap: '12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <ShieldAlert size={20} style={{ color: '#dc2626', flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 700, fontSize: '14px', color: '#b91c1c' }}>
                URGENT: In-Memory Object Cache Tampering Active!
              </div>
              <div style={{ fontSize: '13px', color: '#7f1d1d', marginTop: '2px' }}>
                Attackers have manipulated live cache memory directly without modifying MySQL. Live visitors are receiving corrupted configurations or malicious redirects directly from RAM.
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '4px' }}>
            {report?.critical_issues.map((crit, idx) => (
              <div
                key={idx}
                style={{
                  padding: '10px 14px',
                  borderRadius: '6px',
                  background: 'rgba(255, 255, 255, 0.85)',
                  border: '1px solid #fecaca',
                  fontSize: '12px',
                  color: '#991b1b',
                }}
              >
                <div style={{ fontWeight: 600 }}>
                  Option: <code>{crit.option_name}</code> ({crit.label})
                </div>
                <div style={{ marginTop: '4px' }}>
                  <strong>Forensic Details:</strong> {crit.forensics}
                </div>
                <div style={{ display: 'flex', gap: '16px', marginTop: '4px', fontFamily: 'monospace' }}>
                  <span>DB Truth: <span style={{ color: '#047857' }}>{crit.db_value}</span></span>
                  <span>Live RAM: <span style={{ color: '#dc2626' }}>{crit.ram_value}</span></span>
                </div>
              </div>
            ))}

            {report?.suspicious_sinks.map((sink, idx) => (
              <div
                key={`sink-${idx}`}
                style={{
                  padding: '10px 14px',
                  borderRadius: '6px',
                  background: 'rgba(255, 255, 255, 0.85)',
                  border: '1px solid #fecaca',
                  fontSize: '12px',
                  color: '#991b1b',
                }}
              >
                <div style={{ fontWeight: 600 }}>
                  Execution Sink: <code>{sink.option_name}</code> ({sink.sink_type})
                </div>
                <div style={{ marginTop: '2px' }}>{sink.message}</div>
                <div style={{ marginTop: '4px', fontFamily: 'monospace', color: '#7f1d1d' }}>
                  Snippet: <code>{sink.snippet}</code>
                </div>
              </div>
            ))}
          </div>

          <div style={{ marginTop: '4px' }}>
            <button
              type="button"
              className="webcare-btn webcare-btn-danger"
              onClick={handleFlushResync}
              disabled={flushing}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '13px' }}
            >
              <Zap size={14} />
              <span>1-Click Surgical Purge: Restore Memory from MySQL Truth</span>
            </button>
          </div>
        </div>
      )}

      {/* Telemetry Metrics Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '16px',
          marginTop: '24px',
          paddingTop: '20px',
          borderTop: '1px solid var(--webcare-border-subtle, #e2e8f0)',
        }}
      >
        <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--webcare-bg-surface, #f8fafc)', border: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>
            RAM-to-Disk Parity Score
          </div>
          <div
            style={{
              fontSize: '24px',
              fontWeight: 700,
              marginTop: '4px',
              color: isClean ? '#10b981' : (isPoisoned ? '#dc2626' : '#d97706'),
            }}
          >
            {parityScore}%
          </div>
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
            {isClean ? 'Cryptographic match' : `${divergenceCount} divergence(s)`}
          </div>
        </div>

        <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--webcare-bg-surface, #f8fafc)', border: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>
            External Cache Drop-in
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--webcare-text-heading, #0f172a)', marginTop: '4px' }}>
            {isExternalCache ? 'Active' : 'Built-in'}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
            {report?.environment?.dropin_exists ? 'wp-content/object-cache.php' : 'WP_Object_Cache RAM'}
          </div>
        </div>

        <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--webcare-bg-surface, #f8fafc)', border: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>
            Critical Vectors Verified
          </div>
          <div
            style={{
              fontSize: '24px',
              fontWeight: 700,
              marginTop: '4px',
              color: criticalCount === 0 ? '#10b981' : '#dc2626',
            }}
          >
            {criticalCount === 0 ? '7 / 7 Secure' : `${criticalCount} Hijacked`}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
            siteurl, home, plugins, roles
          </div>
        </div>

        <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--webcare-bg-surface, #f8fafc)', border: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>
            Autoloaded Options
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--webcare-text-heading, #0f172a)', marginTop: '4px' }}>
            {report?.db_autoload_count || 0}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
            RAM Cached: {report?.ram_options_count !== null ? report.ram_options_count : 'On-Demand'}
          </div>
        </div>
      </div>

      {/* Critical Security Options Matrix */}
      <div style={{ marginTop: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
          <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 600, color: 'var(--webcare-text-heading, #0f172a)' }}>
            Critical Security Options Integrity Matrix
          </h4>
          <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
            Audited directly against MySQL storage
          </span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="webcare-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
                <th style={{ padding: '10px 14px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)' }}>Key / Option</th>
                <th style={{ padding: '10px 14px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)' }}>Vector Description</th>
                <th style={{ padding: '10px 14px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)' }}>Attack Surface Defended</th>
                <th style={{ padding: '10px 14px', textAlign: 'right', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)' }}>Memory Status</th>
              </tr>
            </thead>
            <tbody>
              {[
                { key: 'siteurl', label: 'Site Address (URL)', desc: 'Pre-boot traffic redirect hijack in RAM' },
                { key: 'home', label: 'Home Address (URL)', desc: 'Frontend redirect & canonical host hijacking' },
                { key: 'active_plugins', label: 'Active Plugins List', desc: 'Fileless stealth plugin loader injection' },
                { key: 'default_role', label: 'Default User Role', desc: 'Privilege escalation for new registrations' },
                { key: 'users_can_register', label: 'User Registration Policy', desc: 'Unauthorized user registration opening' },
                { key: 'template', label: 'Active Parent Theme', desc: 'Rogue backdoor theme activation' },
                { key: 'stylesheet', label: 'Active Child Theme', desc: 'Rogue child stylesheet/template override' },
              ].map((item) => {
                const issue = report?.critical_issues.find((c) => c.option_name === item.key);
                return (
                  <tr key={item.key} style={{ borderBottom: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
                    <td style={{ padding: '10px 14px', fontWeight: 600, fontFamily: 'monospace', color: 'var(--webcare-text-heading, #0f172a)' }}>
                      {item.key}
                    </td>
                    <td style={{ padding: '10px 14px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                      {item.label}
                    </td>
                    <td style={{ padding: '10px 14px', color: 'var(--webcare-text-secondary, #475569)' }}>
                      {item.desc}
                    </td>
                    <td style={{ padding: '10px 14px', textAlign: 'right' }}>
                      {issue ? (
                        <span className="webcare-badge-pill" style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fecaca' }}>
                          <AlertTriangle size={11} style={{ marginRight: '4px', display: 'inline' }} /> Hijacked
                        </span>
                      ) : (
                        <span className="webcare-badge-pill" style={{ background: '#ecfdf5', color: '#047857', border: '1px solid #a7f3d0' }}>
                          <CheckCircle2 size={11} style={{ marginRight: '4px', display: 'inline' }} /> Parity Verified
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* SysAdmin Guidance Tip */}
      <div
        style={{
          marginTop: '20px',
          padding: '12px 16px',
          borderRadius: '8px',
          background: 'var(--webcare-bg-surface, #f8fafc)',
          border: '1px solid var(--webcare-border-subtle, #e2e8f0)',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '10px',
          fontSize: '12px',
          color: 'var(--webcare-text-secondary, #475569)',
          lineHeight: 1.5,
        }}
      >
        <Info size={16} style={{ color: '#0284c7', flexShrink: 0, marginTop: '2px' }} />
        <div>
          <strong>SysAdmin Hardening Note:</strong> Ensure your Redis / Memcached daemon is bound strictly to a UNIX domain socket (<code>/var/run/redis/redis.sock</code>)
          or loopback <code>127.0.0.1</code> with strong password authentication (<code>requirepass</code>). Never expose port <code>6379</code> or <code>11211</code> to public or multi-tenant network interfaces.
        </div>
      </div>

      {/* Confirmation Dialog */}
      <ConfirmDialog
        isOpen={confirmDialog.isOpen}
        title={confirmDialog.title}
        message={confirmDialog.message}
        confirmLabel={confirmDialog.confirmLabel}
        variant={confirmDialog.variant}
        onConfirm={confirmDialog.onConfirm}
        onCancel={() => setConfirmDialog((prev) => ({ ...prev, isOpen: false }))}
      />
    </div>
  );
};
