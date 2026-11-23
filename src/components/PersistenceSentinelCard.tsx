import { useState, useEffect } from '@wordpress/element';
import { showConfirm } from '../utils/dialog';
import {
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  AlertTriangle,
  RotateCcw,
  Zap,
  Trash2,
  Database,
  FileCode,
  Layers,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Wand2,
  CheckCircle2,
  Clock,
  Sparkles,
  Flame,
  Radio
} from 'lucide-react';

interface MuPluginItem {
  filename: string;
  path: string;
  relative_path: string;
  size: number;
  size_formatted: string;
  mtime: number;
  modified_human: string;
  status: 'clean' | 'warning' | 'malicious';
  threat_summary: string;
  snippet?: string;
  evidence?: string;
}

interface DropinItem {
  filename: string;
  path: string;
  relative_path: string;
  purpose: string;
  is_unexpected: boolean;
  size: number;
  size_formatted: string;
  mtime: number;
  modified_human: string;
  status: 'clean' | 'unauthorized' | 'warning' | 'malicious';
  threat_summary: string;
  snippet?: string;
  evidence?: string;
}

interface AutoloadOptionItem {
  option_id: number;
  option_name: string;
  size: number;
  size_formatted: string;
  severity: 'critical' | 'high' | 'medium';
  reason: string;
  snippet?: string;
}

interface CronTaskItem {
  hook: string;
  timestamp: number;
  next_run_human: string;
  has_callback: boolean;
  severity: 'critical' | 'high' | 'info';
  reason: string;
}

interface ResurrectionItem {
  backup_id: string;
  file_path: string;
  filename: string;
  original_action: string;
  remediated_at: string;
  current_mtime: number;
  current_mtime_human: string;
  timeline_human: string;
  diff_human: string;
  threat_reason: string;
}

interface PersistenceAuditData {
  success: boolean;
  is_healthy: boolean;
  total_threats: number;
  kpis: {
    mu_plugins_count: number;
    mu_threats_count: number;
    dropins_count: number;
    dropin_threats_count: number;
    autoload_threats: number;
    cron_threats_count: number;
    resurrections_count: number;
  };
  mu_plugins: MuPluginItem[];
  dropins: DropinItem[];
  autoload_options: AutoloadOptionItem[];
  cron_tasks: CronTaskItem[];
  resurrections: ResurrectionItem[];
}

interface PersistenceSentinelCardProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  onPersistenceUpdated?: () => void;
}

export function PersistenceSentinelCard({ apiRequest, onPersistenceUpdated }: PersistenceSentinelCardProps) {
  const [loading, setLoading] = useState<boolean>(false);
  const [neutralizing, setNeutralizing] = useState<boolean>(false);
  const [auditData, setAuditData] = useState<PersistenceAuditData | null>(null);
  const [activeVectorTab, setActiveVectorTab] = useState<'mu' | 'dropins' | 'autoload' | 'crons' | 'resurrections'>('resurrections');
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const runAudit = async () => {
    setLoading(true);
    setErrorMessage(null);
    try {
      const res: PersistenceAuditData = await apiRequest({
        path: '/webcare-pro-security/v1/persistence/audit',
        method: 'GET',
      });
      if (res && res.success) {
        setAuditData(res);
        // Prioritize showing active resurrections or threats
        if (res.kpis.resurrections_count > 0) {
          setActiveVectorTab('resurrections');
        } else if (res.kpis.dropin_threats_count > 0) {
          setActiveVectorTab('dropins');
        } else if (res.kpis.autoload_threats > 0) {
          setActiveVectorTab('autoload');
        } else if (res.kpis.mu_threats_count > 0) {
          setActiveVectorTab('mu');
        } else if (res.kpis.cron_threats_count > 0) {
          setActiveVectorTab('crons');
        }
      }
    } catch (err: any) {
      console.error('Failed to audit persistence vectors', err);
      setErrorMessage(err.message || 'Failed to complete persistence audit.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runAudit();
  }, []);

  // Neutralize Single Item
  const handleNeutralizeItem = async (type: string, id: string, name: string) => {
    const confirmed = await showConfirm({
      title: 'Neutralize Persistence Anchor',
      message: `Neutralize and isolate persistence anchor: ${name}?\nA safety snapshot will be saved in the Cryptographic Vault.`,
      confirmLabel: 'Neutralize Anchor',
      variant: 'danger',
    });
    if (!confirmed) {
      return;
    }

    setNeutralizing(true);
    setSuccessMessage(null);
    setErrorMessage(null);

    try {
      const res: any = await apiRequest({
        path: '/webcare-pro-security/v1/persistence/neutralize',
        method: 'POST',
        data: { type, id },
      });

      if (res && res.success) {
        setSuccessMessage(res.message);
        if (onPersistenceUpdated) {
          onPersistenceUpdated();
        }
        await runAudit();
      } else {
        setErrorMessage(res.message || 'Failed to neutralize item.');
      }
    } catch (err: any) {
      console.error(err);
      setErrorMessage(err.message || 'Error executing neutralization.');
    } finally {
      setNeutralizing(false);
    }
  };

  // Neutralize All Items
  const handleNeutralizeAll = async () => {
    const confirmed = await showConfirm({
      title: 'Mass Persistence Neutralization',
      message: 'Execute 1-Click Mass Neutralization across all identified malicious persistence anchors?\n\nThis will purge rogue drop-ins, unregister rogue crons, delete malicious autoload options, and isolate resurrected files with automated vault rollback.',
      confirmLabel: 'Neutralize All Anchors',
      variant: 'danger',
    });
    if (!confirmed) {
      return;
    }

    setNeutralizing(true);
    setSuccessMessage(null);
    setErrorMessage(null);

    try {
      const res: any = await apiRequest({
        path: '/webcare-pro-security/v1/persistence/neutralize',
        method: 'POST',
        data: { bulk: true },
      });

      if (res && res.success) {
        setSuccessMessage(res.message);
        if (onPersistenceUpdated) {
          onPersistenceUpdated();
        }
        await runAudit();
      } else {
        setErrorMessage(res.message || 'Failed to complete mass neutralization.');
      }
    } catch (err: any) {
      console.error(err);
      setErrorMessage(err.message || 'Error executing mass neutralization.');
    } finally {
      setNeutralizing(false);
    }
  };

  const isClean = auditData?.is_healthy;
  const totalThreats = auditData?.total_threats || 0;

  return (
    <div className="webcare-card webcare-forensics-subcard" style={{ marginBottom: '24px' }}>
      {/* Header Strip */}
      <div className="webcare-forensics-subcard-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span style={{ display: 'inline-flex', padding: '6px', borderRadius: '8px', background: isClean ? 'var(--webcare-status-clean-soft, rgba(16, 185, 129, 0.15))' : 'var(--webcare-status-critical-soft, rgba(239, 68, 68, 0.15))', color: isClean ? 'var(--webcare-status-clean, #059669)' : 'var(--webcare-status-critical, #dc2626)' }}>
              {isClean ? <ShieldCheck size={20} /> : <Flame size={20} />}
            </span>
            <h3 className="webcare-forensics-subcard-title">
              Self-Healing Malware &amp; Multi-Persistence Hunter
            </h3>
            <span
              className={`webcare-badge-pill ${isClean ? 'webcare-badge-clean' : 'webcare-badge-danger'}`}
              style={{ fontWeight: 700 }}
            >
              {loading ? 'Auditing Anchors...' : isClean ? '● No Persistence Vectors Active' : `● ${totalThreats} Anchors Identified`}
            </span>
          </div>
          <p className="webcare-forensics-subcard-desc">
            Detects multi-vector malware persistence (EtherHiding, Balada, SocGholish) designed to resurrect after file cleanup: scans Must-Use plugins, rogue PHP drop-ins, database autoload anchors, orphan cron triggers, and monitors self-healing re-infection loops.
          </p>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            type="button"
            className="webcare-btn webcare-btn-secondary"
            onClick={runAudit}
            disabled={loading || neutralizing}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', padding: '8px 14px' }}
          >
            <RefreshCw size={14} className={loading ? 'webcare-spin-icon' : ''} />
            {loading ? 'Auditing...' : 'Analyze Persistence'}
          </button>

          <button
            type="button"
            className="webcare-btn webcare-btn-primary"
            onClick={handleNeutralizeAll}
            disabled={loading || neutralizing || totalThreats === 0}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '13px',
              padding: '8px 16px',
              background: totalThreats === 0 ? '#94a3b8' : 'linear-gradient(135deg, #7c3aed, #4f46e5)',
              border: 'none',
              boxShadow: totalThreats === 0 ? 'none' : '0 2px 4px rgba(124, 58, 237, 0.25)',
              cursor: totalThreats === 0 ? 'not-allowed' : 'pointer'
            }}
          >
            <Wand2 size={15} />
            {neutralizing ? 'Neutralizing Anchors...' : '1-Click Neutralize All Anchors'}
          </button>
        </div>
      </div>

      {/* Notifications */}
      {successMessage && (
        <div style={{ padding: '12px 16px', background: '#ecfdf5', border: '1px solid #a7f3d0', borderRadius: '8px', color: '#047857', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <CheckCircle2 size={18} style={{ flexShrink: 0 }} />
          <span style={{ fontSize: '13px', fontWeight: 600 }}>{successMessage}</span>
        </div>
      )}

      {errorMessage && (
        <div style={{ padding: '12px 16px', background: '#fef2f2', border: '1px solid #fecaca', borderRadius: '8px', color: '#b91c1c', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <AlertTriangle size={18} style={{ flexShrink: 0 }} />
          <span style={{ fontSize: '13px', fontWeight: 600 }}>{errorMessage}</span>
        </div>
      )}

      {/* KPI Tiles Strip */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '12px', marginBottom: '20px' }}>
        {/* KPI 1: Resurrections */}
        <div
          onClick={() => setActiveVectorTab('resurrections')}
          style={{
            background: (auditData?.kpis?.resurrections_count || 0) > 0 ? '#fff1f2' : '#f8fafc',
            padding: '14px',
            borderRadius: '8px',
            border: `1px solid ${(auditData?.kpis?.resurrections_count || 0) > 0 ? '#fecdd3' : '#e2e8f0'}`,
            cursor: 'pointer'
          }}
        >
          <div style={{ fontSize: '11px', fontWeight: 700, color: (auditData?.kpis?.resurrections_count || 0) > 0 ? '#e11d48' : '#64748b', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '4px' }}>
            Resurrection Loops
          </div>
          <div style={{ fontSize: '20px', fontWeight: 800, color: (auditData?.kpis?.resurrections_count || 0) > 0 ? '#e11d48' : '#059669' }}>
            {loading ? '...' : (auditData?.kpis?.resurrections_count || 0)}
          </div>
          <div style={{ fontSize: '11px', color: (auditData?.kpis?.resurrections_count || 0) > 0 ? '#f43f5e' : '#94a3b8', marginTop: '2px' }}>
            {(auditData?.kpis?.resurrections_count || 0) > 0 ? 'Self-Healing Active!' : '0 re-infections'}
          </div>
        </div>

        {/* KPI 2: Drop-ins */}
        <div
          onClick={() => setActiveVectorTab('dropins')}
          style={{
            background: (auditData?.kpis?.dropin_threats_count || 0) > 0 ? '#fff7ed' : '#f8fafc',
            padding: '14px',
            borderRadius: '8px',
            border: `1px solid ${(auditData?.kpis?.dropin_threats_count || 0) > 0 ? '#fed7aa' : '#e2e8f0'}`,
            cursor: 'pointer'
          }}
        >
          <div style={{ fontSize: '11px', fontWeight: 700, color: (auditData?.kpis?.dropin_threats_count || 0) > 0 ? '#ea580c' : '#64748b', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '4px' }}>
            Drop-In Files
          </div>
          <div style={{ fontSize: '20px', fontWeight: 800, color: (auditData?.kpis?.dropin_threats_count || 0) > 0 ? '#ea580c' : '#0f172a' }}>
            {loading ? '...' : `${auditData?.kpis?.dropins_count || 0}`}
          </div>
          <div style={{ fontSize: '11px', color: (auditData?.kpis?.dropin_threats_count || 0) > 0 ? '#f97316' : '#94a3b8', marginTop: '2px' }}>
            {(auditData?.kpis?.dropin_threats_count || 0) > 0 ? `${auditData?.kpis?.dropin_threats_count} Suspicious / Loose` : 'Standard / Authorized'}
          </div>
        </div>

        {/* KPI 3: MU-Plugins */}
        <div
          onClick={() => setActiveVectorTab('mu')}
          style={{
            background: (auditData?.kpis?.mu_threats_count || 0) > 0 ? '#fef2f2' : '#f8fafc',
            padding: '14px',
            borderRadius: '8px',
            border: `1px solid ${(auditData?.kpis?.mu_threats_count || 0) > 0 ? '#fecaca' : '#e2e8f0'}`,
            cursor: 'pointer'
          }}
        >
          <div style={{ fontSize: '11px', fontWeight: 700, color: (auditData?.kpis?.mu_threats_count || 0) > 0 ? '#dc2626' : '#64748b', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '4px' }}>
            Must-Use (MU) Plugins
          </div>
          <div style={{ fontSize: '20px', fontWeight: 800, color: (auditData?.kpis?.mu_threats_count || 0) > 0 ? '#dc2626' : '#0f172a' }}>
            {loading ? '...' : `${auditData?.kpis?.mu_plugins_count || 0}`}
          </div>
          <div style={{ fontSize: '11px', color: (auditData?.kpis?.mu_threats_count || 0) > 0 ? '#ef4444' : '#94a3b8', marginTop: '2px' }}>
            {(auditData?.kpis?.mu_threats_count || 0) > 0 ? `${auditData?.kpis?.mu_threats_count} Threat Detected` : 'All Verified'}
          </div>
        </div>

        {/* KPI 4: Autoload Database Anchors */}
        <div
          onClick={() => setActiveVectorTab('autoload')}
          style={{
            background: (auditData?.kpis?.autoload_threats || 0) > 0 ? '#fff1f2' : '#f8fafc',
            padding: '14px',
            borderRadius: '8px',
            border: `1px solid ${(auditData?.kpis?.autoload_threats || 0) > 0 ? '#fecdd3' : '#e2e8f0'}`,
            cursor: 'pointer'
          }}
        >
          <div style={{ fontSize: '11px', fontWeight: 700, color: (auditData?.kpis?.autoload_threats || 0) > 0 ? '#e11d48' : '#64748b', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '4px' }}>
            Database Autoloads
          </div>
          <div style={{ fontSize: '20px', fontWeight: 800, color: (auditData?.kpis?.autoload_threats || 0) > 0 ? '#e11d48' : '#059669' }}>
            {loading ? '...' : (auditData?.kpis?.autoload_threats || 0)}
          </div>
          <div style={{ fontSize: '11px', color: (auditData?.kpis?.autoload_threats || 0) > 0 ? '#f43f5e' : '#94a3b8', marginTop: '2px' }}>
            {(auditData?.kpis?.autoload_threats || 0) > 0 ? 'Malicious Payloads' : 'Clean & Non-Executable'}
          </div>
        </div>

        {/* KPI 5: Scheduled Cron Sentinel */}
        <div
          onClick={() => setActiveVectorTab('crons')}
          style={{
            background: (auditData?.kpis?.cron_threats_count || 0) > 0 ? '#fff7ed' : '#f8fafc',
            padding: '14px',
            borderRadius: '8px',
            border: `1px solid ${(auditData?.kpis?.cron_threats_count || 0) > 0 ? '#fed7aa' : '#e2e8f0'}`,
            cursor: 'pointer'
          }}
        >
          <div style={{ fontSize: '11px', fontWeight: 700, color: (auditData?.kpis?.cron_threats_count || 0) > 0 ? '#ea580c' : '#64748b', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '4px' }}>
            Orphan Cron Tasks
          </div>
          <div style={{ fontSize: '20px', fontWeight: 800, color: (auditData?.kpis?.cron_threats_count || 0) > 0 ? '#ea580c' : '#059669' }}>
            {loading ? '...' : (auditData?.kpis?.cron_threats_count || 0)}
          </div>
          <div style={{ fontSize: '11px', color: (auditData?.kpis?.cron_threats_count || 0) > 0 ? '#f97316' : '#94a3b8', marginTop: '2px' }}>
            {(auditData?.kpis?.cron_threats_count || 0) > 0 ? 'Orphan / Zombie Hooks' : 'All Callbacks Valid'}
          </div>
        </div>
      </div>

      {/* Vector Sub-Tab Navigation Bar */}
      <div style={{ display: 'flex', gap: '8px', borderBottom: '2px solid #e2e8f0', marginBottom: '16px', overflowX: 'auto' }}>
        {[
          { id: 'resurrections', label: `Resurrection Loops (${auditData?.resurrections?.length || 0})`, alert: (auditData?.resurrections?.length || 0) > 0 },
          { id: 'dropins', label: `Drop-Ins & Loose Files (${auditData?.dropins?.length || 0})`, alert: (auditData?.kpis?.dropin_threats_count || 0) > 0 },
          { id: 'mu', label: `Must-Use Plugins (${auditData?.mu_plugins?.length || 0})`, alert: (auditData?.kpis?.mu_threats_count || 0) > 0 },
          { id: 'autoload', label: `Autoload DB Anchors (${auditData?.autoload_options?.length || 0})`, alert: (auditData?.autoload_options?.length || 0) > 0 },
          { id: 'crons', label: `Orphan & Rogue Crons (${auditData?.cron_tasks?.length || 0})`, alert: (auditData?.cron_tasks?.length || 0) > 0 },
        ].map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveVectorTab(tab.id as any)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '10px 16px',
              fontSize: '13px',
              fontWeight: activeVectorTab === tab.id ? 700 : 500,
              color: activeVectorTab === tab.id ? '#7c3aed' : '#64748b',
              background: 'transparent',
              border: 'none',
              borderBottom: activeVectorTab === tab.id ? '3px solid #7c3aed' : '3px solid transparent',
              cursor: 'pointer',
              marginBottom: '-2px',
              whiteSpace: 'nowrap'
            }}
          >
            {tab.label}
            {tab.alert && (
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#dc2626' }} />
            )}
          </button>
        ))}
      </div>

      {/* Tab 1: Resurrection Loops */}
      {activeVectorTab === 'resurrections' && (
        <div>
          {(!auditData?.resurrections || auditData.resurrections.length === 0) ? (
            <div style={{ padding: '36px', textAlign: 'center', background: 'var(--webcare-bg-surface, #f8fafc)', borderRadius: '8px', border: '1px dashed #cbd5e1' }}>
              <ShieldCheck size={36} color="#059669" style={{ margin: '0 auto 8px auto' }} />
              <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>No Resurrection Loops Detected</div>
              <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
                All previously remediated files remain clean. No automated re-infection or self-healing activity detected across monitored backups.
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {auditData.resurrections.map((res, i) => (
                <div key={i} style={{ padding: '16px', background: '#fff1f2', border: '1px solid #fecdd3', borderRadius: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '10px' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ background: '#e11d48', color: 'var(--webcare-bg-card, #ffffff)', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 800 }}>
                          SELF-HEALING DETECTED
                        </span>
                        <code style={{ fontSize: '13px', fontWeight: 700, color: '#9f1239' }}>{res.file_path}</code>
                      </div>
                      <div style={{ fontSize: '13px', color: '#be123c', marginTop: '6px' }}>
                        File was previously neutralized via WebCare (<strong>{res.original_action}</strong>) at {res.remediated_at}, but re-appeared or re-infected <strong>{res.timeline_human}</strong>.
                      </div>
                      <div style={{ fontSize: '12px', color: '#881337', marginTop: '4px', fontFamily: 'monospace' }}>
                        Threat: {res.threat_reason}
                      </div>
                    </div>
                    <button
                      type="button"
                      className="webcare-btn"
                      onClick={() => handleNeutralizeItem('resurrected_file', res.file_path, res.filename)}
                      disabled={neutralizing}
                      style={{ background: '#be123c', color: 'var(--webcare-bg-card, #ffffff)', border: 'none', padding: '6px 12px', borderRadius: '6px', fontSize: '12px', fontWeight: 600, cursor: 'pointer' }}
                    >
                      Isolate & Re-Quarantine
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Drop-Ins & Loose Files */}
      {activeVectorTab === 'dropins' && (
        <div style={{ overflowX: 'auto' }}>
          {(!auditData?.dropins || auditData.dropins.length === 0) ? (
            <div style={{ padding: '36px', textAlign: 'center', background: 'var(--webcare-bg-surface, #f8fafc)', borderRadius: '8px', border: '1px dashed #cbd5e1' }}>
              <ShieldCheck size={36} color="#059669" style={{ margin: '0 auto 8px auto' }} />
              <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>No Drop-Ins or Loose Files</div>
              <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>wp-content root directory is clean of unmanaged or suspicious PHP files.</div>
            </div>
          ) : (
            <table className="webcare-table-modern" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: 'var(--webcare-bg-surface, #f8fafc)', borderBottom: '1px solid #e2e8f0' }}>
                  <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: '12px' }}>Drop-in / File</th>
                  <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: '12px' }}>Purpose / Verification</th>
                  <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: '12px' }}>Modified</th>
                  <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: '12px' }}>Status</th>
                  <th style={{ padding: '10px 14px', textAlign: 'right', fontSize: '12px' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {auditData.dropins.map((d, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid #f1f5f9', background: (d.status === 'malicious' || d.is_unexpected) ? '#fff5f5' : d.status === 'unauthorized' ? '#fffbeb' : 'var(--webcare-bg-card, #ffffff)' }}>
                    <td style={{ padding: '12px 14px' }}>
                      <code style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>{d.filename}</code>
                      <div style={{ fontSize: '11px', color: '#64748b' }}>{d.size_formatted}</div>
                    </td>
                    <td style={{ padding: '12px 14px' }}>
                      <div style={{ fontSize: '12px', fontWeight: 600, color: '#334155' }}>{d.purpose}</div>
                      <div style={{ fontSize: '11px', color: d.status === 'clean' ? '#059669' : '#dc2626' }}>{d.threat_summary}</div>
                      {d.snippet && (
                        <code style={{ display: 'block', fontSize: '10px', color: '#b91c1c', background: 'rgba(239, 68, 68, 0.1)', padding: '2px 4px', borderRadius: '4px', marginTop: '4px', maxWidth: '380px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {d.snippet}
                        </code>
                      )}
                    </td>
                    <td style={{ padding: '12px 14px', fontSize: '12px', color: '#64748b' }}>
                      {d.modified_human}
                    </td>
                    <td style={{ padding: '12px 14px' }}>
                      <span className="webcare-badge" style={{
                        background: d.status === 'clean' ? '#ecfdf5' : d.status === 'unauthorized' ? '#fef3c7' : '#fee2e2',
                        color: d.status === 'clean' ? '#059669' : d.status === 'unauthorized' ? '#b45309' : '#dc2626',
                        fontSize: '11px',
                        fontWeight: 700,
                        textTransform: 'uppercase'
                      }}>
                        {d.status}
                      </span>
                    </td>
                    <td style={{ padding: '12px 14px', textAlign: 'right' }}>
                      {(d.status !== 'clean') && (
                        <button
                          type="button"
                          className="webcare-btn"
                          onClick={() => handleNeutralizeItem('dropin', d.path, d.filename)}
                          disabled={neutralizing}
                          style={{ background: '#dc2626', color: 'var(--webcare-bg-card, #ffffff)', border: 'none', padding: '5px 10px', borderRadius: '5px', fontSize: '11px', fontWeight: 600, cursor: 'pointer' }}
                        >
                          Quarantine
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Tab 3: Must-Use Plugins */}
      {activeVectorTab === 'mu' && (
        <div style={{ overflowX: 'auto' }}>
          {(!auditData?.mu_plugins || auditData.mu_plugins.length === 0) ? (
            <div style={{ padding: '36px', textAlign: 'center', background: 'var(--webcare-bg-surface, #f8fafc)', borderRadius: '8px', border: '1px dashed #cbd5e1' }}>
              <ShieldCheck size={36} color="#059669" style={{ margin: '0 auto 8px auto' }} />
              <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>No Must-Use Plugins Installed</div>
              <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>wp-content/mu-plugins directory does not exist or is empty.</div>
            </div>
          ) : (
            <table className="webcare-table-modern" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: 'var(--webcare-bg-surface, #f8fafc)', borderBottom: '1px solid #e2e8f0' }}>
                  <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: '12px' }}>MU-Plugin File</th>
                  <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: '12px' }}>AST Token Audit</th>
                  <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: '12px' }}>Modified</th>
                  <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: '12px' }}>Status</th>
                  <th style={{ padding: '10px 14px', textAlign: 'right', fontSize: '12px' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {auditData.mu_plugins.map((m, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid #f1f5f9', background: m.status === 'malicious' ? '#fff5f5' : m.status === 'warning' ? '#fffbeb' : 'var(--webcare-bg-card, #ffffff)' }}>
                    <td style={{ padding: '12px 14px' }}>
                      <code style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>{m.filename}</code>
                      <div style={{ fontSize: '11px', color: '#64748b' }}>{m.size_formatted}</div>
                    </td>
                    <td style={{ padding: '12px 14px' }}>
                      <div style={{ fontSize: '12px', color: m.status === 'clean' ? '#059669' : '#b91c1c', fontWeight: 500 }}>
                        {m.threat_summary}
                      </div>
                      {m.snippet && (
                        <code style={{ display: 'block', fontSize: '10px', color: '#b91c1c', background: 'rgba(239, 68, 68, 0.1)', padding: '2px 4px', borderRadius: '4px', marginTop: '4px', maxWidth: '380px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {m.snippet}
                        </code>
                      )}
                    </td>
                    <td style={{ padding: '12px 14px', fontSize: '12px', color: '#64748b' }}>
                      {m.modified_human}
                    </td>
                    <td style={{ padding: '12px 14px' }}>
                      <span className="webcare-badge" style={{
                        background: m.status === 'clean' ? '#ecfdf5' : m.status === 'warning' ? '#fef3c7' : '#fee2e2',
                        color: m.status === 'clean' ? '#059669' : m.status === 'warning' ? '#b45309' : '#dc2626',
                        fontSize: '11px',
                        fontWeight: 700,
                        textTransform: 'uppercase'
                      }}>
                        {m.status}
                      </span>
                    </td>
                    <td style={{ padding: '12px 14px', textAlign: 'right' }}>
                      {(m.status !== 'clean') && (
                        <button
                          type="button"
                          className="webcare-btn"
                          onClick={() => handleNeutralizeItem('mu_plugin', m.path, m.filename)}
                          disabled={neutralizing}
                          style={{ background: '#dc2626', color: 'var(--webcare-bg-card, #ffffff)', border: 'none', padding: '5px 10px', borderRadius: '5px', fontSize: '11px', fontWeight: 600, cursor: 'pointer' }}
                        >
                          Quarantine
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Tab 4: Database Autoload Options */}
      {activeVectorTab === 'autoload' && (
        <div style={{ overflowX: 'auto' }}>
          {(!auditData?.autoload_options || auditData.autoload_options.length === 0) ? (
            <div style={{ padding: '36px', textAlign: 'center', background: 'var(--webcare-bg-surface, #f8fafc)', borderRadius: '8px', border: '1px dashed #cbd5e1' }}>
              <ShieldCheck size={36} color="#059669" style={{ margin: '0 auto 8px auto' }} />
              <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>No Autoload Payload Anchors</div>
              <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>Scanned autoloaded wp_options and transients. Zero embedded executable tags or EtherHiding Web3 C2 blobs found.</div>
            </div>
          ) : (
            <table className="webcare-table-modern" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: 'var(--webcare-bg-surface, #f8fafc)', borderBottom: '1px solid #e2e8f0' }}>
                  <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: '12px' }}>Option Name</th>
                  <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: '12px' }}>Threat Diagnostic</th>
                  <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: '12px' }}>Payload Preview</th>
                  <th style={{ padding: '10px 14px', textAlign: 'right', fontSize: '12px' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {auditData.autoload_options.map((opt, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid #f1f5f9', background: '#fff5f5' }}>
                    <td style={{ padding: '12px 14px' }}>
                      <code style={{ fontSize: '13px', fontWeight: 700, color: '#b91c1c' }}>{opt.option_name}</code>
                      <div style={{ fontSize: '11px', color: '#64748b' }}>Size: {opt.size_formatted}</div>
                    </td>
                    <td style={{ padding: '12px 14px', fontSize: '12px', color: '#991b1b', maxWidth: '300px' }}>
                      {opt.reason}
                    </td>
                    <td style={{ padding: '12px 14px', maxWidth: '300px' }}>
                      {opt.snippet && (
                        <code style={{ display: 'block', fontSize: '11px', color: '#b91c1c', background: '#fee2e2', padding: '4px 6px', borderRadius: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {opt.snippet}
                        </code>
                      )}
                    </td>
                    <td style={{ padding: '12px 14px', textAlign: 'right' }}>
                      <button
                        type="button"
                        className="webcare-btn"
                        onClick={() => handleNeutralizeItem('autoload_option', opt.option_name, opt.option_name)}
                        disabled={neutralizing}
                        style={{ background: '#b91c1c', color: 'var(--webcare-bg-card, #ffffff)', border: 'none', padding: '5px 10px', borderRadius: '5px', fontSize: '11px', fontWeight: 600, cursor: 'pointer' }}
                      >
                        Delete Option
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Tab 5: Scheduled Cron Tasks */}
      {activeVectorTab === 'crons' && (
        <div style={{ overflowX: 'auto' }}>
          {(!auditData?.cron_tasks || auditData.cron_tasks.length === 0) ? (
            <div style={{ padding: '36px', textAlign: 'center', background: 'var(--webcare-bg-surface, #f8fafc)', borderRadius: '8px', border: '1px dashed #cbd5e1' }}>
              <ShieldCheck size={36} color="#059669" style={{ margin: '0 auto 8px auto' }} />
              <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>All Scheduled Crons Verified</div>
              <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>Every scheduled wp-cron task has a verified active callback function. Zero orphan or rogue closures detected.</div>
            </div>
          ) : (
            <table className="webcare-table-modern" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: 'var(--webcare-bg-surface, #f8fafc)', borderBottom: '1px solid #e2e8f0' }}>
                  <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: '12px' }}>Hook Name</th>
                  <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: '12px' }}>Next Scheduled</th>
                  <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: '12px' }}>Diagnostic Reason</th>
                  <th style={{ padding: '10px 14px', textAlign: 'right', fontSize: '12px' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {auditData.cron_tasks.map((cron, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid #f1f5f9', background: cron.severity === 'critical' ? '#fff5f5' : '#fffbeb' }}>
                    <td style={{ padding: '12px 14px' }}>
                      <code style={{ fontSize: '13px', fontWeight: 700, color: cron.severity === 'critical' ? '#b91c1c' : '#b45309' }}>{cron.hook}</code>
                    </td>
                    <td style={{ padding: '12px 14px', fontSize: '12px', color: '#64748b' }}>
                      {cron.next_run_human}
                    </td>
                    <td style={{ padding: '12px 14px', fontSize: '12px', color: cron.severity === 'critical' ? '#991b1b' : '#92400e' }}>
                      {cron.reason}
                    </td>
                    <td style={{ padding: '12px 14px', textAlign: 'right' }}>
                      <button
                        type="button"
                        className="webcare-btn"
                        onClick={() => handleNeutralizeItem('cron_hook', cron.hook, cron.hook)}
                        disabled={neutralizing}
                        style={{ background: '#dc2626', color: 'var(--webcare-bg-card, #ffffff)', border: 'none', padding: '5px 10px', borderRadius: '5px', fontSize: '11px', fontWeight: 600, cursor: 'pointer' }}
                      >
                        Clear Cron Hook
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

export default PersistenceSentinelCard;
