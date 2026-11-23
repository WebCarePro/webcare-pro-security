import { useState, useEffect } from '@wordpress/element';
import { showConfirm } from '../utils/dialog';
import {
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  AlertTriangle,
  Clock,
  Camera,
  History,
  RotateCcw,
  Trash2,
  ExternalLink,
  Lock,
  Globe,
  FileCode,
  CheckCircle2,
  AlertOctagon,
  Eye,
  PlusCircle,
  FileCheck,
  Zap,
  Server,
  Layers,
  Search,
  Check
} from 'lucide-react';
import VisualDiffModal from '../VisualDiffModal';

interface WatchdogItem {
  id: string;
  file_path: string;
  rel_path: string;
  filename: string;
  parent_dir: string;
  expected_status: 'deleted' | 'cleaned';
  clean_hash?: string;
  reason: string;
  remediated_at: number;
  remediated_human: string;
  expires_at: number;
  time_left_seconds: number;
  hours_left: number;
  is_expired: boolean;
  is_reinfected: boolean;
  reinfected_at?: number | null;
  reinfection_desc?: string;
  check_count: number;
}

interface WatchdogAlert {
  alert_id: string;
  watch_id: string;
  file_path: string;
  rel_path: string;
  filename: string;
  detected_at: number;
  detected_iso: string;
  reason: string;
  dismissed: boolean;
}

interface SnapshotItem {
  id: string;
  label: string;
  target_rel: string;
  created_at: string;
  timestamp: number;
  file_count: number;
  archive_bytes: number;
  archive_formatted: string;
  raw_bytes: number;
  raw_formatted: string;
}

interface SnapshotDiffItem {
  rel_path: string;
  status: 'clean' | 'modified' | 'deleted' | 'added_untracked';
  size?: number;
  live_size?: number;
  snapshot_size?: number;
}

interface SnapshotCompareResult {
  snapshot_id: string;
  label: string;
  target_rel: string;
  is_identical: boolean;
  counts: {
    clean: number;
    modified: number;
    deleted: number;
    added: number;
  };
  modified: SnapshotDiffItem[];
  deleted: SnapshotDiffItem[];
  added: SnapshotDiffItem[];
}

interface PreloaderItem {
  type: string;
  directive: string;
  target_file: string;
  is_webcare: boolean;
  file_exists: boolean;
  severity: 'clean' | 'high' | 'critical';
  description: string;
}

interface SystemCronsStatus {
  is_accessible: boolean;
  is_restricted: boolean;
  notice: string;
  checked_paths: Array<{ path: string; exists: boolean; readable: boolean }>;
}

interface DomainReputationReport {
  scanned_at: string;
  domain: string;
  resolved_ip: string;
  is_local_env: boolean;
  reputation_score: number;
  status: 'clean' | 'warning' | 'critical';
  issues: Array<{ type: string; severity: string; message: string }>;
  ssl: {
    status: 'healthy' | 'expiring_soon' | 'expired' | 'unreachable' | 'local_or_ip';
    days_remaining: number;
    issuer: string;
    subject: string;
    valid_to: string;
    sans: string[];
  };
  dns: {
    has_spf: boolean;
    spf_record: string;
    has_dmarc: boolean;
    dmarc_record: string;
    has_mx: boolean;
  };
  dnsbl: {
    total_checked: number;
    total_listed: number;
    is_clean: boolean;
    listed_names: string[];
    providers: Array<{ type: string; host: string; name: string; is_listed: boolean; response: string }>;
  };
}

interface PersistenceWatchdogCardProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  initialSubTab?: 'watchdog' | 'snapshots' | 'preloaders' | 'reputation';
  onSubTabChange?: (sub: 'watchdog' | 'snapshots' | 'preloaders' | 'reputation') => void;
}

export function PersistenceWatchdogCard({ apiRequest, initialSubTab = 'watchdog', onSubTabChange }: PersistenceWatchdogCardProps) {
  const getStartingTab = (): 'watchdog' | 'snapshots' | 'preloaders' | 'reputation' => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const sub = urlParams.get('section') || urlParams.get('subtab');
      if (sub === 'baseline' || sub === 'reputation') return 'reputation';
      if (sub && ['watchdog', 'snapshots', 'preloaders'].includes(sub)) {
        return sub as any;
      }
    } catch (e) {}
    return initialSubTab;
  };

  const [activeTab, setActiveTab] = useState<'watchdog' | 'snapshots' | 'preloaders' | 'reputation'>(getStartingTab);

  useEffect(() => {
    if (initialSubTab && initialSubTab !== activeTab) {
      setActiveTab(initialSubTab);
    }
  }, [initialSubTab]);

  const handleSubTabSwitch = (tab: 'watchdog' | 'snapshots' | 'preloaders' | 'reputation') => {
    setActiveTab(tab);
    const sectionName = tab === 'reputation' ? 'baseline' : tab;
    if (onSubTabChange) {
      onSubTabChange(tab);
    } else {
      try {
        const url = new URL(window.location.href);
        url.searchParams.set('section', sectionName);
        url.searchParams.delete('subtab');
        window.history.pushState({ section: sectionName }, '', url.toString());
      } catch (e) {}
    }
  };
  const [loading, setLoading] = useState<boolean>(false);
  const [actionLoading, setActionLoading] = useState<boolean>(false);

  // Watchdog State
  const [watchdogData, setWatchdogData] = useState<{
    active_count: number;
    expired_count: number;
    reinfected_count: number;
    total_alerts: number;
    next_cron_run?: string;
    active_watches: WatchdogItem[];
    recent_alerts: WatchdogAlert[];
  } | null>(null);

  // Snapshots State
  const [snapshots, setSnapshots] = useState<SnapshotItem[]>([]);
  const [selectedSnapshotId, setSelectedSnapshotId] = useState<string | null>(null);
  const [compareResult, setCompareResult] = useState<SnapshotCompareResult | null>(null);
  const [comparing, setComparing] = useState<boolean>(false);
  const [newSnapshotTarget, setNewSnapshotTarget] = useState<string>('wp-content/themes');
  const [newSnapshotLabel, setNewSnapshotLabel] = useState<string>('');
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);

  // Diff Modal State
  const [diffModalOpen, setDiffModalOpen] = useState<boolean>(false);
  const [diffFileName, setDiffFileName] = useState<string>('');
  const [diffOriginal, setDiffOriginal] = useState<string>('');
  const [diffModified, setDiffModified] = useState<string>('');

  // Preloaders State
  const [preloaders, setPreloaders] = useState<PreloaderItem[]>([]);
  const [systemCrons, setSystemCrons] = useState<SystemCronsStatus | null>(null);

  // Reputation State
  const [reputation, setReputation] = useState<DomainReputationReport | null>(null);

  const [bannerMessage, setBannerMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadWatchdogStatus = async () => {
    setLoading(true);
    try {
      const res = await apiRequest({ path: '/webcare-pro-security/v1/reinfection-watchdog/status', method: 'GET' });
      if (res && res.success) {
        setWatchdogData(res);
      }
    } catch (e: any) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const loadSnapshots = async () => {
    try {
      const res = await apiRequest({ path: '/webcare-pro-security/v1/snapshots/list', method: 'GET' });
      if (res && res.success) {
        setSnapshots(res.snapshots || []);
        if (res.snapshots?.length > 0 && !selectedSnapshotId) {
          setSelectedSnapshotId(res.snapshots[0].id);
        }
      }
    } catch (e) {
      console.error(e);
    }
  };

  const loadPreloaders = async () => {
    try {
      const res = await apiRequest({ path: '/webcare-pro-security/v1/persistence/audit', method: 'GET' });
      if (res && res.success) {
        setPreloaders(res.server_preloaders || []);
        setSystemCrons(res.system_crons || null);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const loadReputation = async (force: boolean = false) => {
    try {
      const path = force ? '/webcare-pro-security/v1/domain-reputation/check' : '/webcare-pro-security/v1/domain-reputation/status';
      const method = force ? 'POST' : 'GET';
      const res = await apiRequest({ path, method });
      if (res && res.success) {
        setReputation(res);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadWatchdogStatus();
    loadSnapshots();
    loadPreloaders();
    loadReputation();
  }, []);

  const handleCheckWatchdogNow = async () => {
    setActionLoading(true);
    try {
      const res = await apiRequest({ path: '/webcare-pro-security/v1/reinfection-watchdog/check-now', method: 'POST' });
      if (res && res.status) {
        setWatchdogData(res.status);
        setBannerMessage({
          type: 'success',
          text: `Surveillance check complete. Inspected ${res.active_monitors} active location(s). Re-infections: ${res.reinfected_alerts}.`,
        });
      }
    } catch (e: any) {
      setBannerMessage({ type: 'error', text: e.message || 'Inspection failed' });
    } finally {
      setActionLoading(false);
    }
  };

  const handleDismissWatch = async (watchId: string) => {
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/reinfection-watchdog/dismiss',
        method: 'POST',
        data: { watch_id: watchId },
      });
      if (res && res.status) {
        setWatchdogData(res.status);
        setBannerMessage({ type: 'success', text: 'Surveillance watch dismissed.' });
      }
    } catch (e: any) {
      setBannerMessage({ type: 'error', text: e.message || 'Dismissal failed' });
    }
  };

  const handleCreateSnapshot = async () => {
    if (!newSnapshotTarget.trim()) return;
    setActionLoading(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/snapshots/create',
        method: 'POST',
        data: { target_rel_path: newSnapshotTarget.trim(), label: newSnapshotLabel.trim() },
      });
      if (res && res.success) {
        setShowCreateModal(false);
        setNewSnapshotLabel('');
        await loadSnapshots();
        setBannerMessage({ type: 'success', text: res.message || 'Snapshot created successfully.' });
      } else {
        setBannerMessage({ type: 'error', text: res?.message || 'Failed to create snapshot.' });
      }
    } catch (e: any) {
      setBannerMessage({ type: 'error', text: e.message || 'Snapshot creation error.' });
    } finally {
      setActionLoading(false);
    }
  };

  const handleCompareSnapshot = async (id: string) => {
    setComparing(true);
    setSelectedSnapshotId(id);
    try {
      const res = await apiRequest({
        path: `/webcare-pro-security/v1/snapshots/compare?snapshot_id=${encodeURIComponent(id)}`,
        method: 'GET',
      });
      if (res && res.success) {
        setCompareResult(res);
      }
    } catch (e: any) {
      setBannerMessage({ type: 'error', text: e.message || 'Comparison failed' });
    } finally {
      setComparing(false);
    }
  };

  const handleOpenDiff = async (relPath: string) => {
    if (!selectedSnapshotId) return;
    try {
      const res = await apiRequest({
        path: `/webcare-pro-security/v1/snapshots/diff?snapshot_id=${encodeURIComponent(selectedSnapshotId)}&rel_path=${encodeURIComponent(relPath)}`,
        method: 'GET',
      });
      if (res && res.success) {
        setDiffFileName(relPath);
        setDiffOriginal(res.original_content || '');
        setDiffModified(res.live_content || '');
        setDiffModalOpen(true);
      }
    } catch (e: any) {
      setBannerMessage({ type: 'error', text: e.message || 'Failed to load diff' });
    }
  };

  const handleRestoreFile = async (relPath: string) => {
    if (!selectedSnapshotId) return;
    const confirmed = await showConfirm({
      title: 'Restore File from Snapshot',
      message: `Restore "${relPath}" to its verified baseline snapshot? Live modifications will be overwritten.`,
      confirmLabel: 'Restore File',
      variant: 'warning',
    });
    if (!confirmed) {
      return;
    }
    setActionLoading(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/snapshots/restore',
        method: 'POST',
        data: { snapshot_id: selectedSnapshotId, rel_path: relPath },
      });
      if (res && res.success) {
        setBannerMessage({ type: 'success', text: res.message });
        await handleCompareSnapshot(selectedSnapshotId);
      } else {
        setBannerMessage({ type: 'error', text: res?.message || 'Restoration failed' });
      }
    } catch (e: any) {
      setBannerMessage({ type: 'error', text: e.message || 'Restore error' });
    } finally {
      setActionLoading(false);
    }
  };

  const handleDeleteSnapshot = async (id: string) => {
    const confirmed = await showConfirm({
      title: 'Delete Baseline Snapshot',
      message: 'Permanently delete this baseline snapshot?',
      confirmLabel: 'Delete Snapshot',
      variant: 'danger',
    });
    if (!confirmed) return;
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/snapshots/delete',
        method: 'POST',
        data: { snapshot_id: id },
      });
      if (res && res.success) {
        setCompareResult(null);
        await loadSnapshots();
        setBannerMessage({ type: 'success', text: 'Snapshot deleted.' });
      }
    } catch (e: any) {
      setBannerMessage({ type: 'error', text: e.message || 'Delete failed' });
    }
  };

  return (
    <div className="webcare-waf-table-card" style={{ marginBottom: '24px' }}>
      {/* Header */}
      <div className="webcare-waf-toolbar-card" style={{ borderBottom: '1px solid var(--webcare-border-subtle)', padding: '16px 20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: 'rgba(99, 102, 241, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <History size={22} color="#6366f1" />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-heading)' }}>
              Memory-Resident Persistence Hunter &amp; 72-Hour Reinfection Watchdog
            </h3>
            <p style={{ margin: '2px 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary)' }}>
              Sub-second self-healing malware resurrection surveillance, Time-Machine snapshots, and server pre-loader defense.
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            type="button"
            className="webcare-btn webcare-btn-secondary"
            onClick={() => {
              if (activeTab === 'watchdog') loadWatchdogStatus();
              else if (activeTab === 'snapshots') loadSnapshots();
              else if (activeTab === 'preloaders') loadPreloaders();
              else if (activeTab === 'reputation') loadReputation(true);
            }}
            disabled={loading || actionLoading}
          >
            <RefreshCw size={14} className={loading || actionLoading ? 'webcare-spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Subtab Navigation */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--webcare-border-subtle)', padding: '0 16px', background: 'var(--webcare-bg-surface)', gap: '4px', overflowX: 'auto' }}>
        <button
          type="button"
          className={`webcare-subtab-btn ${activeTab === 'watchdog' ? 'is-active' : ''}`}
          onClick={() => handleSubTabSwitch('watchdog')}
        >
          <Clock size={14} color={activeTab === 'watchdog' ? '#6366f1' : '#64748b'} />
          <span>72h Reinfection Watchdog ({watchdogData?.active_count || 0})</span>
        </button>

        <button
          type="button"
          className={`webcare-subtab-btn ${activeTab === 'snapshots' ? 'is-active' : ''}`}
          onClick={() => handleSubTabSwitch('snapshots')}
        >
          <Camera size={14} color={activeTab === 'snapshots' ? '#0ea5e9' : '#64748b'} />
          <span>Time-Machine Snapshots ({snapshots.length})</span>
        </button>

        <button
          type="button"
          className={`webcare-subtab-btn ${activeTab === 'preloaders' ? 'is-active' : ''}`}
          onClick={() => handleSubTabSwitch('preloaders')}
        >
          <Server size={14} color={activeTab === 'preloaders' ? '#f59e0b' : '#64748b'} />
          <span>Server Pre-Loaders &amp; System Crons</span>
        </button>

        <button
          type="button"
          className={`webcare-subtab-btn ${activeTab === 'reputation' ? 'is-active' : ''}`}
          onClick={() => handleSubTabSwitch('reputation')}
        >
          <Globe size={14} color={activeTab === 'reputation' ? '#10b981' : '#64748b'} />
          <span>Domain Reputation &amp; SSL</span>
        </button>
      </div>

      {/* Banner Feedback */}
      {bannerMessage && (
        <div style={{
          margin: '16px 20px 0',
          padding: '10px 14px',
          borderRadius: '8px',
          background: bannerMessage.type === 'success' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
          border: `1px solid ${bannerMessage.type === 'success' ? '#10b981' : '#ef4444'}`,
          color: bannerMessage.type === 'success' ? '#059669' : '#dc2626',
          fontSize: '13px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <span>{bannerMessage.text}</span>
          <button type="button" onClick={() => setBannerMessage(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', fontWeight: 'bold' }}>×</button>
        </div>
      )}

      {/* TAB 1: 72-Hour Reinfection Watchdog */}
      {activeTab === 'watchdog' && (
        <div style={{ padding: '20px' }}>
          {/* Active Reinfection Alerts Banner */}
          {watchdogData && watchdogData.recent_alerts && watchdogData.recent_alerts.length > 0 && (
            <div style={{
              background: 'rgba(239, 68, 68, 0.08)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              borderRadius: '10px',
              padding: '16px',
              marginBottom: '20px'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                <AlertOctagon size={18} color="#ef4444" />
                <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: '#dc2626' }}>
                  Critical Reinfection Alert: Self-Healing Malware Loop Detected!
                </h4>
              </div>
              <p style={{ margin: '0 0 12px', fontSize: '13px', color: 'var(--webcare-text-body)' }}>
                Remediated files have been re-created or re-injected on disk by persistent background loops or external C2 triggers. WebCare has locked down parent directory permissions and recorded high-priority forensic telemetry.
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {watchdogData.recent_alerts.map((alt) => (
                  <div key={alt.alert_id} style={{
                    background: 'var(--webcare-bg-panel)',
                    padding: '10px 14px',
                    borderRadius: '6px',
                    border: '1px solid var(--webcare-border-subtle)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    gap: '8px'
                  }}>
                    <div>
                      <span style={{ fontWeight: 600, color: '#dc2626', fontSize: '13px' }}>{alt.rel_path}</span>
                      <p style={{ margin: '2px 0 0', fontSize: '12px', color: 'var(--webcare-text-secondary)' }}>{alt.reason}</p>
                    </div>
                    <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted)' }}>{alt.detected_iso}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* KPI Strip */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', marginBottom: '20px' }}>
            <div className="webcare-firewall-rule-card" style={{ padding: '16px', borderRadius: '10px' }}>
              <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Active 72h Monitors</span>
              <div style={{ fontSize: '24px', fontWeight: 800, color: '#6366f1', marginTop: '4px' }}>
                {watchdogData?.active_count || 0}
              </div>
              <span style={{ fontSize: '11px', color: 'var(--webcare-text-secondary)' }}>Hourly background checks</span>
            </div>

            <div className="webcare-firewall-rule-card" style={{ padding: '16px', borderRadius: '10px' }}>
              <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Re-Infections Caught</span>
              <div style={{ fontSize: '24px', fontWeight: 800, color: (watchdogData?.reinfected_count || 0) > 0 ? '#ef4444' : '#10b981', marginTop: '4px' }}>
                {watchdogData?.reinfected_count || 0}
              </div>
              <span style={{ fontSize: '11px', color: 'var(--webcare-text-secondary)' }}>Resurrections intercepted</span>
            </div>

            <div className="webcare-firewall-rule-card" style={{ padding: '16px', borderRadius: '10px' }}>
              <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Next WP-Cron Inspection</span>
              <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-heading)', marginTop: '8px' }}>
                {watchdogData?.next_cron_run || 'Scheduled hourly'}
              </div>
              <span style={{ fontSize: '11px', color: 'var(--webcare-text-secondary)' }}>Autonomous background worker</span>
            </div>

            <div className="webcare-firewall-rule-card" style={{ padding: '16px', borderRadius: '10px', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <button
                type="button"
                className="webcare-btn webcare-btn-primary"
                onClick={handleCheckWatchdogNow}
                disabled={actionLoading}
              >
                <Zap size={14} />
                <span>Run Inspection Now</span>
              </button>
            </div>
          </div>

          {/* Active Watches Table */}
          <div style={{ overflowX: 'auto', border: '1px solid var(--webcare-border-subtle)', borderRadius: '10px' }}>
            <table className="webcare-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: 'var(--webcare-bg-surface)', borderBottom: '1px solid var(--webcare-border-subtle)' }}>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '12px', color: 'var(--webcare-text-secondary)' }}>File Path</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '12px', color: 'var(--webcare-text-secondary)' }}>Expected State</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '12px', color: 'var(--webcare-text-secondary)' }}>Time Left</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '12px', color: 'var(--webcare-text-secondary)' }}>Checks</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '12px', color: 'var(--webcare-text-secondary)' }}>Status</th>
                  <th style={{ padding: '12px 16px', textAlign: 'right', fontSize: '12px', color: 'var(--webcare-text-secondary)' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {watchdogData?.active_watches && watchdogData.active_watches.length > 0 ? (
                  watchdogData.active_watches.map((w) => (
                    <tr key={w.id} style={{ borderBottom: '1px solid var(--webcare-border-subtle)' }}>
                      <td style={{ padding: '12px 16px', fontSize: '13px' }}>
                        <div style={{ fontWeight: 600, color: 'var(--webcare-text-heading)' }}>{w.filename}</div>
                        <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted)' }}>{w.rel_path}</div>
                      </td>
                      <td style={{ padding: '12px 16px', fontSize: '12px' }}>
                        <span className={`webcare-badge-pill ${w.expected_status === 'deleted' ? 'webcare-badge-danger' : 'webcare-badge-info'}`}>
                          {w.expected_status.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px', fontSize: '13px', color: 'var(--webcare-text-body)' }}>
                        {w.hours_left > 0 ? `${w.hours_left} hrs` : 'Expiring'}
                      </td>
                      <td style={{ padding: '12px 16px', fontSize: '13px', color: 'var(--webcare-text-secondary)' }}>
                        {w.check_count} rounds
                      </td>
                      <td style={{ padding: '12px 16px', fontSize: '12px' }}>
                        {w.is_reinfected ? (
                          <span className="webcare-badge-pill webcare-badge-danger" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                            <AlertTriangle size={12} /> RE-INFECTED
                          </span>
                        ) : (
                          <span className="webcare-badge-pill webcare-badge-clean" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                            <CheckCircle2 size={12} /> CLEAN
                          </span>
                        )}
                      </td>
                      <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                        <button
                          type="button"
                          className="webcare-btn webcare-btn-secondary"
                          style={{ fontSize: '11px', padding: '4px 8px' }}
                          onClick={() => handleDismissWatch(w.id)}
                        >
                          Dismiss
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} style={{ padding: '36px', textAlign: 'center', color: 'var(--webcare-text-secondary)' }}>
                      <ShieldCheck size={32} color="#10b981" style={{ margin: '0 auto 8px', display: 'block' }} />
                      <div style={{ fontWeight: 600 }}>No active files currently undergoing 72-hour reinfection surveillance.</div>
                      <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted)', marginTop: '4px' }}>
                        Files quarantined to the vault or remediated via Auto-Cure are automatically monitored here for 72 hours.
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: Time-Machine Snapshots */}
      {activeTab === 'snapshots' && (
        <div style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--webcare-text-heading)' }}>
                Verified Baseline Snapshots &amp; Side-by-Side Visual Diff
              </h4>
              <p style={{ margin: '2px 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary)' }}>
                Protect bespoke child themes and custom plugins. Compare live files on disk against verified local baselines and restore single files with 1-click.
              </p>
            </div>
            <button
              type="button"
              className="webcare-btn webcare-btn-primary"
              onClick={() => setShowCreateModal(true)}
            >
              <PlusCircle size={14} />
              <span>Create Baseline Snapshot</span>
            </button>
          </div>

          {/* Snapshot Creation Modal / Drawer */}
          {showCreateModal && (
            <div style={{
              background: 'var(--webcare-bg-surface)',
              border: '1px solid var(--webcare-border-strong)',
              borderRadius: '10px',
              padding: '16px',
              marginBottom: '20px'
            }}>
              <h4 style={{ margin: '0 0 12px', fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-heading)' }}>
                Create New Verified Baseline Snapshot
              </h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '12px', marginBottom: '14px' }}>
                <div>
                  <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-secondary)', display: 'block', marginBottom: '4px' }}>
                    Target Relative Directory
                  </label>
                  <input
                    type="text"
                    className="webcare-input"
                    value={newSnapshotTarget}
                    onChange={(e) => setNewSnapshotTarget(e.target.value)}
                    placeholder="e.g. wp-content/themes/my-theme"
                  />
                </div>
                <div>
                  <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-secondary)', display: 'block', marginBottom: '4px' }}>
                    Snapshot Label
                  </label>
                  <input
                    type="text"
                    className="webcare-input"
                    value={newSnapshotLabel}
                    onChange={(e) => setNewSnapshotLabel(e.target.value)}
                    placeholder="e.g. Clean Production Baseline"
                  />
                </div>
              </div>
              <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                <button type="button" className="webcare-btn webcare-btn-secondary" onClick={() => setShowCreateModal(false)}>
                  Cancel
                </button>
                <button type="button" className="webcare-btn webcare-btn-primary" onClick={handleCreateSnapshot} disabled={actionLoading}>
                  {actionLoading ? 'Archiving...' : 'Capture Snapshot'}
                </button>
              </div>
            </div>
          )}

          {/* Snapshots Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px', marginBottom: '24px' }}>
            {snapshots.map((s) => (
              <div
                key={s.id}
                className="webcare-firewall-rule-card"
                style={{
                  padding: '16px',
                  borderRadius: '10px',
                  border: selectedSnapshotId === s.id ? '2px solid #6366f1' : '1px solid var(--webcare-border-subtle)',
                  cursor: 'pointer'
                }}
                onClick={() => handleCompareSnapshot(s.id)}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                  <div style={{ fontWeight: 700, fontSize: '14px', color: 'var(--webcare-text-heading)' }}>{s.label}</div>
                  <span className="webcare-badge-pill webcare-badge-info">{s.archive_formatted}</span>
                </div>
                <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted)', marginBottom: '8px' }}>{s.target_rel}</div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: 'var(--webcare-text-secondary)', marginBottom: '12px' }}>
                  <span>{s.file_count} code files</span>
                  <span>{s.created_at}</span>
                </div>
                <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                  <button
                    type="button"
                    className="webcare-btn webcare-btn-secondary"
                    style={{ fontSize: '11px', padding: '4px 8px' }}
                    onClick={(e) => {
                      e.stopPropagation();
                      handleCompareSnapshot(s.id);
                    }}
                    disabled={comparing}
                  >
                    Compare Live
                  </button>
                  <button
                    type="button"
                    className="webcare-btn webcare-btn-danger"
                    style={{ fontSize: '11px', padding: '4px 8px' }}
                    onClick={(e) => {
                      e.stopPropagation();
                      handleDeleteSnapshot(s.id);
                    }}
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              </div>
            ))}
          </div>

          {/* Comparison Results Card */}
          {compareResult && (
            <div style={{ border: '1px solid var(--webcare-border-subtle)', borderRadius: '10px', overflow: 'hidden' }}>
              <div style={{ padding: '14px 18px', background: 'var(--webcare-bg-surface)', borderBottom: '1px solid var(--webcare-border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-heading)' }}>
                    Live Integrity Comparison vs &quot;{compareResult.label}&quot;
                  </h4>
                  <span style={{ fontSize: '12px', color: 'var(--webcare-text-secondary)' }}>Target: {compareResult.target_rel}</span>
                </div>
                <div>
                  {compareResult.is_identical ? (
                    <span className="webcare-badge-pill webcare-badge-clean">
                      <Check size={12} style={{ marginRight: '4px' }} /> 100% IDENTICAL TO BASELINE
                    </span>
                  ) : (
                    <span className="webcare-badge-pill webcare-badge-danger">
                      <AlertTriangle size={12} style={{ marginRight: '4px' }} /> CODE DRIFT DETECTED
                    </span>
                  )}
                </div>
              </div>

              {/* Drift Table */}
              <table className="webcare-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ background: 'var(--webcare-bg-surface)', borderBottom: '1px solid var(--webcare-border-subtle)' }}>
                    <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: '12px', color: 'var(--webcare-text-secondary)' }}>File</th>
                    <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: '12px', color: 'var(--webcare-text-secondary)' }}>Status</th>
                    <th style={{ padding: '10px 16px', textAlign: 'right', fontSize: '12px', color: 'var(--webcare-text-secondary)' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {compareResult.modified.map((m) => (
                    <tr key={m.rel_path} style={{ borderBottom: '1px solid var(--webcare-border-subtle)' }}>
                      <td style={{ padding: '10px 16px', fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-heading)' }}>
                        {m.rel_path}
                      </td>
                      <td style={{ padding: '10px 16px' }}>
                        <span className="webcare-badge-pill webcare-badge-danger">MODIFIED ON DISK</span>
                      </td>
                      <td style={{ padding: '10px 16px', textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                          <button
                            type="button"
                            className="webcare-btn webcare-btn-secondary"
                            style={{ fontSize: '11px', padding: '4px 8px' }}
                            onClick={() => handleOpenDiff(m.rel_path)}
                          >
                            <Eye size={12} /> Visual Diff
                          </button>
                          <button
                            type="button"
                            className="webcare-btn webcare-btn-primary"
                            style={{ fontSize: '11px', padding: '4px 8px' }}
                            onClick={() => handleRestoreFile(m.rel_path)}
                            disabled={actionLoading}
                          >
                            <RotateCcw size={12} /> Restore Baseline
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}

                  {compareResult.added.map((a) => (
                    <tr key={a.rel_path} style={{ borderBottom: '1px solid var(--webcare-border-subtle)' }}>
                      <td style={{ padding: '10px 16px', fontSize: '13px', fontWeight: 600, color: '#dc2626' }}>
                        {a.rel_path}
                      </td>
                      <td style={{ padding: '10px 16px' }}>
                        <span className="webcare-badge-pill webcare-badge-danger">NEW UNTRACKED FILE</span>
                      </td>
                      <td style={{ padding: '10px 16px', textAlign: 'right', fontSize: '12px', color: 'var(--webcare-text-muted)' }}>
                        Injected after snapshot
                      </td>
                    </tr>
                  ))}

                  {compareResult.deleted.map((d) => (
                    <tr key={d.rel_path} style={{ borderBottom: '1px solid var(--webcare-border-subtle)' }}>
                      <td style={{ padding: '10px 16px', fontSize: '13px', color: 'var(--webcare-text-muted)' }}>
                        {d.rel_path}
                      </td>
                      <td style={{ padding: '10px 16px' }}>
                        <span className="webcare-badge-pill webcare-badge-info">MISSING / DELETED</span>
                      </td>
                      <td style={{ padding: '10px 16px', textAlign: 'right' }}>
                        <button
                          type="button"
                          className="webcare-btn webcare-btn-primary"
                          style={{ fontSize: '11px', padding: '4px 8px' }}
                          onClick={() => handleRestoreFile(d.rel_path)}
                          disabled={actionLoading}
                        >
                          <RotateCcw size={12} /> Recreate File
                        </button>
                      </td>
                    </tr>
                  ))}

                  {compareResult.is_identical && (
                    <tr>
                      <td colSpan={3} style={{ padding: '24px', textAlign: 'center', color: '#059669', fontSize: '13px' }}>
                        All {compareResult.counts.clean} code files match the verified baseline checksums bit-for-bit.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: Server Pre-Loaders & System Crons */}
      {activeTab === 'preloaders' && (
        <div style={{ padding: '20px' }}>
          <h4 style={{ margin: '0 0 6px', fontSize: '15px', fontWeight: 700, color: 'var(--webcare-text-heading)' }}>
            Server-Level Pre-Loader &amp; PHP Startup Execution Sentinel
          </h4>
          <p style={{ margin: '0 0 16px', fontSize: '13px', color: 'var(--webcare-text-secondary)' }}>
            Detects persistent backdoors configured to execute via PHP&apos;s early lifecycle (<code style={{ color: '#0284c7' }}>auto_prepend_file</code> / <code style={{ color: '#0284c7' }}>auto_append_file</code>) in <code style={{ color: '#0284c7' }}>php.ini</code>, <code style={{ color: '#0284c7' }}>.user.ini</code>, and <code style={{ color: '#0284c7' }}>.htaccess</code>.
          </p>

          <div style={{ overflowX: 'auto', border: '1px solid var(--webcare-border-subtle)', borderRadius: '10px', marginBottom: '24px' }}>
            <table className="webcare-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: 'var(--webcare-bg-surface)', borderBottom: '1px solid var(--webcare-border-subtle)' }}>
                  <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: '12px', color: 'var(--webcare-text-secondary)' }}>Directive Source</th>
                  <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: '12px', color: 'var(--webcare-text-secondary)' }}>Target Script</th>
                  <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: '12px', color: 'var(--webcare-text-secondary)' }}>Status</th>
                  <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: '12px', color: 'var(--webcare-text-secondary)' }}>Forensic Analysis</th>
                </tr>
              </thead>
              <tbody>
                {preloaders.length > 0 ? (
                  preloaders.map((p, idx) => (
                    <tr key={idx} style={{ borderBottom: '1px solid var(--webcare-border-subtle)' }}>
                      <td style={{ padding: '12px 16px', fontSize: '13px', fontWeight: 600 }}>{p.directive}</td>
                      <td style={{ padding: '12px 16px', fontSize: '12px', color: '#0284c7', fontFamily: 'monospace' }}>{p.target_file}</td>
                      <td style={{ padding: '12px 16px' }}>
                        <span className={`webcare-badge-pill ${p.severity === 'clean' ? 'webcare-badge-clean' : 'webcare-badge-danger'}`}>
                          {p.severity.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px', fontSize: '12px', color: 'var(--webcare-text-body)' }}>{p.description}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={4} style={{ padding: '24px', textAlign: 'center', color: 'var(--webcare-text-secondary)' }}>
                      <CheckCircle2 size={24} color="#10b981" style={{ margin: '0 auto 8px', display: 'block' }} />
                      No unexpected server pre-loaders detected. PHP boot environment is clean.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* System Crons Transparency Box */}
          <div style={{
            background: 'var(--webcare-bg-surface)',
            border: '1px solid var(--webcare-border-subtle)',
            borderRadius: '10px',
            padding: '16px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <Server size={16} color="#6366f1" />
              <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-heading)' }}>
                System-Level Crontab Transparency Check
              </h4>
            </div>
            <p style={{ margin: '0 0 12px', fontSize: '13px', color: 'var(--webcare-text-secondary)' }}>
              {systemCrons?.notice || 'Checking system crontab accessibility...'}
            </p>
            {systemCrons?.checked_paths && systemCrons.checked_paths.length > 0 && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                {systemCrons.checked_paths.map((cp, idx) => (
                  <span key={idx} className="webcare-badge-pill webcare-badge-info" style={{ fontSize: '11px' }}>
                    {cp.path} ({cp.readable ? 'Readable' : 'Restricted'})
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 4: Domain Reputation & SSL */}
      {activeTab === 'reputation' && (
        <div style={{ padding: '20px' }}>
          {reputation ? (
            <div>
              {/* Score Header Strip */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', marginBottom: '20px' }}>
                <div className="webcare-firewall-rule-card" style={{ padding: '16px', borderRadius: '10px' }}>
                  <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted)', textTransform: 'uppercase' }}>Reputation Score</span>
                  <div style={{ fontSize: '28px', fontWeight: 800, color: reputation.reputation_score >= 90 ? '#10b981' : (reputation.reputation_score >= 60 ? '#f59e0b' : '#ef4444'), marginTop: '4px' }}>
                    {reputation.reputation_score}/100
                  </div>
                  <span style={{ fontSize: '11px', color: 'var(--webcare-text-secondary)' }}>Overall trust level</span>
                </div>

                <div className="webcare-firewall-rule-card" style={{ padding: '16px', borderRadius: '10px' }}>
                  <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted)', textTransform: 'uppercase' }}>SSL Certificate</span>
                  <div style={{ fontSize: '18px', fontWeight: 700, color: reputation.ssl.status === 'healthy' ? '#10b981' : '#f59e0b', marginTop: '8px' }}>
                    {reputation.ssl.days_remaining} Days Left
                  </div>
                  <span style={{ fontSize: '11px', color: 'var(--webcare-text-secondary)' }}>Issuer: {reputation.ssl.issuer}</span>
                </div>

                <div className="webcare-firewall-rule-card" style={{ padding: '16px', borderRadius: '10px' }}>
                  <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted)', textTransform: 'uppercase' }}>Blacklist Listings</span>
                  <div style={{ fontSize: '28px', fontWeight: 800, color: reputation.dnsbl.total_listed > 0 ? '#ef4444' : '#10b981', marginTop: '4px' }}>
                    {reputation.dnsbl.total_listed} / {reputation.dnsbl.total_checked}
                  </div>
                  <span style={{ fontSize: '11px', color: 'var(--webcare-text-secondary)' }}>Spamhaus, Barracuda, SpamCop</span>
                </div>

                <div className="webcare-firewall-rule-card" style={{ padding: '16px', borderRadius: '10px' }}>
                  <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted)', textTransform: 'uppercase' }}>Email Security</span>
                  <div style={{ fontSize: '14px', fontWeight: 700, color: reputation.dns.has_dmarc ? '#10b981' : '#f59e0b', marginTop: '8px' }}>
                    {reputation.dns.has_spf ? 'SPF Configured' : 'No SPF'} &bull; {reputation.dns.has_dmarc ? 'DMARC Active' : 'No DMARC'}
                  </div>
                  <span style={{ fontSize: '11px', color: 'var(--webcare-text-secondary)' }}>Anti-spoofing defense</span>
                </div>
              </div>

              {/* DNSBL Detail Rows */}
              <div style={{ border: '1px solid var(--webcare-border-subtle)', borderRadius: '10px', overflow: 'hidden' }}>
                <div style={{ padding: '12px 16px', background: 'var(--webcare-bg-surface)', borderBottom: '1px solid var(--webcare-border-subtle)', fontWeight: 700, fontSize: '13px', color: 'var(--webcare-text-heading)' }}>
                  Threat Blacklist Providers Checked
                </div>
                <table className="webcare-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <tbody>
                    {reputation.dnsbl.providers.map((p, idx) => (
                      <tr key={idx} style={{ borderBottom: '1px solid var(--webcare-border-subtle)' }}>
                        <td style={{ padding: '10px 16px', fontSize: '13px', fontWeight: 600 }}>{p.name}</td>
                        <td style={{ padding: '10px 16px', fontSize: '12px', color: '#0284c7', fontFamily: 'monospace' }}>{p.host}</td>
                        <td style={{ padding: '10px 16px', textAlign: 'right' }}>
                          {p.is_listed ? (
                            <span className="webcare-badge-pill webcare-badge-danger">LISTED ({p.response})</span>
                          ) : (
                            <span className="webcare-badge-pill webcare-badge-clean">CLEAN</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div style={{ padding: '36px', textAlign: 'center', color: 'var(--webcare-text-secondary)' }}>
              <Globe size={32} color="#6366f1" style={{ margin: '0 auto 8px', display: 'block' }} />
              <div>Loading domain reputation telemetry...</div>
            </div>
          )}
        </div>
      )}

      {/* Visual Diff Modal */}
      {diffModalOpen && (
        <VisualDiffModal
          isOpen={diffModalOpen}
          onClose={() => setDiffModalOpen(false)}
          fileName={diffFileName}
          originalContent={diffOriginal}
          modifiedContent={diffModified}
          mode="side-by-side"
          showRestoreOption={true}
          onRestore={() => {
            setDiffModalOpen(false);
            handleRestoreFile(diffFileName);
          }}
        />
      )}
    </div>
  );
}
