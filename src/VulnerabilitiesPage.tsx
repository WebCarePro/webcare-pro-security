import { Fragment, useState, useEffect } from '@wordpress/element';
import { EmptyStateCard } from './components/ui/EmptyStateCard';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  Layers,
  ArrowUpRight,
  Filter,
  CheckCircle2,
  Search,
  Package,
  Cpu,
  Palette,
  Check,
  ChevronDown,
  ChevronRight,
  Info,
  Shield,
  RotateCcw,
  Loader2
} from 'lucide-react';

interface CveItem {
  cve_id: string;
  title: string;
  severity: string;
  cvss: number;
  fixed_in: string;
  reference: string;
  cve_details: string;
}

interface UnknownFileItem {
  file: string;
  full_path: string;
  size: number;
  is_executable: boolean;
}

interface ComponentItem {
  name: string;
  slug?: string;
  file?: string;
  author?: string;
  plugin_uri?: string;
  theme_uri?: string;
  is_active?: boolean;
  type: 'core' | 'plugin' | 'theme';
  origin?: 'official' | 'premium_custom';
  is_official?: boolean;
  unknown_files?: UnknownFileItem[];
  unknown_count?: number;
  installed_version: string;
  latest_version: string;
  is_outdated: boolean;
  has_cve: boolean;
  cves: CveItem[];
  cve_count: number;
  max_cvss: number;
  update_url: string;
  package_url?: string;
  status: 'vulnerable' | 'outdated' | 'secure';
}

interface VulnerabilityReport {
  summary: {
    total_components: number;
    outdated_count: number;
    vulnerable_count: number;
    total_cves: number;
    secure_count: number;
    official_count?: number;
    premium_count?: number;
    items_with_unknown_files?: number;
    total_unknown_files?: number;
    timestamp: string;
  };
  core: ComponentItem;
  plugins: ComponentItem[];
  themes: ComponentItem[];
}

interface VulnerabilitiesPageProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  onInspectCve?: (cveList: CveItem[], componentName: string, version: string, updateUrl: string) => void;
}

const VulnerabilitiesPage = ({ apiRequest, onInspectCve }: VulnerabilitiesPageProps) => {
  const [report, setReport] = useState<VulnerabilityReport | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeFilter, setActiveFilter] = useState<'all' | 'vulnerable' | 'outdated' | 'secure'>('all');
  const [originFilter, setOriginFilter] = useState<'all' | 'official' | 'premium_custom' | 'has_unknown'>('all');
  const [typeFilter, setTypeFilter] = useState<'all' | 'core' | 'plugin' | 'theme'>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedItems, setExpandedItems] = useState<Record<string, boolean>>({});
  const [virtualShields, setVirtualShields] = useState<Record<string, string>>({});
  const [safeBackups, setSafeBackups] = useState<Record<string, any>>({});
  const [busyActionKey, setBusyActionKey] = useState<string | null>(null);
  const [nistStatus, setNistStatus] = useState<{
    is_running: boolean;
    total_components: number;
    checked_count: number;
    last_fetch_human: string;
    has_api_key: boolean;
    batch_size: number;
    checked_components?: Record<string, any>;
    logs?: any[];
  } | null>(null);
  const [showNistLogs, setShowNistLogs] = useState(false);

  const loadNistStatus = async () => {
    try {
      const res = await apiRequest({ path: '/webcare-pro-security/v1/cve/nist-status', method: 'GET' });
      if (res?.success && res.status) {
        setNistStatus(res.status);
      }
    } catch (e) {}
  };

  useEffect(() => {
    loadNistStatus();
  }, []);
  const [actionFeedback, setActionFeedback] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadReport = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiRequest({ path: '/webcare-pro-security/v1/vulnerabilities/report' });
      if (res && res.success && res.report) {
        setReport(res.report);
        setVirtualShields(res.virtual_shields || {});
        setSafeBackups(res.safe_update_backups || {});
      } else {
        setError(res?.message || 'Failed to retrieve vulnerability analysis report.');
      }
    } catch (err: any) {
      setError(err?.message || 'Network error fetching vulnerability advisories.');
    } finally {
      setLoading(false);
    }
  };

  const handleActivateVirtualShield = async (item: ComponentItem) => {
    const slug = item.slug || item.name;
    const key = `shield-${slug}`;
    setBusyActionKey(key);
    setActionFeedback(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/vulnerabilities/virtual-shield',
        method: 'POST',
        data: { slug, type: item.type },
      });
      if (res?.success) {
        setVirtualShields((prev) => ({ ...prev, [slug]: res.rule_id || 'MOD-CVE-ACTIVE' }));
        setActionFeedback({ type: 'success', text: res.message || `Virtual Shield activated for ${item.name}!` });
      } else {
        setActionFeedback({ type: 'error', text: res?.message || 'Failed to activate Virtual Shield.' });
      }
    } catch (err: any) {
      setActionFeedback({ type: 'error', text: err?.message || 'Failed to activate Virtual Shield.' });
    } finally {
      setBusyActionKey(null);
    }
  };

  const handleSafeUpdateWithBackup = async (item: ComponentItem) => {
    if (!item.file) return;
    const slug = item.slug || item.name;
    const key = `update-${item.file}`;
    setBusyActionKey(key);
    setActionFeedback(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/vulnerabilities/safe-update',
        method: 'POST',
        data: { plugin_file: item.file, slug, name: item.name },
      });
      if (res?.success) {
        setActionFeedback({ type: 'success', text: res.message });
        await loadReport();
      } else {
        setActionFeedback({ type: 'error', text: res?.message || 'Safe Update failed. Backup snapshot preserved.' });
      }
    } catch (err: any) {
      setActionFeedback({ type: 'error', text: err?.message || 'Safe Update failed.' });
    } finally {
      setBusyActionKey(null);
    }
  };

  const handleRollbackSafeUpdate = async (snapshotId: string, label: string) => {
    const key = `rollback-${snapshotId}`;
    setBusyActionKey(key);
    setActionFeedback(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/vulnerabilities/safe-rollback',
        method: 'POST',
        data: { snapshot_id: snapshotId },
      });
      if (res?.success) {
        setActionFeedback({ type: 'success', text: res.message || `Rolled back ${label} safely.` });
        await loadReport();
      } else {
        setActionFeedback({ type: 'error', text: res?.message || 'Rollback failed.' });
      }
    } catch (err: any) {
      setActionFeedback({ type: 'error', text: err?.message || 'Rollback failed.' });
    } finally {
      setBusyActionKey(null);
    }
  };

  useEffect(() => {
    loadReport();
  }, []);

  const toggleExpand = (key: string) => {
    setExpandedItems((prev) => ({
      ...prev,
      [key]: !prev[key],
    }));
  };

  // Compile list of components
  const allComponents: ComponentItem[] = report
    ? [report.core, ...report.plugins, ...report.themes]
    : [];

  const filteredComponents = allComponents.filter((item) => {
    // Status filter
    if (activeFilter === 'vulnerable' && !item.has_cve) return false;
    if (activeFilter === 'outdated' && (!item.is_outdated || item.has_cve)) return false;
    if (activeFilter === 'secure' && (item.is_outdated || item.has_cve)) return false;

    // Origin filter
    if (originFilter === 'official' && item.type !== 'core' && item.origin !== 'official') return false;
    if (originFilter === 'premium_custom' && (item.type === 'core' || item.origin !== 'premium_custom')) return false;
    if (originFilter === 'has_unknown' && (!item.unknown_count || item.unknown_count === 0)) return false;

    // Type filter
    if (typeFilter !== 'all' && item.type !== typeFilter) return false;

    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchName = item.name.toLowerCase().includes(q);
      const matchSlug = item.slug ? item.slug.toLowerCase().includes(q) : false;
      const matchCve = item.cves.some((c) => c.cve_id.toLowerCase().includes(q) || c.title.toLowerCase().includes(q));
      if (!matchName && !matchSlug && !matchCve) return false;
    }

    return true;
  });

  return (
    <div className="webcare-page-container" style={{ width: '100%', maxWidth: '100%', margin: '0' }}>
      {/* Page Header Banner */}
      <div className="webcare-card webcare-vuln-hero" style={{ padding: '24px 28px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '20px' }}>
        <div style={{ maxWidth: '640px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', flexWrap: 'wrap' }}>
            <span className="webcare-badge-critical">
              <ShieldAlert size={12} />
              Vulnerability &amp; CVE Intelligence
            </span>
            <span className="webcare-badge-neutral">
              WP.org Checksums &amp; Integrity
            </span>
          </div>
          <h1 style={{ margin: 0, fontSize: '24px', fontWeight: 800, letterSpacing: '-0.3px', color: 'inherit' }}>
            Themes, Plugins &amp; Core Security Health
          </h1>
          <p style={{ margin: '6px 0 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary, #64748b)', lineHeight: 1.5 }}>
            Audit installed software against official WordPress.org release manifests, CVE exploit databases, and detect unrecognized foreign files.
          </p>
        </div>

        <div>
          <button
            type="button"
            className="webcare-btn-primary"
            onClick={loadReport}
            disabled={loading}
          >
            <RefreshCw size={14} className={loading ? 'webcare-spin' : ''} />
            <span>{loading ? 'Auditing...' : 'Re-Check All'}</span>
          </button>
        </div>
      </div>

      {/* Modern Executive Stat Cards */}
      {report && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
          {/* 1: Total Items */}
          <div className="webcare-stat-card-compact">
            <div>
              <div className="stat-label">Total Software</div>
              <div className="stat-number" style={{ color: '#0f172a' }}>{report.summary.total_components}</div>
              <div className="stat-sub">1 Core &bull; {report.plugins.length} Plugins &bull; {report.themes.length} Themes</div>
            </div>
            <div style={{ background: '#eff6ff', padding: '10px', borderRadius: '10px' }}>
              <Package size={22} color="#3b82f6" />
            </div>
          </div>

          {/* 2: Official vs Premium Origin */}
          <div className="webcare-stat-card-compact" style={{ borderLeft: '3px solid #8b5cf6' }}>
            <div>
              <div className="stat-label">Origin Provenance</div>
              <div className="stat-number" style={{ color: '#6d28d9', fontSize: '19px' }}>
                {report.summary.official_count ?? (1 + report.plugins.length + report.themes.length)}
                <span style={{ fontSize: '12px', color: '#94a3b8', fontWeight: 500, margin: '0 4px' }}>WP.org /</span>
                <span style={{ color: '#9333ea' }}>{report.summary.premium_count ?? 0}</span>
                <span style={{ fontSize: '12px', color: '#94a3b8', fontWeight: 500, marginLeft: '4px' }}>custom</span>
              </div>
              <div className="stat-sub">Public repository vs. Vendor bespoke</div>
            </div>
            <div style={{ background: '#f5f3ff', padding: '10px', borderRadius: '10px' }}>
              <Layers size={22} color="#8b5cf6" />
            </div>
          </div>

          {/* 3: Known CVE Vulnerabilities */}
          <div className="webcare-stat-card-compact" style={{ borderLeft: '3px solid #ef4444' }}>
            <div>
              <div className="stat-label">Vulnerabilities (CVE)</div>
              <div className="stat-number" style={{ color: (report.summary.vulnerable_count > 0) ? '#dc2626' : '#10b981' }}>
                {report.summary.vulnerable_count}
              </div>
              <div className="stat-sub" style={{ color: report.summary.vulnerable_count > 0 ? '#ef4444' : '#059669', fontWeight: 600 }}>
                {report.summary.total_cves > 0 ? `${report.summary.total_cves} CVE Advisories` : 'Zero known CVEs'}
              </div>
            </div>
            <div style={{ background: report.summary.vulnerable_count > 0 ? '#fef2f2' : '#ecfdf5', padding: '10px', borderRadius: '10px' }}>
              <ShieldAlert size={22} color={report.summary.vulnerable_count > 0 ? '#ef4444' : '#10b981'} />
            </div>
          </div>

          {/* 4: Unknown Files in Official Packages */}
          <div className="webcare-stat-card-compact" style={{ borderLeft: `3px solid ${(report.summary.total_unknown_files ?? 0) > 0 ? '#e11d48' : '#10b981'}` }}>
            <div>
              <div className="stat-label">Unknown Files</div>
              <div className="stat-number" style={{ color: (report.summary.total_unknown_files ?? 0) > 0 ? '#e11d48' : '#10b981' }}>
                {report.summary.total_unknown_files ?? 0}
              </div>
              <div className="stat-sub" style={{ color: (report.summary.total_unknown_files ?? 0) > 0 ? '#e11d48' : '#059669', fontWeight: 600 }}>
                {(report.summary.items_with_unknown_files ?? 0) > 0
                  ? `In ${report.summary.items_with_unknown_files} official package(s)`
                  : 'Clean manifest audit'}
              </div>
            </div>
            <div style={{ background: (report.summary.total_unknown_files ?? 0) > 0 ? '#fff1f2' : '#ecfdf5', padding: '10px', borderRadius: '10px' }}>
              <AlertTriangle size={22} color={(report.summary.total_unknown_files ?? 0) > 0 ? '#e11d48' : '#10b981'} />
            </div>
          </div>

          {/* 5: Secure / Up-To-Date */}
          <div className="webcare-stat-card-compact" style={{ borderLeft: '3px solid #10b981' }}>
            <div>
              <div className="stat-label">Clean & Up to Date</div>
              <div className="stat-number" style={{ color: '#059669' }}>
                {report.summary.secure_count}
              </div>
              <div className="stat-sub">
                {report.summary.outdated_count > 0 ? `${report.summary.outdated_count} update(s) ready` : 'Everything up-to-date'}
              </div>
            </div>
            <div style={{ background: '#ecfdf5', padding: '10px', borderRadius: '10px' }}>
              <ShieldCheck size={22} color="#10b981" />
            </div>
          </div>
        </div>
      )}

      {/* Feedback Banner */}
      {actionFeedback && (
        <div
          style={{
            padding: '12px 16px',
            borderRadius: '10px',
            fontSize: '12.5px',
            fontWeight: 700,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            background: actionFeedback.type === 'success' ? 'var(--webcare-status-clean-soft)' : 'var(--webcare-status-critical-soft)',
            color: actionFeedback.type === 'success' ? 'var(--webcare-status-clean)' : 'var(--webcare-status-critical)',
            border: `1px solid ${actionFeedback.type === 'success' ? 'var(--webcare-status-clean-border)' : 'var(--webcare-status-critical-border)'}`,
          }}
        >
          {actionFeedback.type === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
          <span>{actionFeedback.text}</span>
        </div>
      )}

      {/* Unified Filter & Search Control Panel */}
      <div className="webcare-card" style={{
        padding: '16px 20px',
        display: 'flex',
        flexDirection: 'column',
        gap: '14px'
      }}>
        {/* Row 1: Search & Type */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ position: 'relative', flex: '1', minWidth: '260px', maxWidth: '420px' }}>
            <Search size={15} color="#94a3b8" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
            <input
              type="text"
              className="webcare-form-input"
              placeholder="Search plugin, theme, author, or CVE..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: '100%',
                padding: '8px 12px 8px 36px',
              }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div className="webcare-subtabs-nav">
              {(['all', 'core', 'plugin', 'theme'] as const).map((t) => (
                <button
                  key={t}
                  type="button"
                  className={`webcare-subtab-btn ${typeFilter === t ? 'is-active' : ''}`}
                  onClick={() => setTypeFilter(t)}
                >
                  {t === 'all' ? 'All Types' : t === 'core' ? 'Core' : t === 'plugin' ? 'Plugins' : 'Themes'}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Row 2: Status & Origin Filter Badges */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px', paddingTop: '10px', borderTop: '1px solid #f1f5f9' }}>
          {/* Status Filters */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
            <button
              type="button"
              className={`webcare-pill-filter-btn ${activeFilter === 'all' ? 'active-all' : ''}`}
              onClick={() => setActiveFilter('all')}
            >
              All ({allComponents.length})
            </button>
            <button
              type="button"
              className={`webcare-pill-filter-btn ${activeFilter === 'vulnerable' ? 'active-vuln' : ''}`}
              onClick={() => setActiveFilter('vulnerable')}
            >
              <ShieldAlert size={12} />
              Vulnerable ({report?.summary.vulnerable_count || 0})
            </button>
            <button
              type="button"
              className={`webcare-pill-filter-btn ${activeFilter === 'outdated' ? 'active-update' : ''}`}
              onClick={() => setActiveFilter('outdated')}
            >
              <AlertTriangle size={12} />
              Outdated ({report?.summary.outdated_count || 0})
            </button>
            <button
              type="button"
              className={`webcare-pill-filter-btn ${activeFilter === 'secure' ? 'active-secure' : ''}`}
              onClick={() => setActiveFilter('secure')}
            >
              <CheckCircle2 size={12} />
              Secure ({report?.summary.secure_count || 0})
            </button>
          </div>

          {/* Origin Filters */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '11px', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase' }}>Origin:</span>
            <button
              type="button"
              className={`webcare-pill-filter-btn ${originFilter === 'all' ? 'active-all' : ''}`}
              style={{ padding: '4px 9px', fontSize: '11px' }}
              onClick={() => setOriginFilter('all')}
            >
              All
            </button>
            <button
              type="button"
              className={`webcare-pill-filter-btn ${originFilter === 'official' ? 'active-official' : ''}`}
              style={{ padding: '4px 9px', fontSize: '11px' }}
              onClick={() => setOriginFilter('official')}
            >
              <CheckCircle2 size={11} />
              Official WP.org ({report?.summary.official_count ?? 0})
            </button>
            <button
              type="button"
              className={`webcare-pill-filter-btn ${originFilter === 'premium_custom' ? 'active-premium' : ''}`}
              style={{ padding: '4px 9px', fontSize: '11px' }}
              onClick={() => setOriginFilter('premium_custom')}
            >
              <Package size={11} />
              Premium / Custom ({report?.summary.premium_count ?? 0})
            </button>
            <button
              type="button"
              className={`webcare-pill-filter-btn ${originFilter === 'has_unknown' ? 'active-unknown' : ''}`}
              style={{ padding: '4px 9px', fontSize: '11px' }}
              onClick={() => setOriginFilter('has_unknown')}
            >
              <AlertTriangle size={11} />
              Unknown Files ({report?.summary.items_with_unknown_files ?? 0})
            </button>
          </div>
        </div>
      </div>

      {/* Loading & Error States */}
      {loading && (
        <div style={{ padding: '50px 20px', textAlign: 'center', background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '14px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
          <RefreshCw size={32} color="#3b82f6" className="webcare-spin" style={{ margin: '0 auto 10px auto' }} />
          <h4 style={{ margin: '0 0 4px 0', fontSize: '16px', color: 'var(--webcare-text-primary, #1e293b)' }}>Auditing Versions & Security Manifests...</h4>
          <p style={{ margin: 0, fontSize: '13px', color: 'var(--webcare-text-muted, #64748b)' }}>Reconciling WordPress.org checksums and National Vulnerability Database CVE records.</p>
        </div>
      )}

      {error && !loading && (
        <div style={{ background: '#fef2f2', border: '1px solid #fecaca', borderRadius: '12px', padding: '16px 20px', color: '#991b1b', fontSize: '14px' }}>
          <strong>Error loading vulnerability report:</strong> {error}
        </div>
      )}

      {/* Main Catalog Table */}
      {!loading && report && (
        <div style={{
          background: '#ffffff',
          borderRadius: '14px',
          border: '1px solid #e2e8f0',
          boxShadow: '0 1px 3px rgba(0, 0, 0, 0.03)',
          overflow: 'hidden'
        }}>
          <div style={{
            padding: '16px 22px',
            borderBottom: '1px solid #f1f5f9',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '10px'
          }}>
            <div>
              <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: '#0f172a', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Layers size={17} color="#3b82f6" />
                Vulnerability Catalog & Upgrade Advisory
              </h3>
              <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: '#64748b' }}>
                Showing <strong>{filteredComponents.length}</strong> of <strong>{allComponents.length}</strong> installed components
              </p>
            </div>
            <div style={{ fontSize: '12px', color: '#94a3b8' }}>
              Checked: {report.summary.timestamp}
            </div>
          </div>

          {/* NIST NVD Background Sync & Encrypted API Key Bar */}
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '12px',
              padding: '12px 16px',
              margin: '0 20px 14px 20px',
              borderRadius: '10px',
              background: 'var(--webcare-bg-panel)',
              border: '1px solid var(--webcare-border-subtle)',
            }}
          >
            <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '10px', fontSize: '12px', color: 'var(--webcare-text-secondary)' }}>
              <strong style={{ color: 'var(--webcare-text-primary)' }}>NIST NVD Intelligence:</strong>
              <span
                style={{
                  padding: '2px 8px',
                  borderRadius: '999px',
                  fontSize: '11px',
                  fontWeight: 700,
                  background: nistStatus?.has_api_key ? 'rgba(16, 185, 129, 0.14)' : 'rgba(59, 130, 246, 0.12)',
                  color: nistStatus?.has_api_key ? '#059669' : '#2563eb',
                }}
              >
                {nistStatus?.has_api_key ? 'NIST API Connected (25 req / 35s)' : 'Free NIST Fetch (5 req / 35s)'}
              </span>
              <span>&bull;</span>
              <span>
                Checked{' '}
                <strong style={{ color: 'var(--webcare-text-primary)' }}>
                  {nistStatus ? `${nistStatus.checked_count} / ${nistStatus.total_components}` : '0 / 0'}
                </strong>{' '}
                plugins &amp; themes
              </span>
              <span>&bull;</span>
              <span>Last NIST Fetch: {nistStatus?.last_fetch_human || 'Never'}</span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <button
                type="button"
                className="webcare-btn-micro"
                onClick={() => setShowNistLogs((prev) => !prev)}
              >
                {showNistLogs ? 'Hide Sync Logs' : `Sync Logs & Checked (${Object.keys(nistStatus?.checked_components || {}).length})`}
              </button>
              <a
                href="admin.php?page=webcare-pro-settings&tab=threat_intel"
                style={{ fontSize: '12px', fontWeight: 600, color: '#4f46e5', textDecoration: 'none' }}
              >
                Configure Key in Settings &rarr;
              </a>
              <button
                type="button"
                className="webcare-btn-micro"
                disabled={Boolean(nistStatus?.is_running)}
                onClick={async () => {
                  try {
                    const res = await wp.apiFetch({ path: '/webcare-pro-security/v1/cve/nist-sync-start', method: 'POST' }) as any;
                    if (res?.status) setNistStatus(res.status);
                  } catch {
                    // ignore
                  }
                }}
                style={{
                  background: nistStatus?.is_running ? 'var(--webcare-bg-elevated)' : '#4f46e5',
                  color: nistStatus?.is_running ? 'var(--webcare-text-muted)' : '#ffffff',
                  borderColor: nistStatus?.is_running ? 'var(--webcare-border-subtle)' : '#4338ca',
                  fontWeight: 600,
                }}
              >
                <RefreshCw size={12} className={nistStatus?.is_running ? 'webcare-spin' : ''} />
                {nistStatus?.is_running
                  ? `Syncing (${nistStatus.checked_count}/${nistStatus.total_components})…`
                  : 'Sync All with NIST'}
              </button>
            </div>
          </div>

          {showNistLogs && (
            <div
              style={{
                margin: '0 20px 14px 20px',
                padding: '14px 16px',
                borderRadius: '10px',
                background: 'var(--webcare-bg-panel)',
                border: '1px solid var(--webcare-border-subtle)',
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
                gap: '14px',
              }}
            >
              <div>
                <strong style={{ display: 'block', marginBottom: '8px', fontSize: '12.5px', color: 'var(--webcare-text-primary)' }}>
                  Checked Components ({Object.keys(nistStatus?.checked_components || {}).length})
                </strong>
                <div style={{ maxHeight: '180px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {Object.keys(nistStatus?.checked_components || {}).length === 0 ? (
                    <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted)' }}>No components checked yet. Click "Fetch NIST" or "Sync All with NIST".</span>
                  ) : (
                    Object.values(nistStatus?.checked_components || {}).map((comp: any) => (
                      <div key={comp.slug} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 10px', borderRadius: '8px', background: 'var(--webcare-bg-card)', border: '1px solid var(--webcare-border-subtle)', fontSize: '12px' }}>
                        <div>
                          <strong>{comp.name}</strong> <span style={{ color: 'var(--webcare-text-muted)' }}>v{comp.version}</span>
                          <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted)' }}>{comp.checked_human} &bull; {comp.raw_total} NVD records</div>
                        </div>
                        <span style={{ fontWeight: 700, fontSize: '11px', color: comp.matched_count > 0 ? '#dc2626' : '#059669' }}>
                          {comp.error ? comp.error : comp.matched_count > 0 ? `${comp.matched_count} CVE(s)` : 'Clean'}
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>
              <div>
                <strong style={{ display: 'block', marginBottom: '8px', fontSize: '12.5px', color: 'var(--webcare-text-primary)' }}>
                  Recent NIST Sync Logs ({(nistStatus?.logs || []).length})
                </strong>
                <div style={{ maxHeight: '180px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {(nistStatus?.logs || []).length === 0 ? (
                    <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted)' }}>No sync activity logged yet.</span>
                  ) : (
                    (nistStatus?.logs || []).map((log: any, idx: number) => (
                      <div key={idx} style={{ padding: '6px 10px', borderRadius: '8px', background: 'var(--webcare-bg-card)', border: '1px solid var(--webcare-border-subtle)', fontSize: '11.5px' }}>
                        <div style={{ color: 'var(--webcare-text-primary)' }}>{log.message}</div>
                        <div style={{ fontSize: '10.5px', color: 'var(--webcare-text-muted)', marginTop: '2px' }}>{log.ts_human} &bull; HTTP {log.http_status || 'ERR'}</div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}

          {filteredComponents.length === 0 ? (
            <EmptyStateCard
              icon={ShieldCheck}
              title="No known CVEs detected across your installed plugins and themes."
              description="Zero known CVE vulnerabilities detected. All active plugins and themes are verified against the latest official security bulletins."
              badge="Zero CVEs"
              badgeType="clean"
            />
          ) : (
            <table className="webcare-table-modern" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={{ width: '36px', textAlign: 'center' }}></th>
                  <th>Component Name & Details</th>
                  <th>Origin Provenance</th>
                  <th>Status & Risk</th>
                  <th>Installed</th>
                  <th>Latest Available</th>
                  <th>Known CVEs</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredComponents.map((item) => {
                  const itemKey = `${item.type}-${item.slug || item.name}`;
                  const isExpanded = !!expandedItems[itemKey];
                  const hasUnknown = !!(item.unknown_count && item.unknown_count > 0);

                  return (
                    <Fragment key={itemKey}>
                      <tr className={`webcare-table-row-modern ${item.has_cve ? 'has-alert' : hasUnknown || item.is_outdated ? 'is-update-ready' : 'is-clean'}`}>
                        {/* Expand Button */}
                        <td style={{ textAlign: 'center', padding: '12px 6px' }}>
                          <button
                            type="button"
                            style={{
                              background: 'transparent',
                              border: 'none',
                              cursor: 'pointer',
                              padding: '4px',
                              color: '#64748b',
                              display: 'inline-flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              borderRadius: '4px'
                            }}
                            onClick={() => toggleExpand(itemKey)}
                          >
                            {isExpanded ? <ChevronDown size={17} /> : <ChevronRight size={17} />}
                          </button>
                        </td>

                        {/* Name & Metadata */}
                        <td>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                            <div style={{ fontWeight: 700, color: '#0f172a', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span>{item.name}</span>
                              {item.is_active && (
                                <span style={{
                                  fontSize: '10px',
                                  background: '#e0f2fe',
                                  color: '#0369a1',
                                  padding: '1px 6px',
                                  borderRadius: '4px',
                                  fontWeight: 700
                                }}>
                                  ACTIVE
                                </span>
                              )}
                            </div>
                            <div style={{ fontSize: '11px', color: '#64748b', display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span style={{
                                textTransform: 'uppercase',
                                fontWeight: 700,
                                fontSize: '10px',
                                color: item.type === 'core' ? '#2563eb' : item.type === 'theme' ? '#7c3aed' : '#059669'
                              }}>
                                {item.type}
                              </span>
                              {item.slug && <span>&bull; slug: <code style={{ fontSize: '11px' }}>{item.slug}</code></span>}
                              {item.author && <span>&bull; by {item.author}</span>}
                            </div>
                          </div>
                        </td>

                        {/* Type & Origin Badges */}
                        <td>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', alignItems: 'flex-start' }}>
                            {item.type === 'core' ? (
                              <span className="webcare-origin-badge-official" title="Official WordPress Core Distribution">
                                <CheckCircle2 size={11} /> Official Core
                              </span>
                            ) : item.origin === 'official' ? (
                              <span className="webcare-origin-badge-official" title="Verified against WordPress.org public directory">
                                <CheckCircle2 size={11} /> Official WP.org
                              </span>
                            ) : (
                              <span className="webcare-origin-badge-premium" title="Third-Party, Commercial or Bespoke Plugin/Theme">
                                <Package size={11} /> Premium / Custom
                              </span>
                            )}
                          </div>
                        </td>

                        {/* Status Badge & Unknown Warnings */}
                        <td>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', alignItems: 'flex-start' }}>
                            {item.has_cve ? (
                              <span className="webcare-status-pill-vulnerable">
                                <ShieldAlert size={11} /> CRITICAL &bull; CVSS {item.max_cvss}
                              </span>
                            ) : item.is_outdated ? (
                              <span className="webcare-status-pill-update">
                                <AlertTriangle size={11} /> UPDATE READY
                              </span>
                            ) : (
                              <span className="webcare-status-pill-secure">
                                <CheckCircle2 size={11} /> UP TO DATE
                              </span>
                            )}

                            {hasUnknown && (
                              <span
                                className="webcare-unknown-warning-badge"
                                onClick={() => toggleExpand(itemKey)}
                                title="Unrecognized files not part of official release manifest"
                              >
                                <AlertTriangle size={11} /> {item.unknown_count} Unknown File{item.unknown_count! > 1 ? 's' : ''}
                              </span>
                            )}
                          </div>
                        </td>

                        {/* Installed Version */}
                        <td>
                          <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: '12px', color: item.is_outdated ? '#b91c1c' : '#334155' }}>
                            v{item.installed_version}
                          </span>
                        </td>

                        {/* Available Version */}
                        <td>
                          <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: '12px', color: item.is_outdated ? '#16a34a' : '#64748b' }}>
                            v{item.latest_version}
                          </span>
                        </td>

                        {/* Known CVEs Badge */}
                        <td>
                          {item.has_cve ? (
                            <button
                              type="button"
                              className="webcare-cve-pill-btn"
                              onClick={() => toggleExpand(itemKey)}
                              title="Click to view complete CVE advisory details"
                            >
                              <ShieldAlert size={12} />
                              <span>{item.cve_count} CVE{item.cve_count > 1 ? 's' : ''}</span>
                              <span className="webcare-cvss-score-pill">CVSS {item.max_cvss}</span>
                            </button>
                          ) : (
                            <span style={{ fontSize: '12px', color: '#94a3b8' }}>None</span>
                          )}
                        </td>

                        {/* Action Buttons */}
                        <td style={{ textAlign: 'right' }}>
                          <div style={{ display: 'inline-flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                            <button
                              type="button"
                              className="webcare-btn-micro"
                              disabled={busyActionKey === `nist-${item.slug || item.name}`}
                              onClick={async () => {
                                const key = `nist-${item.slug || item.name}`;
                                setBusyActionKey(key);
                                try {
                                  const res = await apiRequest({
                                    path: '/webcare-pro-security/v1/cve/nist-fetch-component',
                                    method: 'POST',
                                    data: {
                                      slug: item.slug,
                                      name: item.name,
                                      version: item.installed_version || '0.0.0',
                                    },
                                  });
                                  if (res && res.success) {
                                    if (res.status) setNistStatus(res.status);
                                    await loadInventory(true);
                                  }
                                } catch {
                                  // Ignore transient network errors
                                } finally {
                                  setBusyActionKey(null);
                                }
                              }}
                              title="Live-query NIST NVD for this component"
                            >
                              <RefreshCw size={11} className={busyActionKey === `nist-${item.slug || item.name}` ? 'webcare-spin' : ''} />
                              {busyActionKey === `nist-${item.slug || item.name}` ? 'Fetching…' : 'Fetch NIST'}
                            </button>
                            {(item.is_outdated || item.has_cve) && (() => {
                              const compSlug = item.slug || item.name;
                              const activeShieldId = virtualShields[compSlug];
                              const isShieldBusy = busyActionKey === `shield-${compSlug}`;
                              const isUpdateBusy = item.file ? busyActionKey === `update-${item.file}` : false;
                              return (
                                <>
                                  {activeShieldId ? (
                                    <span
                                      style={{
                                        display: 'inline-flex',
                                        alignItems: 'center',
                                        gap: '4px',
                                        padding: '4px 8px',
                                        borderRadius: '6px',
                                        fontSize: '11px',
                                        fontWeight: 700,
                                        background: 'var(--webcare-status-clean-soft)',
                                        color: 'var(--webcare-status-clean)',
                                        border: '1px solid var(--webcare-status-clean-border)',
                                      }}
                                      title={`Protected via ${activeShieldId}`}
                                    >
                                      <ShieldCheck size={11} /> Virtual Shield Active
                                    </span>
                                  ) : (
                                    <button
                                      type="button"
                                      onClick={() => handleActivateVirtualShield(item)}
                                      disabled={isShieldBusy}
                                      style={{
                                        display: 'inline-flex',
                                        alignItems: 'center',
                                        gap: '4px',
                                        padding: '4px 9px',
                                        borderRadius: '6px',
                                        fontSize: '11px',
                                        fontWeight: 700,
                                        cursor: 'pointer',
                                        background: 'var(--webcare-status-info-soft)',
                                        color: 'var(--webcare-status-info)',
                                        border: '1px solid var(--webcare-status-info-border)',
                                      }}
                                      title="Protect endpoints at firewall level immediately without running plugin update"
                                    >
                                      {isShieldBusy ? <Loader2 size={11} className="webcare-spin" /> : <Shield size={11} />}
                                      Shield Without Updating
                                    </button>
                                  )}

                                  <button
                                    type="button"
                                    onClick={async () => {
                                      try {
                                        const res = await apiRequest({
                                          path: '/webcare-pro-security/v1/cve/nist-fetch-component',
                                          method: 'POST',
                                          data: {
                                            slug: item.slug,
                                            name: item.name,
                                            version: item.installed_version || '0.0.0',
                                          },
                                        });
                                        if (res && res.success) {
                                          await loadInventory(true);
                                        }
                                      } catch (e) {
                                        // Ignore transient network errors
                                      }
                                    }}
                                    style={{
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '4px',
                                      padding: '4px 8px',
                                      borderRadius: '6px',
                                      fontSize: '11px',
                                      fontWeight: 600,
                                      cursor: 'pointer',
                                      background: 'var(--webcare-bg-panel)',
                                      color: 'var(--webcare-text-secondary)',
                                      border: '1px solid var(--webcare-border-subtle)',
                                    }}
                                    title="Live-fetch CVE advisories from NIST NVD for this component and store in Vault"
                                  >
                                    Fetch NIST
                                  </button>

                                  {item.is_outdated && item.type === 'plugin' && item.file ? (
                                    <button
                                      type="button"
                                      onClick={() => handleSafeUpdateWithBackup(item)}
                                      disabled={isUpdateBusy}
                                      style={{
                                        display: 'inline-flex',
                                        alignItems: 'center',
                                        gap: '4px',
                                        padding: '4px 10px',
                                        borderRadius: '6px',
                                        fontSize: '11px',
                                        fontWeight: 700,
                                        cursor: 'pointer',
                                        background: '#059669',
                                        color: '#ffffff',
                                        border: 'none',
                                      }}
                                      title="Automatically backs up plugin folder to Vault before updating so you can roll back in 1 click"
                                    >
                                      {isUpdateBusy ? <Loader2 size={11} className="webcare-spin" /> : <RefreshCw size={11} />}
                                      {isUpdateBusy ? 'Backing Up & Updating...' : 'Safe Update (Auto-Backup)'}
                                    </button>
                                  ) : item.is_outdated && item.update_url ? (
                                    <a
                                      href={item.update_url}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="webcare-btn-update-software"
                                      title="Open WordPress update manager in new tab"
                                    >
                                      <RefreshCw size={11} /> Update <ArrowUpRight size={10} />
                                    </a>
                                  ) : null}
                                </>
                              );
                            })()}
                            {item.file && safeBackups[item.file]?.snapshot_id && (
                              <button
                                type="button"
                                onClick={() => handleRollbackSafeUpdate(safeBackups[item.file].snapshot_id, item.name)}
                                disabled={busyActionKey === `rollback-${safeBackups[item.file].snapshot_id}`}
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '4px',
                                  padding: '4px 9px',
                                  borderRadius: '6px',
                                  fontSize: '11px',
                                  fontWeight: 700,
                                  cursor: 'pointer',
                                  background: 'var(--webcare-status-warn-soft)',
                                  color: 'var(--webcare-status-warn)',
                                  border: '1px solid var(--webcare-status-warn-border)',
                                }}
                                title={`Roll back to pre-update backup v${safeBackups[item.file].previous_version}`}
                              >
                                <RotateCcw size={11} /> Rollback v{safeBackups[item.file].previous_version}
                              </button>
                            )}
                            <button
                              type="button"
                              className="webcare-btn"
                              style={{
                                background: 'var(--webcare-bg-surface, #f8fafc)',
                                color: 'var(--webcare-text-secondary, #475569)',
                                fontSize: '11px',
                                padding: '4px 9px',
                                border: '1px solid var(--webcare-border, #e2e8f0)'
                              }}
                              onClick={() => toggleExpand(itemKey)}
                            >
                              {isExpanded ? 'Hide' : 'Details'}
                            </button>
                          </div>
                        </td>
                      </tr>

                      {/* Expanded CVE & Forensic Detail Row */}
                      {isExpanded && (
                        <tr className="webcare-vuln-expanded-row">
                          <td></td>
                          <td colSpan={7} style={{ padding: '20px 24px' }}>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                              {/* Status Alert Banner */}
                              <div className={
                                item.has_cve
                                  ? 'webcare-vuln-banner-cve'
                                  : item.is_outdated
                                  ? 'webcare-vuln-banner-update'
                                  : 'webcare-vuln-banner-clean'
                              }>
                                <div>
                                  <div className={
                                    item.has_cve
                                      ? 'webcare-vuln-banner-title-cve'
                                      : item.is_outdated
                                      ? 'webcare-vuln-banner-title-update'
                                      : 'webcare-vuln-banner-title-clean'
                                  }>
                                    {item.has_cve
                                      ? `⚠️ Security Exposure: ${item.cve_count} Active CVE Vulnerability Advisory(s) Documented`
                                      : item.is_outdated
                                      ? `⚡ Pending Update: Upgrade Available to v${item.latest_version}`
                                      : `✅ Component is running latest version v${item.installed_version} with clean security audit.`}
                                  </div>
                                  <div className="webcare-vuln-banner-sub">
                                    Installed path: <code>{item.type === 'core' ? 'WordPress Core (ABSPATH)' : item.file || item.slug}</code>
                                    {(() => {
                                      const nistEntry = nistStatus?.checked_components?.[(item.slug || '').toLowerCase()];
                                      if (!nistEntry) {
                                        return (
                                          <span style={{ display: 'block', marginTop: '4px', fontSize: '11.5px', color: 'var(--webcare-text-muted)' }}>
                                            NIST NVD Audit: Not queried yet — click <strong>Fetch NIST</strong> to live-query NIST NVD 2.0.
                                          </span>
                                        );
                                      }
                                      return (
                                        <span style={{ display: 'block', marginTop: '4px', fontSize: '11.5px', color: 'var(--webcare-text-secondary)' }}>
                                          <strong>NIST NVD Audit:</strong> Checked {nistEntry.checked_human} &bull; Query: <code>{nistEntry.query_keyword}</code> &bull; HTTP {nistEntry.http_status} &bull; Scanned {nistEntry.raw_total} NVD records &bull;{' '}
                                          <strong style={{ color: nistEntry.matched_count > 0 ? '#dc2626' : '#059669' }}>
                                            {nistEntry.error ? nistEntry.error : nistEntry.matched_count > 0 ? `${nistEntry.matched_count} matched CVE(s)` : '0 matching CVEs (Clean)'}
                                          </strong>
                                        </span>
                                      );
                                    })()}
                                  </div>
                                </div>

                                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
                                  {(item.is_outdated || item.has_cve) && (() => {
                                    const compSlug = item.slug || item.name;
                                    const activeShieldId = virtualShields[compSlug];
                                    return activeShieldId ? (
                                      <span
                                        style={{
                                          display: 'inline-flex',
                                          alignItems: 'center',
                                          gap: '5px',
                                          padding: '6px 12px',
                                          borderRadius: '8px',
                                          fontSize: '12px',
                                          fontWeight: 700,
                                          background: 'var(--webcare-status-clean-soft)',
                                          color: 'var(--webcare-status-clean)',
                                          border: '1px solid var(--webcare-status-clean-border)',
                                        }}
                                      >
                                        <ShieldCheck size={13} /> Virtual Shield Active ({activeShieldId})
                                      </span>
                                    ) : (
                                      <button
                                        type="button"
                                        onClick={() => handleActivateVirtualShield(item)}
                                        disabled={busyActionKey === `shield-${compSlug}`}
                                        style={{
                                          display: 'inline-flex',
                                          alignItems: 'center',
                                          gap: '6px',
                                          padding: '7px 13px',
                                          borderRadius: '8px',
                                          fontSize: '12px',
                                          fontWeight: 700,
                                          cursor: 'pointer',
                                          background: 'var(--webcare-status-info-soft)',
                                          color: 'var(--webcare-status-info)',
                                          border: '1px solid var(--webcare-status-info-border)',
                                        }}
                                      >
                                        <Shield size={13} /> Shield Without Updating (1-Click Virtual Patch)
                                      </button>
                                    );
                                  })()}

                                  <button
                                    type="button"
                                    onClick={async () => {
                                      try {
                                        const res = await apiRequest({
                                          path: '/webcare-pro-security/v1/cve/nist-fetch-component',
                                          method: 'POST',
                                          data: {
                                            slug: item.slug,
                                            name: item.name,
                                            version: item.installed_version || '0.0.0',
                                          },
                                        });
                                        if (res && res.success) {
                                          await loadInventory(true);
                                        }
                                      } catch (e) {
                                        // Ignore transient network errors
                                      }
                                    }}
                                    style={{
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '4px',
                                      padding: '4px 8px',
                                      borderRadius: '6px',
                                      fontSize: '11px',
                                      fontWeight: 600,
                                      cursor: 'pointer',
                                      background: 'var(--webcare-bg-panel)',
                                      color: 'var(--webcare-text-secondary)',
                                      border: '1px solid var(--webcare-border-subtle)',
                                    }}
                                    title="Live-fetch CVE advisories from NIST NVD for this component and store in Vault"
                                  >
                                    Fetch NIST
                                  </button>

                                  {item.is_outdated && item.type === 'plugin' && item.file ? (
                                    <button
                                      type="button"
                                      onClick={() => handleSafeUpdateWithBackup(item)}
                                      disabled={busyActionKey === `update-${item.file}`}
                                      style={{
                                        display: 'inline-flex',
                                        alignItems: 'center',
                                        gap: '6px',
                                        padding: '7px 14px',
                                        borderRadius: '8px',
                                        fontSize: '12px',
                                        fontWeight: 700,
                                        cursor: 'pointer',
                                        background: '#059669',
                                        color: '#ffffff',
                                        border: 'none',
                                      }}
                                    >
                                      <RefreshCw size={13} /> Safe Update (With Auto-Backup)
                                    </button>
                                  ) : item.update_url && item.is_outdated ? (
                                    <a
                                      href={item.update_url}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="webcare-btn-update-software"
                                    >
                                      <RefreshCw size={13} /> Update In WordPress Admin <ArrowUpRight size={12} />
                                    </a>
                                  ) : null}
                                </div>
                              </div>

                              {/* Origin & Provenance Information Card */}
                              <div className={`webcare-vuln-origin-box ${item.origin === 'official' || item.type === 'core' ? '' : 'is-custom'}`}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                  <Info size={16} color={item.origin === 'official' || item.type === 'core' ? '#10b981' : '#a855f7'} />
                                  <span className="webcare-vuln-origin-text">
                                    {item.type === 'core'
                                      ? 'WordPress Core: Official release distributed directly by the WordPress foundation.'
                                      : item.origin === 'official'
                                      ? 'Official & Publicly Available: Verified against the official WordPress.org plugin/theme repository release manifest and checksums.'
                                      : 'Premium or Custom Component: Third-party commercial or bespoke plugin/theme. Not hosted on the public WordPress.org repository; verified directly through vendor updates.'}
                                  </span>
                                </div>
                                {item.plugin_uri && (
                                  <a
                                    href={item.plugin_uri}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="webcare-link-subtle"
                                    style={{ fontSize: '12px', color: '#0284c7', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                  >
                                    Plugin Homepage <ExternalLink size={11} />
                                  </a>
                                )}
                                {item.theme_uri && (
                                  <a
                                    href={item.theme_uri}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="webcare-link-subtle"
                                    style={{ fontSize: '12px', color: '#0284c7', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                  >
                                    Theme Homepage <ExternalLink size={11} />
                                  </a>
                                )}
                              </div>

                              {/* Unknown Files Inspector Box */}
                              {hasUnknown && item.unknown_files && item.unknown_files.length > 0 && (
                                <div className="webcare-unknown-files-box">
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                                    <AlertTriangle size={18} color="#ef4444" />
                                    <h4 className="webcare-unknown-files-title">
                                      Unknown / Unrecognized Files Detected ({item.unknown_count})
                                    </h4>
                                  </div>
                                  <p className="webcare-unknown-files-desc">
                                    These files reside inside this official component's directory but are <strong>not present in the official WordPress.org release manifest</strong>.
                                    Foreign executable PHP files in official packages often indicate backdoors, web shells, or unauthorized tampering.
                                  </p>
                                  <table className="webcare-unknown-files-table">
                                    <thead>
                                      <tr>
                                        <th>Relative Path</th>
                                        <th>File Size</th>
                                        <th>Executable Risk</th>
                                        <th>Full Server Path</th>
                                      </tr>
                                    </thead>
                                    <tbody>
                                      {item.unknown_files.map((uf, idx) => (
                                        <tr key={idx}>
                                          <td style={{ fontFamily: 'monospace', fontWeight: 700, color: uf.is_executable ? '#be123c' : '#334155' }}>
                                            {uf.file}
                                          </td>
                                          <td>{Math.round(uf.size / 1024 * 10) / 10} KB</td>
                                          <td>
                                            {uf.is_executable ? (
                                              <span style={{ background: '#fee2e2', color: '#991b1b', padding: '2px 6px', borderRadius: '4px', fontWeight: 700, fontSize: '11px' }}>
                                                ⚠️ Executable PHP Script
                                              </span>
                                            ) : (
                                              <span style={{ color: '#64748b', fontSize: '11px' }}>Static Asset</span>
                                            )}
                                          </td>
                                          <td style={{ fontFamily: 'monospace', fontSize: '11px', color: '#64748b' }}>
                                            {uf.full_path}
                                          </td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                </div>
                              )}

                              {/* CVE List if available */}
                              {item.cves && item.cves.length > 0 && (
                                <div>
                                  <h4 style={{ margin: '0 0 12px 0', fontSize: '14px', color: '#991b1b', textTransform: 'uppercase', fontWeight: 800, letterSpacing: '0.5px' }}>
                                    Documented CVE Vulnerability Advisories & Exploits:
                                  </h4>
                                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '12px' }}>
                                    {item.cves.map((cve) => (
                                      <div key={cve.cve_id} className="webcare-cve-advisory-card">
                                        <div className="webcare-cve-card-header">
                                          <span className="webcare-cve-id-badge">{cve.cve_id}</span>
                                          <span className={
                                            cve.cvss >= 9.0 ? 'webcare-cvss-badge-critical' :
                                            cve.cvss >= 7.0 ? 'webcare-cvss-badge-high' : 'webcare-cvss-badge-medium'
                                          }>
                                            CVSS {cve.cvss} ({cve.severity.toUpperCase()})
                                          </span>
                                        </div>

                                        <div style={{ fontSize: '13px', fontWeight: 700, color: '#1e293b' }}>
                                          {cve.title}
                                        </div>

                                        <div style={{ fontSize: '12px', color: '#475569', lineHeight: 1.6 }}>
                                          {cve.cve_details}
                                        </div>

                                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '6px', paddingTop: '8px', borderTop: '1px solid #f1f5f9', fontSize: '11px' }}>
                                          <span style={{ color: '#64748b' }}>
                                            Fixed in release: <strong style={{ color: '#16a34a' }}>v{cve.fixed_in}</strong>
                                          </span>
                                          <a
                                            href={cve.reference}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="webcare-link-subtle"
                                            style={{ color: '#0284c7', fontWeight: 600 }}
                                          >
                                            NIST NVD Advisory <ExternalLink size={10} />
                                          </a>
                                        </div>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
};

export default VulnerabilitiesPage;
