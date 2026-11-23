import { useState, useEffect, useRef } from '@wordpress/element';
import { showConfirm } from '../utils/dialog';
import {
  Layers,
  ShieldCheck,
  ShieldAlert,
  Shield,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Lock,
  RotateCcw,
  Trash2,
  Search,
  ExternalLink,
  Copy,
  Check,
  Loader2,
  Terminal,
  Cpu,
  ArrowUpRight,
  Sliders,
  AlertCircle,
  Clock,
  Play,
  Download,
  ChevronDown,
  FileText,
  FileSpreadsheet
} from 'lucide-react';

interface SbomSupplyChainCardProps {
  apiRequest: (options: any) => Promise<any>;
  initialSubTab?: 'sbom' | 'gatekeeper' | 'advisor' | 'lockfiles' | 'scripts';
  onSubTabChange?: (tab: 'sbom' | 'gatekeeper' | 'advisor' | 'lockfiles' | 'scripts') => void;
}

export const SbomSupplyChainCard = ({
  apiRequest,
  initialSubTab = 'sbom',
  onSubTabChange,
}: SbomSupplyChainCardProps) => {
  const getStartingTab = (): 'sbom' | 'gatekeeper' | 'advisor' | 'lockfiles' | 'scripts' => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const sub = urlParams.get('section') || urlParams.get('subtab');
      if (sub === 'inventory' || sub === 'sbom') return 'sbom';
      if (sub === 'install-guard' || sub === 'advisor') return 'advisor';
      if (sub && ['gatekeeper', 'lockfiles', 'scripts'].includes(sub)) {
        return sub as any;
      }
    } catch (e) {}
    return initialSubTab;
  };
  const [activeSubTab, setActiveSubTab] = useState<'sbom' | 'gatekeeper' | 'advisor' | 'lockfiles' | 'scripts'>(getStartingTab);

  useEffect(() => {
    if (initialSubTab && initialSubTab !== activeSubTab) {
      setActiveSubTab(initialSubTab);
    }
  }, [initialSubTab]);

  const handleSubTabSwitch = (tab: 'sbom' | 'gatekeeper' | 'advisor' | 'lockfiles' | 'scripts') => {
    setActiveSubTab(tab);
    const sectionName = tab === 'sbom' ? 'inventory' : tab === 'advisor' ? 'install-guard' : tab;
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
  
  // SBOM State
  const [loadingSbom, setLoadingSbom] = useState<boolean>(true);
  const [calibrating, setCalibrating] = useState<boolean>(false);
  const [quarantiningId, setQuarantiningId] = useState<string | null>(null);
  const [sbomData, setSbomData] = useState<any>(null);
  const [sbomFilter, setSbomFilter] = useState<'all' | 'dropin' | 'mu' | 'ini' | 'autoloader'>('all');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Gatekeeper State
  const [loadingGk, setLoadingGk] = useState<boolean>(false);
  const [gkData, setGkData] = useState<{ logs: any[]; snapshots: any[]; settings: any }>({
    logs: [],
    snapshots: [],
    settings: { enabled: true, block_critical_threats: true, auto_snapshot_updates: true }
  });
  const [savingGkSettings, setSavingGkSettings] = useState<boolean>(false);
  const [rollingBackId, setRollingBackId] = useState<string | null>(null);

  // Risk Advisor State
  const [pluginSlugToScan, setPluginSlugToScan] = useState<string>('');
  const [analyzingSlug, setAnalyzingSlug] = useState<boolean>(false);
  const [analysisReport, setAnalysisReport] = useState<any>(null);

  // Dependency Lockfiles State
  const [loadingLockfiles, setLoadingLockfiles] = useState<boolean>(false);
  const [scanningLockfiles, setScanningLockfiles] = useState<boolean>(false);
  const [lockfileData, setLockfileData] = useState<any>(null);

  // Script Inventory & Drift State
  const [loadingScripts, setLoadingScripts] = useState<boolean>(false);
  const [calibratingScripts, setCalibratingScripts] = useState<boolean>(false);
  const [scriptData, setScriptData] = useState<any>(null);

  // Export State
  const [isExportOpen, setIsExportOpen] = useState<boolean>(false);
  const exportMenuRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const handleOutsideClick = (e: MouseEvent) => {
      if (exportMenuRef.current && !exportMenuRef.current.contains(e.target as Node)) {
        setIsExportOpen(false);
      }
    };
    if (isExportOpen) {
      document.addEventListener('mousedown', handleOutsideClick);
    }
    return () => {
      document.removeEventListener('mousedown', handleOutsideClick);
    };
  }, [isExportOpen]);

  const handleExportJSON = () => {
    setIsExportOpen(false);
    const host = window.location.hostname || 'site';
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const filename = `webcare-sbom-ledger-${host}-${timestamp}.json`;

    const fullExportData = {
      meta: {
        product: 'WebCare Pro Security & Firewall',
        engine: 'Supply-Chain Defense & Cryptographic SBOM Sentinel',
        version: '1.29.0',
        exported_at: new Date().toISOString(),
        site_url: window.location.origin,
        host: host,
      },
      sbom_summary: summary,
      baseline_status: {
        is_drifted: isDrifted,
        drift_count: driftCount,
        calibrated_at: sbomData?.calibrated_at || null,
        calibrated_by: sbomData?.calibrated_by || null,
      },
      runtime_inventory: {
        dropins: dropins,
        must_use_plugins: muPlugins,
        php_ini_directives: iniDirectives,
        autoloaders: autoloaders,
      },
      gatekeeper: {
        settings: gkData.settings,
        intercepted_logs: gkData.logs,
        pre_update_snapshots: gkData.snapshots,
      },
      lockfile_auditor: lockfileData || null,
      client_script_drift: scriptData || null,
    };

    const blob = new Blob([JSON.stringify(fullExportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showNotification('success', `Exported full SBOM ledger to ${filename}`);
  };

  const handleExportCSV = () => {
    setIsExportOpen(false);
    const host = window.location.hostname || 'site';
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const filename = `webcare-sbom-ledger-${host}-${timestamp}.csv`;

    const escapeCsv = (str: any) => {
      if (str === null || str === undefined) return '""';
      const s = String(str).replace(/"/g, '""');
      return `"${s}"`;
    };

    const headers = [
      'Category',
      'Identifier / Host',
      'Display Name',
      'Relative Path / Source',
      'SHA-256 Hash',
      'Status / Risk',
      'Details / Context',
      'Official / Verified',
      'First / Last Seen'
    ];

    const rows: string[][] = [];

    // 1. Drop-ins & MU-plugins & INI
    filteredItems.forEach((item: any) => {
      rows.push([
        item.type || 'anchor',
        item.id || item.name || '',
        item.name || '',
        item.rel_path || item.path || '',
        item.sha256 || item.prepend_sha || 'N/A',
        item.risk_level || 'none',
        (item.reasons && item.reasons.length > 0) ? item.reasons.join('; ') : (item.description || ''),
        item.is_trusted ? 'Verified Official' : (item.is_standard ? 'Standard' : 'No'),
        item.modified_at ? new Date(item.modified_at * 1000).toISOString() : 'N/A'
      ]);
    });

    // 2. Client-Side Script Drift
    if (scriptData?.domains) {
      scriptData.domains.forEach((dom: any) => {
        rows.push([
          'client_script_domain',
          dom.host || '',
          dom.provider || dom.host || '',
          `Monitored Handles: ${dom.script_count}`,
          'N/A (Remote Domain)',
          dom.is_recognized ? 'Clean Verified' : (dom.is_baseline ? 'Approved Baseline' : 'Uncalibrated Drift'),
          dom.has_sensitive ? 'ACTIVE ON CHECKOUT / AUTH' : 'General Pages Only',
          dom.is_recognized ? 'Verified Provider' : (dom.is_baseline ? 'Approved' : 'Unapproved'),
          'Runtime Enqueued'
        ]);
      });
    }

    // 3. Gatekeeper Logs
    if (gkData?.logs) {
      gkData.logs.forEach((log: any) => {
        rows.push([
          'gatekeeper_audit',
          log.package_slug || log.action_type || '',
          log.package_name || log.package_slug || '',
          log.version || '',
          log.snapshot_hash || 'N/A',
          log.status || 'intercepted',
          log.reason || log.message || '',
          'Gatekeeper Event',
          log.timestamp || log.created_at || 'N/A'
        ]);
      });
    }

    const csvContent = [
      headers.map(escapeCsv).join(','),
      ...rows.map(row => row.map(escapeCsv).join(','))
    ].join('\r\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showNotification('success', `Exported supply-chain ledger to ${filename}`);
  };

  const showNotification = (type: 'success' | 'error', text: string) => {
    setNotification({ type, text });
    setTimeout(() => setNotification(null), 4500);
  };

  const copyToClipboard = (text: string, id: string) => {
    if (!text) return;
    try {
      navigator.clipboard.writeText(text);
      setCopiedHash(id);
      setTimeout(() => setCopiedHash(null), 2000);
    } catch {
      // ignore
    }
  };

  // Fetch SBOM
  const fetchSbom = async () => {
    setLoadingSbom(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/supply-chain/sbom',
        method: 'GET'
      });
      if (res?.success && res.report) {
        setSbomData(res.report);
      }
    } catch (err: any) {
      console.error('Failed to load SBOM data:', err);
    } finally {
      setLoadingSbom(false);
    }
  };

  // Fetch Gatekeeper
  const fetchGatekeeper = async () => {
    setLoadingGk(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/supply-chain/gatekeeper',
        method: 'GET'
      });
      if (res?.success) {
        setGkData({
          logs: res.logs || [],
          snapshots: res.snapshots || [],
          settings: res.settings || { enabled: true, block_critical_threats: true, auto_snapshot_updates: true }
        });
      }
    } catch (err: any) {
      console.error('Failed to load Gatekeeper data:', err);
    } finally {
      setLoadingGk(false);
    }
  };

  // Fetch Lockfiles
  const fetchLockfiles = async (force: boolean = false) => {
    if (force) setScanningLockfiles(true);
    else setLoadingLockfiles(true);
    try {
      const res = await apiRequest({
        path: force ? '/webcare-pro-security/v1/supply-chain/lockfiles/scan' : '/webcare-pro-security/v1/supply-chain/lockfiles',
        method: force ? 'POST' : 'GET'
      });
      if (res?.success) {
        setLockfileData(res);
        if (force) showNotification('success', 'Lockfile dependency audit completed.');
      }
    } catch (err: any) {
      console.error('Failed to load lockfiles:', err);
      if (force) showNotification('error', err?.message || 'Failed to scan lockfiles.');
    } finally {
      setLoadingLockfiles(false);
      setScanningLockfiles(false);
    }
  };

  // Fetch Scripts
  const fetchScripts = async () => {
    setLoadingScripts(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/supply-chain/scripts',
        method: 'GET'
      });
      if (res?.success) {
        setScriptData(res);
      }
    } catch (err: any) {
      console.error('Failed to load script inventory:', err);
    } finally {
      setLoadingScripts(false);
    }
  };

  const handleCalibrateScripts = async () => {
    setCalibratingScripts(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/supply-chain/scripts/calibrate',
        method: 'POST'
      });
      if (res?.success) {
        showNotification('success', 'Third-party script baseline calibrated.');
        setScriptData(res.status);
      }
    } catch (err: any) {
      showNotification('error', err?.message || 'Failed to calibrate baseline.');
    } finally {
      setCalibratingScripts(false);
    }
  };

  const handleDismissScriptAlert = async (alertId: string) => {
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/supply-chain/scripts/dismiss',
        method: 'POST',
        data: { alert_id: alertId }
      });
      if (res?.success) {
        showNotification('success', 'Script drift alert dismissed.');
        await fetchScripts();
      }
    } catch (err: any) {
      showNotification('error', err?.message || 'Failed to dismiss alert.');
    }
  };

  useEffect(() => {
    fetchSbom();
    fetchGatekeeper();
    fetchLockfiles();
    fetchScripts();
  }, []);

  // Handle Calibrate Baseline
  const handleCalibrate = async () => {
    setCalibrating(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/supply-chain/sbom/calibrate',
        method: 'POST'
      });
      if (res?.success) {
        showNotification('success', res.message || 'Baseline calibrated successfully.');
        await fetchSbom();
      } else {
        showNotification('error', res?.message || 'Failed to calibrate baseline.');
      }
    } catch (err: any) {
      showNotification('error', err?.message || 'Calibration network error.');
    } finally {
      setCalibrating(false);
    }
  };

  // Handle Quarantine Anchor
  const handleQuarantine = async (itemId: string, name: string) => {
    const confirmed = await showConfirm({
      title: 'Quarantine Component',
      message: `Are you sure you want to isolate and quarantine "${name}" into the WebCare Vault? This removes it from runtime execution.`,
      confirmLabel: 'Quarantine to Vault',
      variant: 'danger',
    });
    if (!confirmed) {
      return;
    }
    setQuarantiningId(itemId);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/supply-chain/sbom/isolate',
        method: 'POST',
        data: { item_id: itemId }
      });
      if (res?.success) {
        showNotification('success', res.message || `Successfully quarantined ${name} to vault.`);
        await fetchSbom();
      } else {
        showNotification('error', res?.message || `Failed to quarantine ${name}.`);
      }
    } catch (err: any) {
      showNotification('error', err?.message || 'Quarantine error.');
    } finally {
      setQuarantiningId(null);
    }
  };

  // Handle Toggle Gatekeeper Setting
  const handleUpdateGkSetting = async (key: string, val: boolean) => {
    const updated = { ...gkData.settings, [key]: val };
    setGkData((prev) => ({ ...prev, settings: updated }));
    setSavingGkSettings(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/supply-chain/gatekeeper/settings',
        method: 'POST',
        data: updated
      });
      if (res?.success) {
        showNotification('success', 'Gatekeeper settings updated.');
      }
    } catch (err: any) {
      showNotification('error', err?.message || 'Failed to save settings.');
    } finally {
      setSavingGkSettings(false);
    }
  };

  // Handle 1-Click Rollback
  const handleRollback = async (snapshotId: string, slug: string) => {
    const confirmed = await showConfirm({
      title: 'Rollback Plugin Update',
      message: `Are you sure you want to roll back "${slug}" to this pre-update snapshot? The current plugin files will be safely replaced.`,
      confirmLabel: 'Rollback Plugin',
      variant: 'warning',
    });
    if (!confirmed) {
      return;
    }
    setRollingBackId(snapshotId);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/supply-chain/gatekeeper/rollback',
        method: 'POST',
        data: { snapshot_id: snapshotId }
      });
      if (res?.success) {
        showNotification('success', res.message || `Successfully rolled back ${slug}.`);
        await fetchGatekeeper();
      } else {
        showNotification('error', res?.message || 'Rollback failed.');
      }
    } catch (err: any) {
      showNotification('error', err?.message || 'Rollback execution error.');
    } finally {
      setRollingBackId(null);
    }
  };

  // Handle Clear Gatekeeper Logs
  const handleClearGatekeeperLogs = async () => {
    const confirmed = await showConfirm({
      title: 'Clear Gatekeeper Ledger',
      message: 'Are you sure you want to clear the Gatekeeper audit ledger history?',
      confirmLabel: 'Clear Ledger',
      variant: 'warning',
    });
    if (!confirmed) {
      return;
    }
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/supply-chain/gatekeeper/clear',
        method: 'POST'
      });
      if (res?.success) {
        showNotification('success', 'Gatekeeper audit ledger cleared.');
        await fetchGatekeeper();
      }
    } catch (err: any) {
      showNotification('error', err?.message || 'Failed to clear logs.');
    }
  };

  // Handle Run Risk Analysis
  const handleAnalyzePlugin = async () => {
    const slug = pluginSlugToScan.trim();
    if (!slug) {
      showNotification('error', 'Please enter a plugin slug to analyze.');
      return;
    }
    setAnalyzingSlug(true);
    setAnalysisReport(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/supply-chain/analyze-plugin',
        method: 'POST',
        data: { slug }
      });
      if (res?.success && res.analysis) {
        setAnalysisReport(res.analysis);
      } else {
        showNotification('error', res?.message || 'Failed to inspect plugin folder.');
      }
    } catch (err: any) {
      showNotification('error', err?.message || 'Risk analysis network failure.');
    } finally {
      setAnalyzingSlug(false);
    }
  };

  // Filter SBOM items
  const inventory = sbomData?.inventory || {};
  const dropins = inventory.dropins || [];
  const muPlugins = inventory.mu_plugins || [];
  const iniDirectives = inventory.ini_directives || [];
  const autoloaders = inventory.autoloaders || [];

  const filteredItems = (() => {
    let list: any[] = [];
    if (sbomFilter === 'all' || sbomFilter === 'dropin') {
      list = [...list, ...dropins];
    }
    if (sbomFilter === 'all' || sbomFilter === 'mu') {
      list = [...list, ...muPlugins];
    }
    if (sbomFilter === 'all' || sbomFilter === 'ini') {
      list = [...list, ...iniDirectives];
    }
    if (sbomFilter === 'all' || sbomFilter === 'autoloader') {
      list = [...list, ...autoloaders];
    }
    return list;
  })();

  const summary = inventory.summary || {
    total_anchors: 0,
    active_dropins: 0,
    mu_plugins_count: 0,
    ini_injections_count: 0,
    anomalies_count: 0
  };

  const isDrifted = sbomData?.is_drifted;
  const driftCount = sbomData?.drift_count || 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Toast Notification */}
      {notification && (
        <div
          style={{
            padding: '12px 18px',
            borderRadius: '8px',
            fontSize: '13px',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            background: notification.type === 'success' ? '#ecfdf5' : '#fef2f2',
            color: notification.type === 'success' ? '#047857' : '#b91c1c',
            border: `1px solid ${notification.type === 'success' ? '#a7f3d0' : '#fca5a5'}`,
            boxShadow: '0 2px 6px rgba(0,0,0,0.05)'
          }}
        >
          {notification.type === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
          <span>{notification.text}</span>
        </div>
      )}

      {/* Header Card */}
      <div className="webcare-firewall-card" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{
                width: '40px',
                height: '40px',
                borderRadius: '10px',
                background: 'linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)',
                color: '#ffffff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Layers size={22} />
              </div>
              <div>
                <h2 style={{ margin: 0, fontSize: '20px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  Supply-Chain Defense &amp; SBOM Sentinel
                </h2>
                <p style={{ margin: '3px 0 0 0', fontSize: '13px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  Cryptographic Software Bill of Materials (SBOM), drop-in anchor monitoring, and pre-install delta gatekeeper.
                </p>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {/* Export Report Dropdown */}
            <div ref={exportMenuRef} style={{ position: 'relative' }}>
              <button
                type="button"
                className="webcare-btn"
                onClick={() => setIsExportOpen(!isExportOpen)}
                style={{
                  background: 'var(--webcare-bg-surface, #ffffff)',
                  color: 'var(--webcare-text-primary, #0f172a)',
                  border: '1px solid var(--webcare-border-form, #cbd5e1)',
                  padding: '8px 14px',
                  borderRadius: '8px',
                  fontSize: '13px',
                  fontWeight: 600,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  cursor: 'pointer'
                }}
                title="Export supply-chain ledger and telemetry for offline forensic analysis"
              >
                <Download size={14} />
                <span>Export Report</span>
                <ChevronDown size={13} style={{ transform: isExportOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s ease' }} />
              </button>

              {isExportOpen && (
                <div style={{
                  position: 'absolute',
                  top: '100%',
                  right: 0,
                  marginTop: '6px',
                  width: '240px',
                  background: 'var(--webcare-bg-panel, #ffffff)',
                  border: '1px solid var(--webcare-border-std, #e2e8f0)',
                  borderRadius: '10px',
                  boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)',
                  padding: '6px',
                  zIndex: 100,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '2px'
                }}>
                  <div style={{ padding: '6px 10px', fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>
                    Select Export Format
                  </div>

                  <button
                    type="button"
                    onClick={handleExportJSON}
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '10px',
                      padding: '8px 10px',
                      borderRadius: '6px',
                      background: 'transparent',
                      border: 'none',
                      textAlign: 'left',
                      cursor: 'pointer',
                      color: 'var(--webcare-text-primary, #0f172a)',
                      transition: 'background 0.15s ease'
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--webcare-bg-surface, #f8fafc)')}
                    onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                  >
                    <FileCode size={16} color="#4f46e5" style={{ marginTop: '2px', flexShrink: 0 }} />
                    <div>
                      <div style={{ fontSize: '12.5px', fontWeight: 600 }}>Full SBOM Ledger (.JSON)</div>
                      <div style={{ fontSize: '10.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                        Complete cryptographic raw hashes, directives, script drift, and Gatekeeper logs.
                      </div>
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={handleExportCSV}
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '10px',
                      padding: '8px 10px',
                      borderRadius: '6px',
                      background: 'transparent',
                      border: 'none',
                      textAlign: 'left',
                      cursor: 'pointer',
                      color: 'var(--webcare-text-primary, #0f172a)',
                      transition: 'background 0.15s ease'
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--webcare-bg-surface, #f8fafc)')}
                    onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                  >
                    <FileSpreadsheet size={16} color="#059669" style={{ marginTop: '2px', flexShrink: 0 }} />
                    <div>
                      <div style={{ fontSize: '12.5px', fontWeight: 600 }}>Tabular Summary (.CSV)</div>
                      <div style={{ fontSize: '10.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                        Spreadsheet-friendly rows for inventory audit and compliance review.
                      </div>
                    </div>
                  </button>
                </div>
              )}
            </div>

            <button
              type="button"
              className="webcare-btn"
              onClick={handleCalibrate}
              disabled={calibrating}
              style={{
                background: 'linear-gradient(135deg, #4f46e5 0%, #4338ca 100%)',
                color: '#ffffff',
                border: 'none',
                padding: '8px 16px',
                borderRadius: '8px',
                fontSize: '13px',
                fontWeight: 600,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                cursor: 'pointer'
              }}
              title="Record current active drop-ins and mu-plugins as clean baseline"
            >
              {calibrating ? <Loader2 size={14} className="webcare-spin-icon" /> : <ShieldCheck size={14} />}
              <span>{calibrating ? 'Calibrating...' : 'Calibrate Baseline'}</span>
            </button>

            <button
              type="button"
              className="webcare-btn"
              onClick={() => { fetchSbom(); fetchGatekeeper(); }}
              disabled={loadingSbom || loadingGk}
              style={{
                background: 'var(--webcare-bg-surface, #ffffff)',
                color: 'var(--webcare-text-primary, #0f172a)',
                border: '1px solid var(--webcare-border-form, #cbd5e1)',
                padding: '8px 14px',
                borderRadius: '8px',
                fontSize: '13px',
                fontWeight: 600,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                cursor: 'pointer'
              }}
              title="Refresh real-time inventory ledger"
            >
              <RefreshCw size={14} className={loadingSbom ? 'webcare-spin-icon' : ''} />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {/* 4 KPI Summary Cards */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '16px',
          marginTop: '22px'
        }}>
          {/* KPI 1: Drop-Ins */}
          <div className="webcare-firewall-rule-card" style={{ padding: '16px', borderLeft: '4px solid #4f46e5' }}>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>
              Active Drop-Ins
            </div>
            <div style={{ fontSize: '26px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)', margin: '4px 0' }}>
              {summary.active_dropins} <span style={{ fontSize: '13px', fontWeight: 500, color: '#64748b' }}>/ {dropins.length} standard</span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
              Monitored <code>db.php</code>, <code>object-cache.php</code>, etc.
            </div>
          </div>

          {/* KPI 2: Must-Use Plugins */}
          <div className="webcare-firewall-rule-card" style={{ padding: '16px', borderLeft: '4px solid #7c3aed' }}>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>
              Must-Use Plugins (mu-plugins)
            </div>
            <div style={{ fontSize: '26px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)', margin: '4px 0' }}>
              {summary.mu_plugins_count}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
              Autoloaded before all regular plugins
            </div>
          </div>

          {/* KPI 3: Baseline Integrity */}
          <div className="webcare-firewall-rule-card" style={{
            padding: '16px',
            borderLeft: `4px solid ${isDrifted ? '#dc2626' : '#10b981'}`
          }}>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>
              Baseline Integrity
            </div>
            <div style={{
              fontSize: '18px',
              fontWeight: 800,
              color: isDrifted ? '#dc2626' : '#059669',
              margin: '6px 0',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}>
              {isDrifted ? <AlertTriangle size={20} /> : <CheckCircle2 size={20} />}
              <span>{isDrifted ? `${driftCount} Drift Anomalies` : 'Clean Baseline Match'}</span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
              {sbomData?.calibrated_at ? `Calibrated: ${sbomData.calibrated_at}` : 'No baseline recorded yet'}
            </div>
          </div>

          {/* KPI 4: Gatekeeper Defense */}
          <div className="webcare-firewall-rule-card" style={{ padding: '16px', borderLeft: '4px solid #0284c7' }}>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>
              Update Gatekeeper
            </div>
            <div style={{
              fontSize: '18px',
              fontWeight: 800,
              color: gkData.settings.enabled ? '#0284c7' : '#94a3b8',
              margin: '6px 0',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}>
              <ShieldCheck size={20} color={gkData.settings.enabled ? '#0284c7' : '#94a3b8'} />
              <span>{gkData.settings.enabled ? 'Active Intercept' : 'Disabled'}</span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
              {gkData.snapshots.length} rollback snapshots stashed
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)',
        paddingBottom: '10px'
      }}>
        <button
          type="button"
          className={`webcare-tab-link ${activeSubTab === 'sbom' ? 'is-active' : ''}`}
          onClick={() => handleSubTabSwitch('sbom')}
          style={{ cursor: 'pointer' }}
        >
          <Layers size={15} /> Drop-Ins &amp; SBOM Ledger ({filteredItems.length})
        </button>

        <button
          type="button"
          className={`webcare-tab-link ${activeSubTab === 'gatekeeper' ? 'is-active' : ''}`}
          onClick={() => handleSubTabSwitch('gatekeeper')}
          style={{ cursor: 'pointer' }}
        >
          <Shield size={15} /> Update Gatekeeper Audits ({gkData.logs.length})
        </button>

        <button
          type="button"
          className={`webcare-tab-link ${activeSubTab === 'advisor' ? 'is-active' : ''}`}
          onClick={() => handleSubTabSwitch('advisor')}
          style={{ cursor: 'pointer' }}
        >
          <Cpu size={15} /> Shift-Left Risk Analyzer
        </button>

        <button
          type="button"
          className={`webcare-tab-link ${activeSubTab === 'lockfiles' ? 'is-active' : ''}`}
          onClick={() => handleSubTabSwitch('lockfiles')}
          style={{ cursor: 'pointer' }}
        >
          <Lock size={15} /> Dependency Lockfiles ({lockfileData?.vulnerabilities?.length || 0})
        </button>

        <button
          type="button"
          className={`webcare-tab-link ${activeSubTab === 'scripts' ? 'is-active' : ''}`}
          onClick={() => handleSubTabSwitch('scripts')}
          style={{ cursor: 'pointer' }}
        >
          <Terminal size={15} /> Client JS &amp; Hostname Drift ({scriptData?.open_alerts_count || 0})
        </button>
      </div>

      {/* =========================================================================
          SUB-TAB 1: DROP-INS & SBOM LEDGER
         ========================================================================= */}
      {activeSubTab === 'sbom' && (
        <div className="webcare-waf-table-card" style={{ padding: '0', overflow: 'hidden' }}>
          {/* Toolbar */}
          <div className="webcare-waf-toolbar-card" style={{
            padding: '16px 20px',
            borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '12px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>Filter Type:</span>
              {(['all', 'dropin', 'mu', 'ini', 'autoloader'] as const).map((cat) => (
                <button
                  key={cat}
                  type="button"
                  onClick={() => setSbomFilter(cat)}
                  style={{
                    padding: '4px 10px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    border: '1px solid',
                    background: sbomFilter === cat ? '#4f46e5' : 'transparent',
                    color: sbomFilter === cat ? '#ffffff' : 'var(--webcare-text-muted, #64748b)',
                    borderColor: sbomFilter === cat ? '#4f46e5' : 'var(--webcare-border-form, #cbd5e1)'
                  }}
                >
                  {cat.toUpperCase()}
                </button>
              ))}
            </div>

            <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
              Showing {filteredItems.length} runtime anchor definitions
            </div>
          </div>

          {/* Ledger Table */}
          <div style={{ overflowX: 'auto' }}>
            <table className="webcare-waf-logs-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12.5px' }}>
              <thead>
                <tr style={{ background: 'var(--webcare-bg-surface, #f8fafc)', borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)', textAlign: 'left' }}>
                  <th style={{ padding: '12px 16px' }}>Anchor Name / Type</th>
                  <th style={{ padding: '12px 16px' }}>Relative Path</th>
                  <th style={{ padding: '12px 16px' }}>Cryptographic Hash (SHA-256)</th>
                  <th style={{ padding: '12px 16px' }}>Status &amp; Risk</th>
                  <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredItems.map((item) => {
                  const isQuarantining = quarantiningId === item.id;
                  const isClean = item.risk_level === 'none';
                  const isCritical = item.risk_level === 'critical';
                  const isHigh = item.risk_level === 'high';

                  return (
                    <tr
                      key={item.id}
                      style={{
                        borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)',
                        background: isCritical ? 'rgba(239, 68, 68, 0.04)' : undefined
                      }}
                    >
                      {/* Name / Type */}
                      <td style={{ padding: '12px 16px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span
                            style={{
                              fontSize: '10px',
                              fontWeight: 700,
                              textTransform: 'uppercase',
                              padding: '2px 6px',
                              borderRadius: '4px',
                              background: item.type === 'dropin'
                                ? 'var(--webcare-status-info-soft, rgba(99, 102, 241, 0.12))'
                                : item.type === 'mu-plugin'
                                ? 'var(--webcare-status-purple-soft, rgba(168, 85, 247, 0.12))'
                                : item.type === 'custom_dropin'
                                ? 'var(--webcare-status-critical-soft, rgba(239, 68, 68, 0.12))'
                                : item.type === 'ini_directive'
                                ? 'var(--webcare-status-cyan-soft, rgba(6, 182, 212, 0.12))'
                                : 'var(--webcare-status-muted-soft, rgba(148, 163, 184, 0.12))',
                              color: item.type === 'dropin'
                                ? 'var(--webcare-status-info, #6366f1)'
                                : item.type === 'mu-plugin'
                                ? 'var(--webcare-status-purple, #c084fc)'
                                : item.type === 'custom_dropin'
                                ? 'var(--webcare-status-critical, #f87171)'
                                : item.type === 'ini_directive'
                                ? 'var(--webcare-status-cyan, #38bdf8)'
                                : 'var(--webcare-text-secondary, #cbd5e1)',
                              border: `1px solid ${
                                item.type === 'dropin'
                                  ? 'var(--webcare-status-info-border, rgba(99, 102, 241, 0.3))'
                                  : item.type === 'mu-plugin'
                                  ? 'var(--webcare-status-purple-border, rgba(168, 85, 247, 0.3))'
                                  : item.type === 'custom_dropin'
                                  ? 'var(--webcare-status-critical-border, rgba(239, 68, 68, 0.3))'
                                  : item.type === 'ini_directive'
                                  ? 'var(--webcare-status-cyan-border, rgba(6, 182, 212, 0.3))'
                                  : 'var(--webcare-border-std, rgba(255, 255, 255, 0.1))'
                              }`
                            }}
                          >
                            {item.type === 'ini_directive' ? 'INI' : item.type}
                          </span>
                          <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>{item.name}</strong>
                        </div>
                        {item.description && (
                          <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
                            {item.description}
                          </div>
                        )}
                      </td>

                      {/* Path */}
                      <td style={{ padding: '12px 16px', fontFamily: 'monospace', color: 'var(--webcare-accent-code, #0284c7)' }}>
                        {item.rel_path}
                      </td>

                      {/* Hash */}
                      <td style={{ padding: '12px 16px' }}>
                        {item.exists && item.sha256 ? (
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <code style={{ fontSize: '11px', background: 'var(--webcare-bg-surface, #f1f5f9)', padding: '2px 6px', borderRadius: '4px' }}>
                              {item.sha256.substring(0, 16)}...
                            </code>
                            <button
                              type="button"
                              onClick={() => copyToClipboard(item.sha256, item.id)}
                              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '2px', color: copiedHash === item.id ? '#10b981' : '#64748b' }}
                              title="Copy full SHA-256 hash"
                            >
                              {copiedHash === item.id ? <Check size={13} /> : <Copy size={13} />}
                            </button>
                          </div>
                        ) : (
                          <span style={{ color: 'var(--webcare-text-muted, #94a3b8)', fontStyle: 'italic', fontSize: '11px' }}>
                            {item.exists === false ? 'Inactive (File Not Present)' : 'N/A (Runtime Directive)'}
                          </span>
                        )}
                      </td>

                      {/* Status / Risk */}
                      <td style={{ padding: '12px 16px' }}>
                        {item.exists === false ? (
                          <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #94a3b8)', fontWeight: 600 }}>Unused</span>
                        ) : item.is_trusted ? (
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            color: 'var(--webcare-status-clean, #34d399)',
                            background: 'var(--webcare-status-clean-soft, rgba(16, 185, 129, 0.16))',
                            border: '1px solid var(--webcare-status-clean-border, rgba(16, 185, 129, 0.4))',
                            padding: '2px 8px',
                            borderRadius: '999px',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px'
                          }}>
                            <CheckCircle2 size={11} /> {item.label || 'Clean Verified (Security Tool)'}
                          </span>
                        ) : isCritical ? (
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            color: 'var(--webcare-status-critical, #f87171)',
                            background: 'var(--webcare-status-critical-soft, rgba(239, 68, 68, 0.16))',
                            border: '1px solid var(--webcare-status-critical-border, rgba(239, 68, 68, 0.4))',
                            padding: '2px 8px',
                            borderRadius: '999px',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px'
                          }}>
                            <AlertTriangle size={11} /> Critical Threat
                          </span>
                        ) : isHigh ? (
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            color: 'var(--webcare-status-high, #fb923c)',
                            background: 'var(--webcare-status-high-soft, rgba(249, 115, 22, 0.16))',
                            border: '1px solid var(--webcare-status-high-border, rgba(249, 115, 22, 0.4))',
                            padding: '2px 8px',
                            borderRadius: '999px',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px'
                          }}>
                            <AlertCircle size={11} /> Non-Standard Anchor
                          </span>
                        ) : (
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            color: 'var(--webcare-status-clean, #34d399)',
                            background: 'var(--webcare-status-clean-soft, rgba(16, 185, 129, 0.16))',
                            border: '1px solid var(--webcare-status-clean-border, rgba(16, 185, 129, 0.4))',
                            padding: '2px 8px',
                            borderRadius: '999px',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px'
                          }}>
                            <CheckCircle2 size={11} /> Clean Verified
                          </span>
                        )}
                        {item.reasons && item.reasons.length > 0 && (
                          <div style={{
                            fontSize: '10.5px',
                            color: (item.is_trusted || item.risk_level === 'none') ? 'var(--webcare-text-muted, #64748b)' : 'var(--webcare-status-critical, #f87171)',
                            marginTop: '3px'
                          }}>
                            {item.reasons[0]}
                          </div>
                        )}
                      </td>

                      {/* Actions */}
                      <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                        {item.is_trusted ? (
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 600,
                            color: 'var(--webcare-status-clean, #059669)',
                            background: 'var(--webcare-status-clean-soft, rgba(16, 185, 129, 0.12))',
                            padding: '3px 8px',
                            borderRadius: '4px'
                          }}>
                            Official Tool
                          </span>
                        ) : item.exists && (item.is_custom || isCritical || isHigh) ? (
                          <button
                            type="button"
                            className="webcare-btn"
                            onClick={() => handleQuarantine(item.id, item.name)}
                            disabled={isQuarantining}
                            style={{
                              background: '#fef2f2',
                              color: '#dc2626',
                              border: '1px solid #fca5a5',
                              padding: '4px 10px',
                              borderRadius: '6px',
                              fontSize: '11px',
                              fontWeight: 600,
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '4px'
                            }}
                            title="Quarantine this file to WebCare Vault"
                          >
                            {isQuarantining ? <Loader2 size={11} className="webcare-spin-icon" /> : <Trash2 size={11} />}
                            <span>{isQuarantining ? 'Isolating...' : 'Quarantine'}</span>
                          </button>
                        ) : (
                          <span style={{ fontSize: '11px', color: '#94a3b8' }}>Standard</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* =========================================================================
          SUB-TAB 2: UPDATE GATEKEEPER DELTA AUDITS
         ========================================================================= */}
      {activeSubTab === 'gatekeeper' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Controls Bar */}
          <div className="webcare-firewall-card" style={{ padding: '18px 24px' }}>
            <h3 style={{ margin: '0 0 12px 0', fontSize: '15px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
              Gatekeeper Enforcement Controls
            </h3>
            <div style={{ display: 'flex', alignItems: 'center', gap: '24px', flexWrap: 'wrap' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', margin: 0 }}>
                <input
                  type="checkbox"
                  checked={!!gkData.settings.enabled}
                  onChange={(e) => handleUpdateGkSetting('enabled', e.target.checked)}
                  style={{ accentColor: '#4f46e5' }}
                />
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  Enable Update Gatekeeper Intercept
                </span>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', margin: 0 }}>
                <input
                  type="checkbox"
                  checked={!!gkData.settings.block_critical_threats}
                  onChange={(e) => handleUpdateGkSetting('block_critical_threats', e.target.checked)}
                  style={{ accentColor: '#dc2626' }}
                />
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  Block Critical Threats Automatically
                </span>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', margin: 0 }}>
                <input
                  type="checkbox"
                  checked={!!gkData.settings.auto_snapshot_updates}
                  onChange={(e) => handleUpdateGkSetting('auto_snapshot_updates', e.target.checked)}
                  style={{ accentColor: '#0284c7' }}
                />
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  Stash Pre-Update Rollback Snapshots in Vault
                </span>
              </label>
            </div>
          </div>

          {/* Audit Trail List */}
          <div className="webcare-waf-table-card" style={{ padding: '0', overflow: 'hidden' }}>
            <div className="webcare-waf-toolbar-card" style={{ padding: '14px 20px', borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
              <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                Intercepted Update &amp; Installation Ledger
              </h4>
              {gkData.logs.length > 0 && (
                <button
                  type="button"
                  className="webcare-btn webcare-btn-secondary"
                  onClick={handleClearGatekeeperLogs}
                  style={{
                    fontSize: '11.5px',
                    padding: '4px 10px',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '5px'
                  }}
                >
                  <Trash2 size={12} />
                  <span>Clear Ledger History</span>
                </button>
              )}
            </div>

            {gkData.logs.length === 0 ? (
              <div style={{ padding: '40px', textAlign: 'center', color: 'var(--webcare-text-muted, #64748b)' }}>
                <ShieldCheck size={36} color="#10b981" style={{ margin: '0 auto 10px auto' }} />
                <div style={{ fontWeight: 600, fontSize: '14px' }}>No Intercepted Updates Yet</div>
                <p style={{ margin: '4px 0 0 0', fontSize: '12px' }}>
                  The gatekeeper silently audits all incoming plugin ZIP installations and updates. When an update occurs, differential file deltas will be recorded here.
                </p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                {gkData.logs.map((log) => {
                  const isBlocked = log.status === 'blocked';
                  const isRollingBack = rollingBackId === log.snapshot_id;

                  return (
                    <div
                      key={log.id}
                      style={{
                        padding: '16px 20px',
                        borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'flex-start',
                        flexWrap: 'wrap',
                        gap: '12px',
                        background: isBlocked ? 'rgba(239, 68, 68, 0.04)' : undefined
                      }}
                    >
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            textTransform: 'uppercase',
                            padding: '2px 8px',
                            borderRadius: '4px',
                            background: isBlocked ? '#fef2f2' : '#ecfdf5',
                            color: isBlocked ? '#b91c1c' : '#047857',
                            border: `1px solid ${isBlocked ? '#fca5a5' : '#a7f3d0'}`
                          }}>
                            {log.status.toUpperCase()}
                          </span>
                          <strong style={{ fontSize: '14px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                            {log.plugin_slug}
                          </strong>
                          <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                            ({log.action_type.toUpperCase()}) &bull; {log.datetime}
                          </span>
                        </div>

                        {/* Delta stats */}
                        {log.delta && (
                          <div style={{ display: 'flex', gap: '12px', marginTop: '6px', fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                            <span style={{ color: '#047857', fontWeight: 600 }}>+{log.delta.added_count} Added</span>
                            <span style={{ color: '#b45309', fontWeight: 600 }}>~{log.delta.modified_count} Modified</span>
                            <span style={{ color: '#64748b' }}>-{log.delta.deleted_count} Removed</span>
                            <span>&bull; Risk Score: <strong>{log.risk_score}/100</strong> ({log.risk_level.toUpperCase()})</span>
                          </div>
                        )}

                        {/* Findings preview */}
                        {log.findings && log.findings.length > 0 && (
                          <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                            {log.findings.map((f: any, idx: number) => (
                              <div key={idx} style={{ fontSize: '11.5px', color: '#b91c1c', display: 'flex', alignItems: 'center', gap: '5px' }}>
                                <AlertTriangle size={12} />
                                <span><strong>{f.title}</strong> ({f.file})</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Snapshot Rollback button */}
                      {log.snapshot_id && (
                        <button
                          type="button"
                          className="webcare-btn"
                          onClick={() => handleRollback(log.snapshot_id, log.plugin_slug)}
                          disabled={isRollingBack}
                          style={{
                            background: '#eff6ff',
                            color: '#1d4ed8',
                            border: '1px solid #bfdbfe',
                            padding: '6px 12px',
                            borderRadius: '6px',
                            fontSize: '12px',
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '5px'
                          }}
                          title="Restore pre-update snapshot"
                        >
                          {isRollingBack ? <Loader2 size={12} className="webcare-spin-icon" /> : <RotateCcw size={12} />}
                          <span>{isRollingBack ? 'Restoring...' : '1-Click Rollback'}</span>
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* =========================================================================
          SUB-TAB 3: SHIFT-LEFT PLUGIN RISK ANALYZER
         ========================================================================= */}
      {activeSubTab === 'advisor' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div className="webcare-firewall-card" style={{ padding: '24px' }}>
            <h3 style={{ margin: '0 0 6px 0', fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
              Static Pre-Activation Risk Advisor
            </h3>
            <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: 'var(--webcare-text-muted, #64748b)' }}>
              Perform an instant Shift-Left static security audit on any installed plugin folder to evaluate command execution, obfuscation, and raw network sockets.
            </p>

            <div style={{ display: 'flex', gap: '10px', maxWidth: '600px' }}>
              <input
                type="text"
                className="webcare-input"
                placeholder="Enter plugin slug (e.g. contact-form-7, woocommerce)"
                value={pluginSlugToScan}
                onChange={(e) => setPluginSlugToScan(e.target.value)}
                style={{ flex: 1 }}
              />
              <button
                type="button"
                className="webcare-btn"
                onClick={handleAnalyzePlugin}
                disabled={analyzingSlug}
                style={{
                  background: '#4f46e5',
                  color: '#ffffff',
                  border: 'none',
                  padding: '8px 18px',
                  borderRadius: '8px',
                  fontWeight: 600,
                  fontSize: '13px',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
              >
                {analyzingSlug ? <Loader2 size={14} className="webcare-spin-icon" /> : <Play size={14} />}
                <span>{analyzingSlug ? 'Auditing...' : 'Run Audit'}</span>
              </button>
            </div>
          </div>

          {/* Analysis Report */}
          {analysisReport && (
            <div className="webcare-firewall-card" style={{ padding: '24px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)', paddingBottom: '16px' }}>
                <div>
                  <h4 style={{ margin: 0, fontSize: '17px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)' }}>
                    Risk Evaluation: <code>{analysisReport.slug}</code>
                  </h4>
                  <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
                    Scanned {analysisReport.stats?.files_scanned} files &bull; Found {analysisReport.findings?.length || 0} security indicators
                  </div>
                </div>

                <div style={{
                  padding: '6px 14px',
                  borderRadius: '8px',
                  fontSize: '14px',
                  fontWeight: 800,
                  background: analysisReport.score >= 60 ? '#fef2f2' : analysisReport.score >= 35 ? '#fff7ed' : '#ecfdf5',
                  color: analysisReport.score >= 60 ? '#b91c1c' : analysisReport.score >= 35 ? '#c2410c' : '#047857',
                  border: `1px solid ${analysisReport.score >= 60 ? '#fca5a5' : analysisReport.score >= 35 ? '#fed7aa' : '#a7f3d0'}`
                }}>
                  Risk Score: {analysisReport.score} / 100 ({analysisReport.level.toUpperCase()})
                </div>
              </div>

              {/* Capabilities Strip */}
              <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', margin: '16px 0' }}>
                <span style={{ fontSize: '11px', fontWeight: 600, padding: '3px 8px', borderRadius: '4px', background: analysisReport.capabilities?.has_exec ? '#fee2e2' : '#f1f5f9', color: analysisReport.capabilities?.has_exec ? '#b91c1c' : '#64748b' }}>
                  OS Shell Exec: {analysisReport.capabilities?.has_exec ? 'YES' : 'NO'}
                </span>
                <span style={{ fontSize: '11px', fontWeight: 600, padding: '3px 8px', borderRadius: '4px', background: analysisReport.capabilities?.has_obfuscation ? '#fee2e2' : '#f1f5f9', color: analysisReport.capabilities?.has_obfuscation ? '#b91c1c' : '#64748b' }}>
                  Obfuscation / Eval: {analysisReport.capabilities?.has_obfuscation ? 'YES' : 'NO'}
                </span>
                <span style={{ fontSize: '11px', fontWeight: 600, padding: '3px 8px', borderRadius: '4px', background: analysisReport.capabilities?.has_network ? '#ffedd5' : '#f1f5f9', color: analysisReport.capabilities?.has_network ? '#c2410c' : '#64748b' }}>
                  Raw IP Outbound: {analysisReport.capabilities?.has_network ? 'YES' : 'NO'}
                </span>
                <span style={{ fontSize: '11px', fontWeight: 600, padding: '3px 8px', borderRadius: '4px', background: analysisReport.capabilities?.has_persistence ? '#fee2e2' : '#f1f5f9', color: analysisReport.capabilities?.has_persistence ? '#b91c1c' : '#64748b' }}>
                  Drop-In Injection: {analysisReport.capabilities?.has_persistence ? 'YES' : 'NO'}
                </span>
              </div>

              {/* Findings List */}
              {analysisReport.findings && analysisReport.findings.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '14px' }}>
                  {analysisReport.findings.map((f: any, i: number) => (
                    <div
                      key={i}
                      style={{
                        padding: '12px 16px',
                        borderRadius: '8px',
                        background: 'var(--webcare-bg-surface, #f8fafc)',
                        border: '1px solid var(--webcare-border-std, #e2e8f0)',
                        borderLeft: `4px solid ${f.severity === 'critical' ? '#dc2626' : '#ea580c'}`
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <strong style={{ fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                          {f.title}
                        </strong>
                        <span style={{ fontSize: '11px', fontWeight: 700, color: f.severity === 'critical' ? '#dc2626' : '#ea580c' }}>
                          +{f.weight} PTS
                        </span>
                      </div>
                      <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', margin: '4px 0' }}>
                        {f.description}
                      </div>
                      <div style={{ fontSize: '11px', fontFamily: 'monospace', color: '#0284c7' }}>
                        {f.file} {f.line ? `(Line #${f.line})` : ''}
                      </div>
                      {f.snippet && (
                        <pre style={{
                          background: 'rgba(0,0,0,0.03)',
                          padding: '6px 10px',
                          borderRadius: '4px',
                          fontSize: '11px',
                          margin: '6px 0 0 0',
                          overflowX: 'auto',
                          color: '#b91c1c'
                        }}>
                          {f.snippet}
                        </pre>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ padding: '24px', textAlign: 'center', color: '#059669' }}>
                  <CheckCircle2 size={32} style={{ margin: '0 auto 8px auto' }} />
                  <div style={{ fontWeight: 700, fontSize: '14px' }}>Clean Static Audit</div>
                  <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: '#64748b' }}>
                    No obfuscated execution patterns, system commands, or unauthorized drop-in injections identified.
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* =========================================================================
          SUB-TAB 4: DEPENDENCY LOCKFILES AUDITOR
         ========================================================================= */}
      {activeSubTab === 'lockfiles' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Main Card */}
          <div className="webcare-waf-table-card" style={{ padding: '0', overflow: 'hidden' }}>
            <div className="webcare-waf-toolbar-card" style={{
              padding: '16px 20px',
              borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '12px'
            }}>
              <div>
                <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  Dependency Lockfiles &amp; Offline CVE Auditor
                </h4>
                <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  Auditing <code>composer.lock</code> and <code>package-lock.json</code> manifests bundled within plugins and active themes against known security advisories.
                </p>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <button
                  type="button"
                  className="webcare-firewall-rule-save-btn"
                  onClick={() => fetchLockfiles(true)}
                  disabled={scanningLockfiles || loadingLockfiles}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '12px',
                    padding: '8px 14px',
                    cursor: scanningLockfiles ? 'not-allowed' : 'pointer'
                  }}
                >
                  {scanningLockfiles ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
                  <span>{scanningLockfiles ? 'Auditing Lockfiles...' : 'Run Lockfile Audit'}</span>
                </button>
              </div>
            </div>

            {/* Lockfile KPI Strip */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '12px',
              padding: '16px 20px',
              background: 'var(--webcare-bg-surface, #f8fafc)',
              borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)'
            }}>
              <div style={{ padding: '10px 14px', background: 'var(--webcare-bg-panel, #ffffff)', borderRadius: '8px', border: '1px solid var(--webcare-border-std, #e2e8f0)' }}>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>
                  Discovered Lockfiles
                </div>
                <div style={{ fontSize: '18px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)', margin: '4px 0' }}>
                  {lockfileData?.total_lockfiles ?? 0}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  composer.lock &amp; package-lock
                </div>
              </div>

              <div style={{ padding: '10px 14px', background: 'var(--webcare-bg-panel, #ffffff)', borderRadius: '8px', border: '1px solid var(--webcare-border-std, #e2e8f0)' }}>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>
                  Packages Checked
                </div>
                <div style={{ fontSize: '18px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)', margin: '4px 0' }}>
                  {lockfileData?.total_packages ?? 0}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  Resolved pinned dependencies
                </div>
              </div>

              <div style={{ padding: '10px 14px', background: 'var(--webcare-bg-panel, #ffffff)', borderRadius: '8px', border: '1px solid var(--webcare-border-std, #e2e8f0)' }}>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>
                  CVE Advisories
                </div>
                <div style={{
                  fontSize: '18px',
                  fontWeight: 800,
                  color: (lockfileData?.vulnerabilities?.length || 0) > 0 ? '#dc2626' : '#059669',
                  margin: '4px 0'
                }}>
                  {lockfileData?.vulnerabilities?.length ?? 0}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  {lockfileData?.summary?.critical || 0} Critical, {lockfileData?.summary?.high || 0} High
                </div>
              </div>

              <div style={{ padding: '10px 14px', background: 'var(--webcare-bg-panel, #ffffff)', borderRadius: '8px', border: '1px solid var(--webcare-border-std, #e2e8f0)' }}>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>
                  Audit Posture
                </div>
                <div style={{
                  fontSize: '14px',
                  fontWeight: 800,
                  color: lockfileData?.summary?.clean ? '#059669' : '#ea580c',
                  margin: '6px 0',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}>
                  {lockfileData?.summary?.clean ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
                  <span>{lockfileData?.summary?.clean ? 'CLEAN & PINNED' : 'RISK DETECTED'}</span>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  {lockfileData?.scanned_at ? `Audited: ${lockfileData.scanned_at}` : 'Awaiting manual trigger'}
                </div>
              </div>
            </div>

            {/* Vulnerabilities Section */}
            {lockfileData?.vulnerabilities && lockfileData.vulnerabilities.length > 0 ? (
              <div style={{ padding: '20px' }}>
                <div style={{ marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <ShieldAlert size={18} color="#dc2626" />
                  <h5 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                    Active CVE Advisories in Bundled Dependencies ({lockfileData.vulnerabilities.length})
                  </h5>
                </div>
                <div style={{ overflowX: 'auto' }}>
                  <table className="webcare-waf-logs-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                    <thead>
                      <tr style={{ background: 'var(--webcare-bg-surface, #f8fafc)', borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)', textAlign: 'left' }}>
                        <th style={{ padding: '10px 14px' }}>Ecosystem &amp; Package</th>
                        <th style={{ padding: '10px 14px' }}>Installed Version</th>
                        <th style={{ padding: '10px 14px' }}>Patched In</th>
                        <th style={{ padding: '10px 14px' }}>Advisory / CVE</th>
                        <th style={{ padding: '10px 14px' }}>Severity</th>
                        <th style={{ padding: '10px 14px' }}>Lockfile Location</th>
                      </tr>
                    </thead>
                    <tbody>
                      {lockfileData.vulnerabilities.map((v: any, idx: number) => (
                        <tr key={idx} style={{ borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)', background: v.severity === 'critical' ? 'rgba(239, 68, 68, 0.05)' : undefined }}>
                          <td style={{ padding: '10px 14px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <span style={{
                                fontSize: '10px',
                                fontWeight: 700,
                                padding: '2px 5px',
                                borderRadius: '4px',
                                background: v.ecosystem === 'composer' ? 'rgba(79, 70, 229, 0.12)' : 'rgba(234, 88, 12, 0.12)',
                                color: v.ecosystem === 'composer' ? '#4f46e5' : '#ea580c'
                              }}>
                                {v.ecosystem ? v.ecosystem.toUpperCase() : 'PKG'}
                              </span>
                              <strong style={{ fontFamily: 'monospace', color: 'var(--webcare-text-primary, #0f172a)' }}>{v.package}</strong>
                            </div>
                            <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                              {v.description}
                            </div>
                          </td>
                          <td style={{ padding: '10px 14px', fontFamily: 'monospace', color: '#dc2626' }}>
                            {v.installed}
                          </td>
                          <td style={{ padding: '10px 14px', fontFamily: 'monospace', color: '#059669', fontWeight: 600 }}>
                            {v.fixed_in || 'N/A'}
                          </td>
                          <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontWeight: 600 }}>
                            <span style={{ color: '#0284c7' }}>{v.cve}</span>
                          </td>
                          <td style={{ padding: '10px 14px' }}>
                            <span style={{
                              padding: '2px 8px',
                              borderRadius: '4px',
                              fontSize: '11px',
                              fontWeight: 700,
                              textTransform: 'uppercase',
                              background: v.severity === 'critical' ? '#fee2e2' : v.severity === 'high' ? '#ffedd5' : '#fef3c7',
                              color: v.severity === 'critical' ? '#b91c1c' : v.severity === 'high' ? '#c2410c' : '#b45309'
                            }}>
                              {v.severity}
                            </span>
                          </td>
                          <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                            {v.lockfile}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div style={{ padding: '24px 20px', textAlign: 'center', color: '#059669' }}>
                <CheckCircle2 size={32} style={{ margin: '0 auto 8px auto' }} />
                <div style={{ fontWeight: 700, fontSize: '14px' }}>No Vulnerable Dependencies Identified</div>
                <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  All audited composer.lock and package-lock.json packages match clean advisory profiles.
                </p>
              </div>
            )}

            {/* Lockfile Anomalies Section */}
            {lockfileData?.anomalies && lockfileData.anomalies.length > 0 && (
              <div style={{ padding: '0 20px 20px 20px' }}>
                <div style={{ marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <AlertTriangle size={18} color="#ea580c" />
                  <h5 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                    Manifest Anomalies &amp; Insecure Transports ({lockfileData.anomalies.length})
                  </h5>
                </div>
                <div style={{ overflowX: 'auto' }}>
                  <table className="webcare-waf-logs-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                    <thead>
                      <tr style={{ background: 'var(--webcare-bg-surface, #f8fafc)', borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)', textAlign: 'left' }}>
                        <th style={{ padding: '10px 14px' }}>Anomaly Type</th>
                        <th style={{ padding: '10px 14px' }}>Package</th>
                        <th style={{ padding: '10px 14px' }}>Description</th>
                        <th style={{ padding: '10px 14px' }}>Lockfile</th>
                      </tr>
                    </thead>
                    <tbody>
                      {lockfileData.anomalies.map((a: any, idx: number) => (
                        <tr key={idx} style={{ borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)' }}>
                          <td style={{ padding: '10px 14px' }}>
                            <span style={{
                              padding: '2px 8px',
                              borderRadius: '4px',
                              fontSize: '11px',
                              fontWeight: 700,
                              background: '#fff7ed',
                              color: '#c2410c'
                            }}>
                              {a.type}
                            </span>
                          </td>
                          <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontWeight: 600 }}>
                            {a.package}
                          </td>
                          <td style={{ padding: '10px 14px', color: 'var(--webcare-text-muted, #64748b)' }}>
                            {a.description}
                          </td>
                          <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontSize: '11px', color: '#0284c7' }}>
                            {a.lockfile}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Discovered Manifests Table */}
            {lockfileData?.lockfiles && lockfileData.lockfiles.length > 0 && (
              <div style={{ padding: '0 20px 20px 20px' }}>
                <div style={{ marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <FileCode size={18} color="#4f46e5" />
                  <h5 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                    Discovered Lockfile Manifests ({lockfileData.lockfiles.length})
                  </h5>
                </div>
                <div style={{ overflowX: 'auto' }}>
                  <table className="webcare-waf-logs-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                    <thead>
                      <tr style={{ background: 'var(--webcare-bg-surface, #f8fafc)', borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)', textAlign: 'left' }}>
                        <th style={{ padding: '10px 14px' }}>Lockfile Path</th>
                        <th style={{ padding: '10px 14px' }}>Ecosystem</th>
                        <th style={{ padding: '10px 14px' }}>Plugin / Theme</th>
                        <th style={{ padding: '10px 14px' }}>Resolved Packages</th>
                        <th style={{ padding: '10px 14px' }}>Advisories</th>
                        <th style={{ padding: '10px 14px' }}>File Size</th>
                      </tr>
                    </thead>
                    <tbody>
                      {lockfileData.lockfiles.map((l: any, idx: number) => (
                        <tr key={idx} style={{ borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)' }}>
                          <td style={{ padding: '10px 14px', fontFamily: 'monospace', color: '#0284c7' }}>
                            {l.rel_path}
                          </td>
                          <td style={{ padding: '10px 14px' }}>
                            <span style={{
                              padding: '2px 8px',
                              borderRadius: '4px',
                              fontSize: '11px',
                              fontWeight: 700,
                              background: l.ecosystem === 'composer' ? '#eef2ff' : '#fff7ed',
                              color: l.ecosystem === 'composer' ? '#4f46e5' : '#ea580c'
                            }}>
                              {l.ecosystem.toUpperCase()}
                            </span>
                          </td>
                          <td style={{ padding: '10px 14px', fontWeight: 600 }}>
                            {l.plugin_slug || 'Root / Custom'}
                          </td>
                          <td style={{ padding: '10px 14px' }}>
                            {l.total_packages} packages
                          </td>
                          <td style={{ padding: '10px 14px' }}>
                            <span style={{
                              padding: '2px 8px',
                              borderRadius: '4px',
                              fontSize: '11px',
                              fontWeight: 700,
                              background: l.vulnerabilities > 0 ? '#fee2e2' : '#ecfdf5',
                              color: l.vulnerabilities > 0 ? '#dc2626' : '#059669'
                            }}>
                              {l.vulnerabilities > 0 ? `${l.vulnerabilities} CVEs` : 'Clean'}
                            </span>
                          </td>
                          <td style={{ padding: '10px 14px', color: 'var(--webcare-text-muted, #64748b)' }}>
                            {Math.round(l.filesize / 1024)} KB
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* =========================================================================
          SUB-TAB 5: CLIENT JS & HOSTNAME DRIFT MONITOR
         ========================================================================= */}
      {activeSubTab === 'scripts' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Main Card */}
          <div className="webcare-waf-table-card" style={{ padding: '0', overflow: 'hidden' }}>
            <div className="webcare-waf-toolbar-card" style={{
              padding: '16px 20px',
              borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '12px'
            }}>
              <div>
                <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  Client-Side JS &amp; Third-Party Hostname Drift Monitor
                </h4>
                <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  Passive telemetry baseline monitoring enqueued frontend scripts to catch Magecart payment skimmers, unauthorized CDN drift, and data exfiltration scripts.
                </p>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <button
                  type="button"
                  className="webcare-firewall-rule-save-btn"
                  onClick={handleCalibrateScripts}
                  disabled={calibratingScripts}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '12px',
                    padding: '8px 14px',
                    cursor: calibratingScripts ? 'not-allowed' : 'pointer'
                  }}
                >
                  {calibratingScripts ? <Loader2 size={14} className="animate-spin" /> : <CheckCircle2 size={14} />}
                  <span>{calibratingScripts ? 'Calibrating...' : 'Calibrate Baseline'}</span>
                </button>

                <button
                  type="button"
                  onClick={fetchScripts}
                  disabled={loadingScripts}
                  className="webcare-btn-micro"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '12px',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    border: '1px solid var(--webcare-border-form, #cbd5e1)',
                    background: 'var(--webcare-bg-panel, #ffffff)',
                    color: 'var(--webcare-text-primary, #0f172a)',
                    cursor: 'pointer'
                  }}
                >
                  <RefreshCw size={14} className={loadingScripts ? 'animate-spin' : ''} />
                  <span>Refresh</span>
                </button>
              </div>
            </div>

            {/* Script KPI Strip */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '12px',
              padding: '16px 20px',
              background: 'var(--webcare-bg-surface, #f8fafc)',
              borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)'
            }}>
              <div style={{ padding: '10px 14px', background: 'var(--webcare-bg-panel, #ffffff)', borderRadius: '8px', border: '1px solid var(--webcare-border-std, #e2e8f0)' }}>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>
                  Enqueued Scripts
                </div>
                <div style={{ fontSize: '18px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)', margin: '4px 0' }}>
                  {scriptData?.total_scripts ?? 0}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  Total monitored handles
                </div>
              </div>

              <div style={{ padding: '10px 14px', background: 'var(--webcare-bg-panel, #ffffff)', borderRadius: '8px', border: '1px solid var(--webcare-border-std, #e2e8f0)' }}>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>
                  Third-Party Hostnames
                </div>
                <div style={{ fontSize: '18px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)', margin: '4px 0' }}>
                  {scriptData?.total_domains ?? 0}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  External CDN &amp; API hosts
                </div>
              </div>

              <div style={{ padding: '10px 14px', background: 'var(--webcare-bg-panel, #ffffff)', borderRadius: '8px', border: '1px solid var(--webcare-border-std, #e2e8f0)' }}>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>
                  Open Drift Alerts
                </div>
                <div style={{
                  fontSize: '18px',
                  fontWeight: 800,
                  color: (scriptData?.open_alerts_count || 0) > 0 ? '#dc2626' : '#059669',
                  margin: '4px 0'
                }}>
                  {scriptData?.open_alerts_count ?? 0}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  {(scriptData?.open_alerts_count || 0) > 0 ? 'Uncalibrated hosts active' : 'Zero unapproved domains'}
                </div>
              </div>

              <div style={{ padding: '10px 14px', background: 'var(--webcare-bg-panel, #ffffff)', borderRadius: '8px', border: '1px solid var(--webcare-border-std, #e2e8f0)' }}>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>
                  Baseline Status
                </div>
                <div style={{
                  fontSize: '14px',
                  fontWeight: 800,
                  color: scriptData?.is_calibrated ? '#059669' : '#d97706',
                  margin: '6px 0',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}>
                  {scriptData?.is_calibrated ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
                  <span>{scriptData?.is_calibrated ? 'Calibrated Baseline' : 'Uncalibrated'}</span>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  {scriptData?.is_calibrated ? 'Strict drift alerts active' : 'Click "Calibrate Baseline" above'}
                </div>
              </div>
            </div>

            {/* Drift Alerts Banner */}
            {scriptData?.alerts && scriptData.alerts.filter((a: any) => a.status === 'open').length > 0 && (
              <div style={{
                margin: '20px',
                padding: '16px 20px',
                borderRadius: '8px',
                background: '#fef2f2',
                border: '1px solid #fecaca',
                borderLeft: '4px solid #dc2626'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                  <AlertTriangle size={20} color="#dc2626" />
                  <strong style={{ fontSize: '14px', color: '#b91c1c' }}>
                    Active Hostname Drift Alerts Detected
                  </strong>
                </div>
                <p style={{ margin: '0 0 12px 0', fontSize: '12px', color: '#7f1d1d' }}>
                  The following third-party script hostnames were enqueued at runtime without being present in your approved baseline. If you did not intentionally add these scripts, inspect your site for Magecart payment skimmers or compromised plugins immediately.
                </p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {scriptData.alerts.filter((a: any) => a.status === 'open').map((alert: any) => (
                    <div
                      key={alert.id}
                      style={{
                        padding: '10px 14px',
                        borderRadius: '6px',
                        background: '#ffffff',
                        border: '1px solid #fecaca',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        flexWrap: 'wrap',
                        gap: '10px'
                      }}
                    >
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{
                            padding: '2px 6px',
                            borderRadius: '4px',
                            fontSize: '10px',
                            fontWeight: 700,
                            textTransform: 'uppercase',
                            background: alert.severity === 'critical' ? '#fee2e2' : '#ffedd5',
                            color: alert.severity === 'critical' ? '#b91c1c' : '#c2410c'
                          }}>
                            {alert.severity}
                          </span>
                          <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: '13px', color: '#0f172a' }}>
                            {alert.host}
                          </span>
                          {alert.is_sensitive && (
                            <span style={{ fontSize: '11px', fontWeight: 600, color: '#dc2626' }}>
                              (Detected on Checkout / Auth Page!)
                            </span>
                          )}
                        </div>
                        <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px' }}>
                          Handle: <code>{alert.handle}</code> &bull; Detected: {alert.detected_at}
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={() => handleDismissScriptAlert(alert.id)}
                        className="webcare-btn-micro"
                        style={{
                          fontSize: '11px',
                          padding: '4px 10px',
                          borderRadius: '4px',
                          border: '1px solid #cbd5e1',
                          background: '#f8fafc',
                          color: '#475569',
                          cursor: 'pointer'
                        }}
                      >
                        Dismiss Alert
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Domains Table */}
            {scriptData?.domains && scriptData.domains.length > 0 && (
              <div style={{ padding: '20px' }}>
                <div style={{ marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <ShieldCheck size={18} color="#4f46e5" />
                  <h5 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                    Third-Party Hostnames &amp; Trust Baseline ({scriptData.domains.length})
                  </h5>
                </div>
                <div style={{ overflowX: 'auto' }}>
                  <table className="webcare-waf-logs-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                    <thead>
                      <tr style={{ background: 'var(--webcare-bg-surface, #f8fafc)', borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)', textAlign: 'left' }}>
                        <th style={{ padding: '10px 14px' }}>External Domain / Host</th>
                        <th style={{ padding: '10px 14px' }}>Monitored Handles</th>
                        <th style={{ padding: '10px 14px' }}>Checkout / Auth Context</th>
                        <th style={{ padding: '10px 14px' }}>Baseline Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scriptData.domains.map((dom: any, idx: number) => (
                        <tr key={idx} style={{ borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)' }}>
                          <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                            {dom.host}
                          </td>
                          <td style={{ padding: '10px 14px' }}>
                            {dom.script_count} script {dom.script_count === 1 ? 'handle' : 'handles'}
                          </td>
                          <td style={{ padding: '10px 14px' }}>
                            {dom.has_sensitive ? (
                              <span style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 700, background: '#fee2e2', color: '#b91c1c' }}>
                                ACTIVE ON CHECKOUT / AUTH
                              </span>
                            ) : (
                              <span style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600, background: '#f1f5f9', color: '#64748b' }}>
                                General Pages Only
                              </span>
                            )}
                          </td>
                          <td style={{ padding: '10px 14px' }}>
                            {dom.is_recognized ? (
                              <span style={{
                                padding: '2px 8px',
                                borderRadius: '4px',
                                fontSize: '11px',
                                fontWeight: 700,
                                background: 'var(--webcare-status-clean-soft, rgba(16, 185, 129, 0.16))',
                                color: 'var(--webcare-status-clean, #059669)',
                                border: '1px solid var(--webcare-status-clean-border, rgba(16, 185, 129, 0.4))',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px'
                              }}>
                                <CheckCircle2 size={11} /> VERIFIED ({dom.provider || 'Official Integration'})
                              </span>
                            ) : dom.is_baseline ? (
                              <span style={{
                                padding: '2px 8px',
                                borderRadius: '4px',
                                fontSize: '11px',
                                fontWeight: 700,
                                background: 'var(--webcare-status-clean-soft, rgba(16, 185, 129, 0.16))',
                                color: 'var(--webcare-status-clean, #059669)',
                                border: '1px solid var(--webcare-status-clean-border, rgba(16, 185, 129, 0.4))'
                              }}>
                                APPROVED BASELINE
                              </span>
                            ) : (
                              <span style={{
                                padding: '2px 8px',
                                borderRadius: '4px',
                                fontSize: '11px',
                                fontWeight: 700,
                                background: 'var(--webcare-status-high-soft, rgba(249, 115, 22, 0.16))',
                                color: 'var(--webcare-status-high, #c2410c)',
                                border: '1px solid var(--webcare-status-high-border, rgba(249, 115, 22, 0.4))'
                              }}>
                                UNCALIBRATED DRIFT
                              </span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Enqueued Scripts Table */}
            {scriptData?.scripts && scriptData.scripts.length > 0 && (
              <div style={{ padding: '0 20px 20px 20px' }}>
                <div style={{ marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Terminal size={18} color="#0284c7" />
                  <h5 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                    Runtime Enqueued Scripts Inventory ({scriptData.scripts.length})
                  </h5>
                </div>
                <div style={{ overflowX: 'auto' }}>
                  <table className="webcare-waf-logs-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                    <thead>
                      <tr style={{ background: 'var(--webcare-bg-surface, #f8fafc)', borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)', textAlign: 'left' }}>
                        <th style={{ padding: '10px 14px' }}>Script Handle</th>
                        <th style={{ padding: '10px 14px' }}>Host</th>
                        <th style={{ padding: '10px 14px' }}>Script Source URL</th>
                        <th style={{ padding: '10px 14px' }}>Sensitive Context</th>
                        <th style={{ padding: '10px 14px' }}>First / Last Seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scriptData.scripts.map((s: any, idx: number) => (
                        <tr key={idx} style={{ borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)' }}>
                          <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                            {s.handle}
                          </td>
                          <td style={{ padding: '10px 14px', fontFamily: 'monospace', color: '#0284c7' }}>
                            {s.host}
                          </td>
                          <td style={{ padding: '10px 14px', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            <a href={s.src} target="_blank" rel="noopener noreferrer" style={{ color: '#4f46e5', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '4px' }}>
                              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{s.src}</span>
                              <ExternalLink size={12} style={{ flexShrink: 0 }} />
                            </a>
                          </td>
                          <td style={{ padding: '10px 14px' }}>
                            {s.is_sensitive ? (
                              <span style={{ padding: '2px 6px', borderRadius: '4px', fontSize: '10px', fontWeight: 700, background: '#fee2e2', color: '#b91c1c' }}>
                                CHECKOUT / AUTH
                              </span>
                            ) : (
                              <span style={{ fontSize: '11px', color: '#64748b' }}>Standard</span>
                            )}
                          </td>
                          <td style={{ padding: '10px 14px', fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                            {s.last_seen || s.first_seen}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
