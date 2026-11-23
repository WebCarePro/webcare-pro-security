import React, { useState, useEffect, useMemo } from 'react';
import {
  Sparkles,
  Shield,
  FileCode,
  Zap,
  Filter,
  RotateCcw,
  Search,
  Eye,
  Check,
  Copy,
  Terminal,
  Activity,
  Layers,
  ArrowUpRight,
  Phone,
  LifeBuoy,
  RefreshCw,
  HardDrive,
  Clock,
  ShieldCheck,
  FileText
} from 'lucide-react';
import { PersistenceSentinelCard } from './components/PersistenceSentinelCard';
import { PersistenceWatchdogCard } from './components/PersistenceWatchdogCard';
import { AttackChainCard } from './components/AttackChainCard';
import { WhitelistManagerTab } from './components/WhitelistManagerTab';
import { BehavioralBaselineCard } from './components/BehavioralBaselineCard';
import { RemediationTransactionsCard } from './components/RemediationTransactionsCard';
import { PluginSelfDefenseCard } from './components/PluginSelfDefenseCard';
import { ThreatCorrelationHierarchyCard } from './components/ThreatCorrelationHierarchyCard';

export type ForensicsSubTab = 'persistence' | 'watchdog' | 'baseline' | 'files' | 'attack_chain' | 'correlation' | 'whitelist' | 'transactions' | 'self_defense';

interface ForensicsPageProps {
  apiRequest: (options: any) => Promise<any>;
  onNavigateToDashboard: () => void;
  onNavigateToSupport?: () => void;
  scannedFiles?: any[];
  initialSubTab?: ForensicsSubTab;
  initialNestedSubTab?: string;
  onSubTabChange?: (sub: ForensicsSubTab, nested?: string) => void;
  onOpenFileViewer?: (issue?: any, directFilePath?: string) => void;
  onRefreshScanData?: () => void;
}

export const FORENSICS_TABS: ForensicsSubTab[] = ['persistence', 'watchdog', 'baseline', 'files', 'attack_chain', 'correlation', 'whitelist', 'transactions', 'self_defense'];

export const ForensicsPage: React.FC<ForensicsPageProps> = ({
  apiRequest,
  onNavigateToDashboard,
  onNavigateToSupport,
  scannedFiles = [],
  initialSubTab = 'persistence',
  initialNestedSubTab,
  onSubTabChange,
  onOpenFileViewer,
  onRefreshScanData,
}) => {
  const normalizeForensicsSection = (raw: string | null): ForensicsSubTab | null => {
    if (!raw) return null;
    if (raw === 'self-defense' || raw === 'self_defense') return 'self_defense';
    if (raw === 'attack-chains' || raw === 'attack_chain') return 'attack_chain';
    if (raw === 'allowlist' || raw === 'whitelist') return 'whitelist';
    if (FORENSICS_TABS.includes(raw as any)) return raw as ForensicsSubTab;
    return null;
  };

  const [activeTab, setActiveTab] = useState<ForensicsSubTab>(() => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const section = normalizeForensicsSection(urlParams.get('section') || urlParams.get('subtab') || urlParams.get('tab'));
      if (section) return section;
    } catch (e) {}
    if (initialSubTab) {
      const normalized = normalizeForensicsSection(initialSubTab);
      if (normalized) return normalized;
    }
    return 'persistence';
  });
  const [fileFilter, setFileFilter] = useState('');
  const [copiedPath, setCopiedPath] = useState<string | null>(null);
  const [localAuditedFiles, setLocalAuditedFiles] = useState<any[]>(scannedFiles);
  const [loadingFiles, setLoadingFiles] = useState(false);

  // Sync with initialSubTab prop if it changes
  useEffect(() => {
    if (initialSubTab && FORENSICS_TABS.includes(initialSubTab)) {
      setActiveTab(initialSubTab);
    }
  }, [initialSubTab]);

  // Popstate listener to switch forensics subtab on browser back/forward navigation
  useEffect(() => {
    const handlePopState = () => {
      try {
        const urlParams = new URLSearchParams(window.location.search);
        const section = normalizeForensicsSection(urlParams.get('section') || urlParams.get('subtab') || urlParams.get('tab'));
        if (section) {
          setActiveTab(section);
          if (onSubTabChange) onSubTabChange(section);
        }
      } catch (e) {}
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, [onSubTabChange]);

  // If scannedFiles is empty, attempt to load them from latest scan files endpoint
  useEffect(() => {
    if (scannedFiles && scannedFiles.length > 0) {
      setLocalAuditedFiles(scannedFiles);
    } else {
      loadAuditedFiles();
    }
  }, [scannedFiles]);

  const loadAuditedFiles = async () => {
    setLoadingFiles(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/scan/latest',
        method: 'GET',
      });
      if (res?.files && Array.isArray(res.files)) {
        setLocalAuditedFiles(res.files);
      }
    } catch (e) {
      console.error('Failed to load audited files for forensics', e);
    } finally {
      setLoadingFiles(false);
    }
  };

  const handleTabChange = (tab: ForensicsSubTab, nestedSubTab?: string) => {
    setActiveTab(tab);
    try {
      const url = new URL(window.location.href);
      const currentPage = url.searchParams.get('page') || '';
      if (currentPage === 'webcare-pro-backups' || currentPage === 'webcare-pro-vault') {
        url.searchParams.set('tab', 'diagnostics');
        url.searchParams.set('section', tab);
        url.searchParams.delete('subtab');
      } else {
        url.searchParams.set('tab', 'diagnostics');
        url.searchParams.set('section', tab);
        url.searchParams.delete('subtab');
      }
      window.history.pushState({ tab: 'diagnostics', section: tab }, '', url.toString());
    } catch (e) {
      // URL push state fallback
    }
    if (onSubTabChange) {
      onSubTabChange(tab, nestedSubTab);
    }
  };

  const filteredFiles = useMemo(() => {
    if (!fileFilter.trim()) return localAuditedFiles;
    const term = fileFilter.toLowerCase();
    return localAuditedFiles.filter(f => (f.file_path || '').toLowerCase().includes(term));
  }, [localAuditedFiles, fileFilter]);

  const cleanFilesCount = useMemo(() => {
    return localAuditedFiles.filter(f => f.status === 'clean' || !f.status).length;
  }, [localAuditedFiles]);

  const threatFilesCount = useMemo(() => {
    return localAuditedFiles.filter(f => f.status === 'threat').length;
  }, [localAuditedFiles]);

  return (
    <div className="webcare-page-container" style={{ width: '100%', maxWidth: '100%', boxSizing: 'border-box' }}>
      {/* Executive Forensics Cockpit Hero */}
      <div className="webcare-forensics-hero">
        <div style={{ position: 'relative', zIndex: 1, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px' }}>
          <div style={{ maxWidth: '800px' }}>
            <div className="webcare-forensics-hero-badge">
              <Terminal size={13} color="#10b981" />
              <span>Deep Security Forensics &amp; System Diagnostics</span>
            </div>
            <h1 className="webcare-forensics-title">
              System Forensics Console
            </h1>
            <p className="webcare-forensics-desc">
              Inspect Living-off-the-Land (LotL) persistence hooks, analyze verified behavioral baselines, query the complete examined files catalog, trace attack correlation timelines, and calibrate false-positive whitelist suppressions.
            </p>
          </div>

          {/* Quick Actions */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <button
              type="button"
              className="webcare-btn webcare-forensics-btn-refresh"
              onClick={() => { window.location.href = 'admin.php?page=webcare-pro-settings&tab=cron'; }}
              title="Open Centralized WP-Cron & Scheduled Tasks Control Center"
            >
              <Clock size={14} />
              <span>Cron Control Center</span>
              <ArrowUpRight size={13} />
            </button>

            <button
              type="button"
              className="webcare-btn webcare-forensics-btn-refresh"
              onClick={() => {
                if (onRefreshScanData) onRefreshScanData();
                loadAuditedFiles();
              }}
              title="Refresh forensics telemetry directly from server"
            >
              <RefreshCw size={14} className={loadingFiles ? 'webcare-spin' : ''} />
              <span>Refresh Telemetry</span>
            </button>

            <button
              type="button"
              className="webcare-btn"
              onClick={onNavigateToDashboard}
              style={{
                background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                color: '#ffffff',
                border: '1px solid #10b981',
                padding: '9px 18px',
                borderRadius: '8px',
                fontSize: '12.5px',
                fontWeight: 700,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '7px',
                cursor: 'pointer',
                boxShadow: '0 4px 12px rgba(16, 185, 129, 0.25)',
              }}
            >
              <ShieldCheck size={14} />
              <span>Return to Scanner</span>
            </button>
          </div>
        </div>

        {/* 4-Card Forensics Telemetry Ribbon */}
        <div className="webcare-forensics-kpi-grid">
          <div className="webcare-forensics-kpi-card">
            <div className="webcare-forensics-kpi-label">
              <FileCode size={13} color="#0284c7" />
              <span>Examined Files</span>
            </div>
            <div className="webcare-forensics-kpi-val" style={{ fontFamily: 'monospace' }}>
              {localAuditedFiles.length.toLocaleString()}
            </div>
            <div className="webcare-forensics-kpi-sub">
              {cleanFilesCount.toLocaleString()} Clean &bull; {threatFilesCount} Threats
            </div>
          </div>

          <div className="webcare-forensics-kpi-card">
            <div className="webcare-forensics-kpi-label">
              <Sparkles size={13} color="#d97706" />
              <span>Persistence Sentinel</span>
            </div>
            <div className="webcare-forensics-kpi-val">
              Active Defense
            </div>
            <div className="webcare-forensics-kpi-sub" style={{ color: '#059669', fontWeight: 600 }}>
              Auto-Prepend &amp; Crons Monitored
            </div>
          </div>

          <div className="webcare-forensics-kpi-card">
            <div className="webcare-forensics-kpi-label">
              <Shield size={13} color="#0284c7" />
              <span>Core Baseline Integrity</span>
            </div>
            <div className="webcare-forensics-kpi-val">
              Cryptographic Hash Lock
            </div>
            <div className="webcare-forensics-kpi-sub" style={{ color: '#0284c7', fontWeight: 600 }}>
              Bit-for-Bit State Verification
            </div>
          </div>

          <div className="webcare-forensics-kpi-card">
            <div className="webcare-forensics-kpi-label">
              <Filter size={13} color="#059669" />
              <span>Whitelist &amp; Tuning</span>
            </div>
            <div className="webcare-forensics-kpi-val">
              Zero-Noise Engine
            </div>
            <div className="webcare-forensics-kpi-sub" style={{ color: '#059669', fontWeight: 600 }}>
              Preserved Across Rescans
            </div>
          </div>
        </div>
      </div>

      {/* 1-on-1 Freelancer Expert Help Ribbon */}
      <div className="webcare-forensics-expert-ribbon">
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div className="webcare-forensics-expert-icon">
            <LifeBuoy size={20} />
          </div>
          <div>
            <div className="webcare-forensics-expert-title">
              Need Senior Linux SysAdmin &amp; WordPress Security Forensics Assistance?
            </div>
            <div className="webcare-forensics-expert-desc">
              Connect directly with Mir Alamin (WebCare Pro) for 1-on-1 root-cause investigation, webshell eradication, and server hardening.
            </div>
          </div>
        </div>

        {onNavigateToSupport && (
          <button
            type="button"
            className="webcare-btn"
            style={{
              background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
              color: '#ffffff',
              border: 'none',
              fontSize: '12.5px',
              fontWeight: 700,
              padding: '9px 18px',
              borderRadius: '8px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              cursor: 'pointer',
              boxShadow: '0 4px 12px rgba(16, 185, 129, 0.25)',
            }}
            onClick={onNavigateToSupport}
          >
            <Phone size={13} />
            <span>Connect with Mir Alamin Directly</span>
            <ArrowUpRight size={13} />
          </button>
        )}
      </div>

      {/* Main Console Container */}
      <div className="webcare-forensics-main-card">
        {/* Navigation Tabs Bar */}
        <div className="webcare-forensics-tabs-bar">
          <div className="webcare-subtabs-nav">
            <button
              type="button"
              className={`webcare-subtab-btn ${activeTab === 'persistence' ? 'is-active' : ''}`}
              onClick={() => handleTabChange('persistence')}
            >
              <Sparkles size={14} color={activeTab === 'persistence' ? '#d97706' : '#64748b'} />
              <span>Startup Scripts</span>
            </button>

            <button
              type="button"
              className={`webcare-subtab-btn ${activeTab === 'watchdog' ? 'is-active' : ''}`}
              onClick={() => handleTabChange('watchdog')}
            >
              <Clock size={14} color={activeTab === 'watchdog' ? '#6366f1' : '#64748b'} />
              <span>72h Watchdog &amp; Snapshots</span>
            </button>

            <button
              type="button"
              className={`webcare-subtab-btn ${activeTab === 'baseline' ? 'is-active' : ''}`}
              onClick={() => handleTabChange('baseline')}
            >
              <Shield size={14} color={activeTab === 'baseline' ? '#06b6d4' : '#64748b'} />
              <span>Behavioral Baseline</span>
            </button>

            <button
              type="button"
              className={`webcare-subtab-btn ${activeTab === 'files' ? 'is-active' : ''}`}
              onClick={() => handleTabChange('files')}
            >
              <FileCode size={14} color={activeTab === 'files' ? '#10b981' : '#64748b'} />
              <span>Audited Files ({localAuditedFiles.length.toLocaleString()})</span>
            </button>

            <button
              type="button"
              className={`webcare-subtab-btn ${activeTab === 'attack_chain' ? 'is-active' : ''}`}
              onClick={() => handleTabChange('attack_chain')}
            >
              <Zap size={14} color={activeTab === 'attack_chain' ? '#6366f1' : '#64748b'} />
              <span>Attack Timeline</span>
            </button>

            <button
              type="button"
              className={`webcare-subtab-btn ${activeTab === 'correlation' ? 'is-active' : ''}`}
              onClick={() => handleTabChange('correlation')}
            >
              <Layers size={14} color={activeTab === 'correlation' ? '#8b5cf6' : '#64748b'} />
              <span>Correlation Hierarchy (5-Tier)</span>
            </button>

            <button
              type="button"
              className={`webcare-subtab-btn ${activeTab === 'whitelist' ? 'is-active' : ''}`}
              onClick={() => handleTabChange('whitelist')}
            >
              <Filter size={14} color={activeTab === 'whitelist' ? '#14b8a6' : '#64748b'} />
              <span>Whitelist &amp; Tuning</span>
            </button>

            <button
              type="button"
              className={`webcare-subtab-btn ${activeTab === 'transactions' ? 'is-active' : ''}`}
              onClick={() => handleTabChange('transactions')}
            >
              <RotateCcw size={14} color={activeTab === 'transactions' ? '#f59e0b' : '#64748b'} />
              <span>Remediation Snapshots</span>
            </button>

            <button
              type="button"
              className={`webcare-subtab-btn ${activeTab === 'self_defense' ? 'is-active' : ''}`}
              onClick={() => handleTabChange('self_defense')}
            >
              <ShieldCheck size={14} color={activeTab === 'self_defense' ? '#10b981' : '#64748b'} />
              <span>Plugin Self-Defense</span>
            </button>
          </div>
        </div>

        {/* Tab Content Display */}
        <div style={{ padding: '24px' }}>
          {/* TAB 1: Startup Scripts / Living-off-the-Land Persistence */}
          {activeTab === 'persistence' && (
            <PersistenceSentinelCard
              apiRequest={apiRequest}
              onPersistenceUpdated={() => {
                if (onRefreshScanData) onRefreshScanData();
              }}
            />
          )}

          {/* TAB: 72-Hour Reinfection Watchdog & Time-Machine Snapshots */}
          {activeTab === 'watchdog' && (
            <PersistenceWatchdogCard
              apiRequest={apiRequest}
              initialSubTab={(initialNestedSubTab as any) || (new URLSearchParams(window.location.search).get('subtab') as any) || 'watchdog'}
              onSubTabChange={(sub) => handleTabChange('watchdog', sub)}
            />
          )}

          {/* TAB 2: Behavioral Baseline */}
          {activeTab === 'baseline' && (
            <BehavioralBaselineCard apiRequest={apiRequest} />
          )}

          {/* TAB 3: Audited Files Catalog */}
          {activeTab === 'files' && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
                <div>
                  <h3 className="webcare-forensics-section-title">
                    Examined Files Catalog ({localAuditedFiles.length.toLocaleString()})
                  </h3>
                  <p className="webcare-forensics-section-desc">
                    Live catalog of all physical files examined during the latest security audit with sizes, scan timestamps, and threat flags.
                  </p>
                </div>

                <div style={{ position: 'relative', width: '320px' }}>
                  <Search size={14} color="#94a3b8" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
                  <input
                    type="text"
                    placeholder="Search file path or extension..."
                    value={fileFilter}
                    onChange={(e) => setFileFilter(e.target.value)}
                    className="webcare-forensics-search-input"
                  />
                  {fileFilter && (
                    <button
                      type="button"
                      onClick={() => setFileFilter('')}
                      style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#94a3b8', fontSize: '11px', fontWeight: 700 }}
                    >
                      Clear
                    </button>
                  )}
                </div>
              </div>

              {filteredFiles.length === 0 ? (
                <div className="webcare-forensics-empty-box">
                  <FileCode size={36} color="#94a3b8" style={{ margin: '0 auto 10px auto' }} />
                  <h4>No Files Match Filter</h4>
                  <p style={{ margin: 0, fontSize: '13px' }}>
                    No examined files match your search criteria "{fileFilter}".
                  </p>
                </div>
              ) : (
                <div className="webcare-forensics-table-container">
                  <div style={{ maxHeight: '560px', overflowY: 'auto' }}>
                    <table className="webcare-forensics-table">
                      <thead>
                        <tr>
                          <th>Examined File Path</th>
                          <th style={{ width: '110px' }}>Size</th>
                          <th style={{ width: '110px' }}>Status</th>
                          <th style={{ width: '150px' }}>Audited At</th>
                          <th style={{ textAlign: 'right', width: '90px' }}>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredFiles.slice(0, 300).map((file, idx) => {
                          return (
                            <tr key={file.id || idx}>
                              <td className="webcare-forensics-path-cell">
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                  <span>{file.file_path}</span>
                                  <button
                                    type="button"
                                    onClick={() => {
                                      if (navigator.clipboard) {
                                        navigator.clipboard.writeText(file.file_path);
                                        setCopiedPath('path_' + (file.id || idx));
                                        setTimeout(() => setCopiedPath(null), 2000);
                                      }
                                    }}
                                    style={{ background: 'none', border: 'none', padding: '2px', cursor: 'pointer', color: copiedPath === 'path_' + (file.id || idx) ? '#16a34a' : '#94a3b8' }}
                                    title="Copy file path"
                                  >
                                    {copiedPath === 'path_' + (file.id || idx) ? <Check size={11} color="#16a34a" /> : <Copy size={11} />}
                                  </button>
                                </div>
                              </td>
                              <td style={{ padding: '10px 14px', color: '#94a3b8' }}>
                                {(file.file_size / 1024).toFixed(1)} KB
                              </td>
                              <td style={{ padding: '10px 14px' }}>
                                <span
                                  className={`webcare-badge-pill ${file.status === 'threat' ? 'webcare-badge-danger' : 'webcare-badge-clean'}`}
                                  style={{
                                    fontSize: '11px',
                                    fontWeight: 700,
                                  }}
                                >
                                  {file.status === 'threat' ? 'Threat' : 'Clean'}
                                </span>
                              </td>
                              <td style={{ padding: '10px 14px', color: '#94a3b8', fontSize: '11px' }}>
                                {file.scanned_at || 'Recent'}
                              </td>
                              <td style={{ padding: '10px 16px', textAlign: 'right' }}>
                                {onOpenFileViewer && (
                                  <button
                                    type="button"
                                    className="webcare-forensics-view-btn"
                                    onClick={() => onOpenFileViewer(undefined, file.file_path)}
                                    title="Inspect source code in popup"
                                  >
                                    <Eye size={11} />
                                    <span>View</span>
                                  </button>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                  {filteredFiles.length > 300 && (
                    <div className="webcare-forensics-table-footer">
                      Showing first 300 of {filteredFiles.length.toLocaleString()} matching files. Refine search filter to narrow paths.
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* TAB 4: Attack Timeline */}
          {activeTab === 'attack_chain' && (
            <AttackChainCard
              apiRequest={apiRequest}
              onChainRemediated={() => {
                if (onRefreshScanData) onRefreshScanData();
              }}
              onNavigateToSupport={onNavigateToSupport}
            />
          )}

          {/* TAB: 5-Tier Telemetry Threat Correlation Hierarchy */}
          {activeTab === 'correlation' && (
            <ThreatCorrelationHierarchyCard
              apiRequest={apiRequest}
              onNavigateToContainment={() => handleTabChange('watchdog')}
            />
          )}

          {/* TAB 5: Whitelist & False-Positives */}
          {activeTab === 'whitelist' && (
            <WhitelistManagerTab
              apiRequest={apiRequest}
              onRefreshFindings={() => {
                if (onRefreshScanData) onRefreshScanData();
              }}
            />
          )}

          {/* TAB 6: Remediation Snapshots */}
          {activeTab === 'transactions' && (
            <RemediationTransactionsCard
              apiRequest={apiRequest}
              onRollbackComplete={() => {
                if (onRefreshScanData) onRefreshScanData();
              }}
            />
          )}

          {/* TAB 7: Plugin Self-Defense & Anti-Tamper Attestation */}
          {activeTab === 'self_defense' && (
            <PluginSelfDefenseCard
              apiRequest={apiRequest}
            />
          )}
        </div>
      </div>
    </div>
  );
};

export default ForensicsPage;
