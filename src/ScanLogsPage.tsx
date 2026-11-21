import React, { useState, useMemo, Fragment } from 'react';
import {
  History,
  Archive,
  Trash2,
  RefreshCw,
  Clock,
  PlayCircle,
  Calendar,
  Layers,
  Target,
  Sliders,
  AlertTriangle,
  CheckCircle2,
  FileText,
  Zap,
  Activity,
  Cpu,
  Server,
  ShieldCheck,
  ShieldAlert,
  LifeBuoy,
  Phone,
  ArrowUpRight,
  ChevronDown,
  ChevronRight,
  ChevronLeft,
  User,
  UserCheck,
  Database,
  Folder,
  Globe,
  Key,
  Edit3,
  BookOpen,
  FileCode,
  Eye,
  Check,
  Copy,
  MessageSquare,
  Search,
  Filter,
  Sparkles,
  BarChart3,
  XCircle,
  Terminal,
  ShieldX,
  Download,
  Info,
  X
} from 'lucide-react';
import ExportResultsDropdown from './ExportResultsDropdown';
import { generateStandardLogFilename } from './exportUtils';
import { getScanTargetInfo, ComponentForensicsCard, getFindingDisplayTitle, SafeErrorBoundary } from './App';
import { formatRelativeTime, formatTelemetryDateFull, formatDateTimeComprehensive } from './timeUtils';
import { FindingForensicsDrawer } from './components/FindingForensicsDrawer';
import { toast } from './utils/dialog';

interface ScanLogsPageProps {
  apiRequest: (opts: any) => Promise<any>;
  scanHistory: any[];
  historyLoading: boolean;
  loadScanHistory: () => Promise<void>;
  handleClearAllScanHistory: () => Promise<void>;
  selectedScanDetail: any;
  setSelectedScanDetail: (d: any) => void;
  loadScanLogDetail: (id: number, updateUrl?: boolean) => Promise<void>;
  scanning: boolean;
  targetedScanning: any;
  handleNavTabChange: (tab: string, subTab?: string) => void;
  setVisualDiffModal: (modal: any) => void;
  handleOpenFileViewer: (issue: any) => void;
  handleOpenChangelog: (issue: any) => void;
  canQuarantineIssue: (issue: any) => boolean;
  handleQuarantine: (issue: any) => Promise<void>;
  handleRemediateUser: (issue: any, action: string, role?: string, targetAdminId?: number) => Promise<void>;
  handleRemediateDbRow: (issue: any, action: string) => Promise<void>;
  handleDeleteCronHook: (issue: any) => Promise<void>;
  handleModerateComment: (issue: any, action: string) => Promise<void>;
  handleFixPermissions: (issue: any) => Promise<void>;
  handleDisableWpDebug?: (issue: any) => Promise<void>;
  handleOpenDbInspector: (issue: any) => void;
  handleOpenPostViewer: (issue: any) => void;
  setWhitelistModal: (modal: any) => void;
  setCveModal: (modal: any) => void;
  handleUpdateIssue: (id: any, status: string) => Promise<void>;
  dbRowCache: Record<number, any>;
  loadDbRow: (issue: any) => void;
  copiedIssuePath: string | null;
  setCopiedIssuePath: (p: string | null) => void;
}

export const ScanLogsPage: React.FC<ScanLogsPageProps> = ({
  apiRequest,
  scanHistory,
  historyLoading,
  loadScanHistory,
  handleClearAllScanHistory,
  selectedScanDetail,
  setSelectedScanDetail,
  loadScanLogDetail,
  scanning,
  targetedScanning,
  handleNavTabChange,
  setVisualDiffModal,
  handleOpenFileViewer,
  handleOpenChangelog,
  canQuarantineIssue,
  handleQuarantine,
  handleRemediateUser,
  handleRemediateDbRow,
  handleDeleteCronHook,
  handleModerateComment,
  handleFixPermissions,
  handleDisableWpDebug,
  handleOpenDbInspector,
  handleOpenPostViewer,
  setWhitelistModal,
  setCveModal,
  handleUpdateIssue,
  dbRowCache,
  loadDbRow,
  copiedIssuePath,
  setCopiedIssuePath,
}) => {
  const [expandedLogIssue, setExpandedLogIssue] = useState<number | null>(null);
  const [logIssueSearch, setLogIssueSearch] = useState<string>('');
  const [logSeverityFilter, setLogSeverityFilter] = useState<string>('all');
  const [logCategoryFilter, setLogCategoryFilter] = useState<string>('all');
  const [logStatusFilter, setLogStatusFilter] = useState<string>('all');
  const [historyFilterTrigger, setHistoryFilterTrigger] = useState<'all' | 'manual' | 'scheduled'>('all');
  const [findingsPage, setFindingsPage] = useState<number>(1);
  const [findingsPageSize, setFindingsPageSize] = useState<number>(100);

  // Scan History Export Modal State
  const [isHistoryExportModalOpen, setIsHistoryExportModalOpen] = useState<boolean>(false);
  const [historyExportScope, setHistoryExportScope] = useState<'all' | 'date'>('all');
  const [historyExportDate, setHistoryExportDate] = useState<string>(() => new Date().toISOString().slice(0, 10));
  const [historyExportFormat, setHistoryExportFormat] = useState<'json' | 'csv'>('json');
  const [isExportingHistory, setIsExportingHistory] = useState<boolean>(false);

  const parseDbFinding = (issue: any) => {
    let tableName = issue.table_name || '';
    let columnName = issue.column_name || '';
    let rowId: string | number | null = issue.row_id || null;

    if (!tableName || !columnName || !rowId) {
      const match = issue.file_path?.match(/^([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)(?:\s*\[ID:\s*(\d+)\])?/i);
      if (match) {
        if (!tableName) tableName = match[1];
        if (!columnName) columnName = match[2];
        if (!rowId && match[3]) rowId = match[3];
      }
    }
    if (!rowId && issue.file_path) {
      const idMatch = issue.file_path.match(/\[ID:\s*(\d+)\]/i);
      if (idMatch) rowId = idMatch[1];
    }
    if (!tableName && issue.file_path) {
      tableName = issue.file_path.split('.')[0] || '';
    }
    if (!columnName && issue.file_path && issue.file_path.includes('.')) {
      columnName = issue.file_path.split('.')[1]?.split(' ')[0] || '';
    }
    return { tableName, columnName, rowId };
  };

  const logIssues: any[] = useMemo(() => selectedScanDetail?.issues || [], [selectedScanDetail]);

  const isCveOrWarningIssue = (item: any) =>
    Boolean(
      (item.cves && item.cves.length > 0) ||
      item.is_software_update ||
      item.engine === 'wordpress-updates' ||
      ((item.severity === 'medium' || item.severity === 'low' || item.type?.includes('warning')) &&
        !item.type?.includes('modified') &&
        !item.type?.includes('integrity') &&
        !item.engine?.includes('fim'))
    );

  const logOpenCount = useMemo(
    () => logIssues.filter((i) => i.status !== 'ignored' && !i.is_whitelisted && i.status !== 'repaired' && i.status !== 'quarantined').length,
    [logIssues]
  );

  const logIgnoredCount = useMemo(
    () => logIssues.filter((i) => i.status === 'ignored' || Boolean(i.is_whitelisted)).length,
    [logIssues]
  );

  const filteredLogIssues = useMemo(() => {
    return logIssues.filter((item) => {
      const matchesStatus =
        logStatusFilter === 'all'
          ? true
          : logStatusFilter === 'open'
          ? item.status !== 'ignored' && !item.is_whitelisted && item.status !== 'repaired' && item.status !== 'quarantined'
          : logStatusFilter === 'ignored'
          ? item.status === 'ignored' || Boolean(item.is_whitelisted)
          : item.status === logStatusFilter;

      const matchesSeverity = logSeverityFilter === 'all' || item.severity === logSeverityFilter;

      const matchesCategory =
        logCategoryFilter === 'all'
          ? true
          : logCategoryFilter === 'critical'
          ? item.severity === 'critical' || item.severity === 'high'
          : logCategoryFilter === 'fim'
          ? item.type?.includes('modified') || item.type?.includes('integrity') || item.engine?.includes('fim')
          : logCategoryFilter === 'cve'
          ? isCveOrWarningIssue(item)
          : logCategoryFilter === 'spam'
          ? item.is_comment || item.is_post || item.engine?.includes('comment') || item.engine?.includes('database') || item.engine?.includes('spam') || item.type?.includes('spam') || (item.file_path && item.file_path.startsWith('comment:'))
          : logCategoryFilter === 'users'
          ? item.is_user || item.engine?.includes('user') || (item.file_path && item.file_path.startsWith('user:'))
          : true;

      const term = logIssueSearch.toLowerCase().trim();
      const matchesSearch =
        !term ||
        (item.file_path && item.file_path.toLowerCase().includes(term)) ||
        (item.description && item.description.toLowerCase().includes(term)) ||
        (item.type && item.type.toLowerCase().includes(term)) ||
        (item.post_title && item.post_title.toLowerCase().includes(term)) ||
        (item.component_name && item.component_name.toLowerCase().includes(term)) ||
        (item.author_name && item.author_name.toLowerCase().includes(term)) ||
        (item.code_snippet && item.code_snippet.toLowerCase().includes(term)) ||
        (item.engine && item.engine.toLowerCase().includes(term));
      return matchesStatus && matchesSeverity && matchesCategory && matchesSearch;
    });
  }, [logIssues, logStatusFilter, logSeverityFilter, logCategoryFilter, logIssueSearch]);

  const totalFindingsCount = filteredLogIssues.length;
  const totalFindingsPages = Math.max(1, Math.ceil(totalFindingsCount / findingsPageSize));

  // Reset to first page when filtering or searching
  React.useEffect(() => {
    setFindingsPage(1);
  }, [logStatusFilter, logSeverityFilter, logCategoryFilter, logIssueSearch, findingsPageSize]);

  const paginatedLogIssues = useMemo(() => {
    const startIndex = (findingsPage - 1) * findingsPageSize;
    return filteredLogIssues.slice(startIndex, startIndex + findingsPageSize);
  }, [filteredLogIssues, findingsPage, findingsPageSize]);

  const copyToClipboard = (text: string) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedIssuePath(text);
      setTimeout(() => setCopiedIssuePath(null), 2000);
    }
  };

  // Aggregated Historical Metrics
  const stats = useMemo(() => {
    const totalRuns = scanHistory.length;
    const cleanRuns = scanHistory.filter((s) => Number(s.issues_found || 0) === 0).length;
    const threatsDetected = scanHistory.reduce((acc, s) => acc + Number(s.issues_found || 0), 0);
    const totalFilesAudited = scanHistory.reduce((acc, s) => acc + Number(s.scanned_files || 0), 0);
    const avgScore = totalRuns > 0 ? Math.round(scanHistory.reduce((acc, s) => acc + Number(s.risk_score || 0), 0) / totalRuns) : 0;
    return { totalRuns, cleanRuns, threatsDetected, totalFilesAudited, avgScore };
  }, [scanHistory]);

  const triggerDownload = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 250);
  };

  const executeHistoryExport = async () => {
    setIsExportingHistory(true);
    try {
      const filename = generateStandardLogFilename('scan-history', historyExportFormat, historyExportScope === 'date' ? historyExportDate : undefined);

      let targetRuns = scanHistory;
      if (historyExportScope === 'date' && historyExportDate) {
        targetRuns = scanHistory.filter((s: any) => {
          const dateStr = (s.started_at || s.created_at || '').slice(0, 10);
          return dateStr === historyExportDate;
        });
      }

      if (targetRuns.length === 0) {
        toast.warning('No scan history records found for the selected scope.');
        setIsExportingHistory(false);
        return;
      }

      let envSnapshot: any = null;
      try {
        const snapRes = await apiRequest({ path: '/system/telemetry-snapshot', method: 'GET' });
        if (snapRes && snapRes.success && snapRes.data) {
          envSnapshot = snapRes.data;
        }
      } catch (e) {
        // Fallback
      }

      if (historyExportFormat === 'json') {
        const payload: any = {
          report_generator: 'WebCare Pro Security & Firewall - Audit Ledger',
          specialist: 'Mir Alamin (WebCare Pro)',
          specialist_role: 'Senior Linux SysAdmin & WordPress Security Engineer',
          site_url: (window as any).webcareScannerSettings?.siteUrl || window.location.origin,
          exported_at: new Date().toISOString(),
          scope: historyExportScope,
          date_filter: historyExportScope === 'date' ? historyExportDate : null,
          total_runs: targetRuns.length,
          runs: targetRuns,
        };
        if (envSnapshot) {
          payload.environment_snapshot = envSnapshot;
          payload.edge_telemetry = envSnapshot.edge_network || null;
        }
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8;' });
        triggerDownload(blob, filename);
      } else {
        const escapeCell = (val: any): string => {
          if (val === null || val === undefined) return '""';
          let str = typeof val === 'object' ? JSON.stringify(val) : String(val);
          const trimmed = str.trim();
          if (trimmed.length > 0 && ['=', '+', '-', '@', '\t', '\r'].includes(trimmed[0])) {
            str = `'` + str;
          }
          return `"${str.replace(/"/g, '""')}"`;
        };

        const headers = [
          'Audit ID',
          'Date Started',
          'Date Completed',
          'Trigger Type',
          'Scan Target',
          'Status',
          'Files Scanned',
          'Total Files',
          'Threats Detected',
          'Risk Score',
          'Duration Seconds',
        ];

        const rows = targetRuns.map((s: any) => [
          escapeCell(s.id),
          escapeCell(s.started_at || s.created_at || ''),
          escapeCell(s.completed_at || ''),
          escapeCell(s.trigger_type || 'manual'),
          escapeCell(s.scan_target || 'plugins_themes'),
          escapeCell(s.status || ''),
          escapeCell(s.scanned_files || 0),
          escapeCell(s.total_files || 0),
          escapeCell(s.issues_found || 0),
          escapeCell(s.risk_score || 0),
          escapeCell(s.duration || s.duration_ms || ''),
        ].join(','));

        let csvContent = '\uFEFF';
        if (envSnapshot) {
          const cfText = envSnapshot?.edge_network?.powered_by_cloudflare
            ? `YES (${envSnapshot?.edge_network?.cloudflare_status || 'Cloudflare Edge'})`
            : 'NO (Direct Origin)';
          const preamble = [
            '# =============================================================================',
            '# WebCare Pro Security & Firewall - SCAN AUDIT HISTORY LEDGER',
            `# Site Domain: ${envSnapshot?.site?.domain || 'Unknown'} | Real Server IP: ${envSnapshot?.server?.real_ip || 'Unknown'}`,
            `# Cloudflare Edge: ${cfText}`,
            `# Cloudflare Integration: ${envSnapshot?.edge_network?.cloudflare_connected ? 'CONNECTED' : 'NOT CONNECTED'} | Auto-Ban Sync: ${envSnapshot?.edge_network?.cf_auto_sync_bans_enabled ? 'ENABLED' : 'DISABLED'} | Active Edge Bans: ${envSnapshot?.edge_network?.cf_active_edge_bans_count || 0} | Local Blocks: ${envSnapshot?.edge_network?.local_active_blocks_count || 0}`,
            `# Server Software: ${envSnapshot?.server?.software || 'Unknown'} | PHP: ${envSnapshot?.server?.php_version || 'Unknown'} | WP Core: ${envSnapshot?.wordpress?.core_version || 'Unknown'}`,
            `# Active Theme: ${envSnapshot?.theme?.active_theme?.name || 'Unknown'} (v${envSnapshot?.theme?.active_theme?.version || 'Unknown'})`,
            `# Exported At (UTC): ${envSnapshot?.exported_at_utc || new Date().toISOString()}`,
            '# ============================================================================='
          ].join('\r\n');
          csvContent += preamble + '\r\n';
        }
        csvContent += [headers.map(escapeCell).join(','), ...rows].join('\r\n');

        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        triggerDownload(blob, filename);
      }

      setIsHistoryExportModalOpen(false);
    } catch (err: any) {
      console.error('Failed to export scan history:', err);
      toast.error(err?.message || 'Failed to export scan history.');
    } finally {
      setIsExportingHistory(false);
    }
  };

  const filteredScanHistory = useMemo(() => {
    if (historyFilterTrigger === 'all') return scanHistory;
    return scanHistory.filter((s) => s.trigger_type === historyFilterTrigger);
  }, [scanHistory, historyFilterTrigger]);

  return (
    <div className="webcare-scan-logs-v2">
      {/* 1. EXECUTIVE MISSION-CONTROL HERO */}
      <div className="webcare-logs-hero-card">
        <div className="webcare-logs-hero-main">
          <div className="webcare-logs-badge-row">
            <div className="webcare-logs-badge">
              <span className="webcare-logs-badge-dot" />
              <span>CRYPTOGRAPHIC AUDIT LEDGER</span>
            </div>
            <div className="webcare-logs-badge" style={{ background: 'rgba(99, 102, 241, 0.08)', color: '#6366f1', borderColor: 'rgba(99, 102, 241, 0.2)' }}>
              <span>THREAT STUDIO VAULT</span>
            </div>
          </div>
          <h1 className="webcare-logs-hero-title">
            Recorded Security Audits & Forensics
          </h1>
          <p className="webcare-logs-hero-desc">
            Complete immutable ledger of all automated and manual security scans, forensic inspection reports, runtime telemetry, and 1-click remediation actions.
          </p>
        </div>

        <div className="webcare-logs-hero-actions">
          <button
            type="button"
            className="webcare-btn webcare-btn-quarantine-vault"
            onClick={() => handleNavTabChange('quarantine')}
            title="Open Quarantine Vault"
          >
            <Archive size={16} />
            <span>Quarantine Vault</span>
          </button>
          <button
            type="button"
            className="webcare-btn webcare-btn-secondary"
            onClick={() => setIsHistoryExportModalOpen(true)}
            disabled={historyLoading || scanHistory.length === 0}
            title="Export complete scan history ledger with domain-stamped filename"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '13px', fontWeight: 600 }}
          >
            <Download size={15} />
            <span>Export Logs</span>
          </button>
          <button
            type="button"
            className="webcare-btn webcare-btn-refresh-logs"
            onClick={loadScanHistory}
            disabled={historyLoading}
          >
            <RefreshCw size={15} className={historyLoading ? 'webcare-spin-icon' : ''} />
            <span>{historyLoading ? 'Refreshing...' : 'Refresh Logs'}</span>
          </button>
          <button
            type="button"
            className="webcare-btn webcare-btn-clear-logs"
            onClick={handleClearAllScanHistory}
            disabled={historyLoading || scanHistory.length === 0}
            title={scanning || Boolean(targetedScanning) ? 'Clear past logs while preserving active scan' : 'Permanently remove all previous scan runs and log archives'}
          >
            <Trash2 size={15} />
            <span>{scanning || Boolean(targetedScanning) ? 'Clear Past Logs' : 'Clear All'}</span>
          </button>
        </div>
      </div>

      {/* 2. REAL-TIME AUDIT TELEMETRY STATS GRID */}
      <div className="webcare-logs-stats-grid">
        <div className="webcare-logs-stat-tile">
          <div className="webcare-logs-stat-icon-wrap is-blue">
            <History size={20} />
          </div>
          <div className="webcare-logs-stat-content">
            <span className="webcare-logs-stat-label">Total Audits Run</span>
            <div className="webcare-logs-stat-value">{stats.totalRuns}</div>
            <span className="webcare-logs-stat-sub">
              {stats.cleanRuns} clean runs ({stats.totalRuns > 0 ? Math.round((stats.cleanRuns / stats.totalRuns) * 100) : 0}% pristine)
            </span>
          </div>
        </div>

        <div className="webcare-logs-stat-tile">
          <div className="webcare-logs-stat-icon-wrap is-cyan">
            <FilesIcon size={20} />
          </div>
          <div className="webcare-logs-stat-content">
            <span className="webcare-logs-stat-label">Files Examined</span>
            <div className="webcare-logs-stat-value">{stats.totalFilesAudited.toLocaleString()}</div>
            <span className="webcare-logs-stat-sub">Across all archived audits</span>
          </div>
        </div>

        <div className="webcare-logs-stat-tile">
          <div className="webcare-logs-stat-icon-wrap is-red">
            <ShieldAlert size={20} />
          </div>
          <div className="webcare-logs-stat-content">
            <span className="webcare-logs-stat-label">Total Threats Logged</span>
            <div className="webcare-logs-stat-value" style={{ color: stats.threatsDetected > 0 ? '#ef4444' : '#10b981' }}>
              {stats.threatsDetected}
            </div>
            <span className="webcare-logs-stat-sub">
              {stats.threatsDetected === 0 ? 'Zero active threats recorded' : 'Historical discoveries recorded'}
            </span>
          </div>
        </div>

        <div className="webcare-logs-stat-tile">
          <div className="webcare-logs-stat-icon-wrap is-amber">
            <Activity size={20} />
          </div>
          <div className="webcare-logs-stat-content">
            <span className="webcare-logs-stat-label">Average Risk Score</span>
            <div className="webcare-logs-stat-value" style={{ color: stats.avgScore > 50 ? '#ef4444' : stats.avgScore > 20 ? '#f59e0b' : '#10b981' }}>
              {stats.avgScore} <span style={{ fontSize: '14px', fontWeight: 600, color: '#94a3b8' }}>/ 100</span>
            </div>
            <span className="webcare-logs-stat-sub">
              {stats.avgScore <= 20 ? 'Optimal Security Posture' : 'Caution Advised'}
            </span>
          </div>
        </div>
      </div>

      {/* 3. RECORDED SCAN RUNS LOG CARD */}
      <div className="webcare-logs-table-card">
        <div className="webcare-logs-table-header">
          <div className="webcare-logs-table-title-wrap">
            <div className="webcare-logs-title-icon">
              <Clock size={18} />
            </div>
            <div>
              <h3 className="webcare-logs-section-title">Recorded Scan Runs</h3>
              <p className="webcare-logs-section-subtitle">Select any audit run to inspect threat telemetry, code diffs, and perform 1-click mitigations.</p>
            </div>
          </div>

          <div className="webcare-logs-trigger-tabs">
            <button
              type="button"
              className={`webcare-trigger-tab-btn ${historyFilterTrigger === 'all' ? 'is-active' : ''}`}
              onClick={() => setHistoryFilterTrigger('all')}
            >
              All Runs ({scanHistory.length})
            </button>
            <button
              type="button"
              className={`webcare-trigger-tab-btn ${historyFilterTrigger === 'manual' ? 'is-active' : ''}`}
              onClick={() => setHistoryFilterTrigger('manual')}
            >
              <PlayCircle size={13} /> Manual Runs ({scanHistory.filter(s => s.trigger_type !== 'scheduled').length})
            </button>
            <button
              type="button"
              className={`webcare-trigger-tab-btn ${historyFilterTrigger === 'scheduled' ? 'is-active' : ''}`}
              onClick={() => setHistoryFilterTrigger('scheduled')}
            >
              <Calendar size={13} /> Scheduled Auto ({scanHistory.filter(s => s.trigger_type === 'scheduled').length})
            </button>
          </div>
        </div>

        {scanHistory.length === 0 ? (
          <div className="webcare-empty-state-clean">
            <div className="webcare-empty-state-icon-wrap">
              <History size={36} />
            </div>
            <h4 className="webcare-empty-state-title">No Historical Logs Recorded</h4>
            <p className="webcare-empty-state-desc">Run your first security scan to generate an audit log entry.</p>
          </div>
        ) : (
          <div className="webcare-table-responsive-wrapper">
            <table className="webcare-logs-history-table">
              <thead>
                <tr>
                  <th style={{ width: '85px' }}>Audit #</th>
                  <th style={{ minWidth: '170px' }}>Date & Timestamp</th>
                  <th style={{ minWidth: '135px' }}>Trigger</th>
                  <th style={{ minWidth: '220px' }}>Target Profile</th>
                  <th style={{ width: '130px' }}>Status</th>
                  <th style={{ width: '140px' }}>Files Scanned</th>
                  <th style={{ width: '120px' }}>Threats</th>
                  <th style={{ width: '110px' }}>Risk Score</th>
                  <th style={{ width: '110px' }}>Duration</th>
                  <th style={{ textAlign: 'right', minWidth: '140px' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredScanHistory.map((s) => {
                  const isSelected = selectedScanDetail?.scan?.id === s.id;
                  const isScheduled = s.trigger_type === 'scheduled';
                  const targetInfo = getScanTargetInfo(s.scan_target);
                  return (
                    <tr
                      key={s.id}
                      className={`webcare-log-row ${isSelected ? 'is-selected' : ''}`}
                      onClick={() => {
                        if (isSelected) {
                          setSelectedScanDetail(null);
                        } else {
                          loadScanLogDetail(s.id, true);
                        }
                      }}
                    >
                      <td>
                        <span className="webcare-log-id-pill">#{s.id}</span>
                      </td>
                      {(() => {
                        const timeDetail = formatDateTimeComprehensive(s.created_at_gmt || s.created_at);
                        return (
                          <td title={timeDetail.tooltip}>
                            <div className="webcare-log-time-cell">
                              <Clock size={13} className="webcare-log-time-icon" />
                              <span style={{ fontWeight: 600 }}>{timeDetail.relative}</span>
                              <span style={{ fontSize: '11px', opacity: 0.75, marginLeft: '4px' }}>({s.created_at})</span>
                            </div>
                          </td>
                        );
                      })()}
                      <td>
                        {isScheduled ? (
                          <span className="webcare-pill-badge is-scheduled" title="Automated scheduled run">
                            <Calendar size={12} />
                            Scheduled
                          </span>
                        ) : (
                          <span className="webcare-pill-badge is-manual" title="Manual admin run">
                            <PlayCircle size={12} />
                            Manual Run
                          </span>
                        )}
                      </td>
                      <td>
                        <div className="webcare-log-profile-cell">
                          <span
                            className="webcare-profile-category-tag"
                            style={{
                              background: targetInfo.badgeBg,
                              color: targetInfo.badgeColor,
                              borderColor: targetInfo.badgeBorder
                            }}
                          >
                            {targetInfo.iconType === 'custom' ? (
                              <Sliders size={11} />
                            ) : targetInfo.iconType === 'targeted' ? (
                              <Target size={11} />
                            ) : (
                              <Layers size={11} />
                            )}
                            {targetInfo.categoryLabel}
                          </span>
                          <span className="webcare-profile-title">{targetInfo.name}</span>
                        </div>
                      </td>
                      <td>
                        <span className={`webcare-log-status-pill ${
                          s.status === 'completed'
                            ? 'is-completed'
                            : s.status === 'interrupted' || s.status === 'aborted' || s.status === 'failed'
                            ? 'is-interrupted'
                            : 'is-pending'
                        }`}>
                          <span className="webcare-pulse-dot" />
                          {s.status === 'completed'
                            ? 'COMPLETED'
                            : s.status === 'interrupted'
                            ? 'INTERRUPTED'
                            : s.status === 'aborted'
                            ? 'ABORTED'
                            : (s.status || 'PENDING').toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <div className="webcare-log-files-cell">
                          <strong>{s.scanned_files?.toLocaleString()}</strong>
                          <span className="webcare-log-files-total"> / {s.total_files?.toLocaleString()}</span>
                        </div>
                      </td>
                      <td>
                        <span className={`webcare-threats-badge ${s.issues_found > 0 ? 'has-threats' : 'is-clean'}`}>
                          {s.issues_found > 0 ? <AlertTriangle size={13} /> : <CheckCircle2 size={13} />}
                          <span>{s.issues_found} {s.issues_found === 1 ? 'threat' : 'threats'}</span>
                        </span>
                      </td>
                      <td>
                        <span className={`webcare-risk-badge ${s.risk_score > 60 ? 'is-critical' : s.risk_score > 25 ? 'is-high' : 'is-clean'}`}>
                          {s.risk_score}/100
                        </span>
                      </td>
                      <td>
                        <div className="webcare-duration-cell">
                          {s.duration_formatted || (s.duration_ms ? (s.duration_ms < 1000 ? `${s.duration_ms}ms` : `${(s.duration_ms / 1000).toFixed(1)}s`) : (s.duration ? `${s.duration}s` : 'N/A'))}
                        </div>
                      </td>
                      <td style={{ textAlign: 'right' }} onClick={(e) => e.stopPropagation()}>
                        <button
                          type="button"
                          className={`webcare-btn webcare-btn-inspect-run ${isSelected ? 'is-active' : ''}`}
                          onClick={() => {
                            if (isSelected) {
                              setSelectedScanDetail(null);
                              try {
                                const url = new URL(window.location.href);
                                url.searchParams.delete('scanresults');
                                window.history.pushState({ tab: 'logs' }, '', url.toString());
                              } catch (e) {}
                            } else {
                              loadScanLogDetail(s.id, true);
                            }
                          }}
                        >
                          <FileText size={13} />
                          <span>{isSelected ? 'Hide Report' : 'Inspect Report'}</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* 4. HIGH-SECURITY COCKPIT INSPECTOR (SHOWN WHEN AN AUDIT IS SELECTED) */}
      {selectedScanDetail && (
        <div id="webcare-scan-log-inspector" className="webcare-inspector-card">
          {/* Header Strip */}
          <div className="webcare-inspector-header">
            <div className="webcare-inspector-header-left">
              <div className="webcare-inspector-id-tag">
                <span className="webcare-pulse-dot webcare-pulse-dot-blue" />
                AUDIT RUN #{selectedScanDetail.scan.id}
              </div>
              <h2 className="webcare-inspector-title">Inspection & Audit Findings Report</h2>
              <div className="webcare-inspector-meta-row">
                <span title={formatDateTimeComprehensive(selectedScanDetail.scan.started_at_gmt || selectedScanDetail.scan.started_at || selectedScanDetail.scan.created_at_gmt || selectedScanDetail.scan.created_at).tooltip}>
                  Started: <strong>{selectedScanDetail.scan.started_at || selectedScanDetail.scan.created_at}</strong>
                </span>
                {selectedScanDetail.scan.completed_at && (
                  <>
                    <span className="webcare-meta-bullet">&bull;</span>
                    <span title={formatDateTimeComprehensive(selectedScanDetail.scan.completed_at_gmt || selectedScanDetail.scan.completed_at).tooltip}>
                      Finished: <strong>{selectedScanDetail.scan.completed_at}</strong>
                    </span>
                  </>
                )}
                <span className="webcare-meta-bullet">&bull;</span>
                <span>Trigger: <strong>{selectedScanDetail.scan.trigger_type === 'scheduled' ? 'Scheduled Auto' : 'Manual Run'}</strong></span>
                <span className="webcare-meta-bullet">&bull;</span>
                <span>Evaluated: <strong>{selectedScanDetail.files_count || selectedScanDetail.scan.scanned_files} files</strong></span>
                <span className="webcare-meta-bullet">&bull;</span>
                <span>
                  Risk Score: <strong style={{ color: selectedScanDetail.summary.score > 50 ? '#ef4444' : '#10b981' }}>{selectedScanDetail.summary.score}/100</strong>
                </span>
              </div>
            </div>

            <div className="webcare-inspector-header-actions">
              <button
                type="button"
                className="webcare-btn webcare-btn-clean"
                style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                title="Download raw forensic scan manifest JSON (includes all audited file paths, symlinks, hashes & permissions)"
                onClick={async () => {
                  try {
                    const res = await apiRequest({
                      path: `/scan/manifest/download?scan_id=${selectedScanDetail.scan.id}`,
                      method: 'GET',
                    });
                    if (res && res.manifest_json) {
                      const blob = new Blob([res.manifest_json], { type: 'application/json' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = res.filename || `scan_${selectedScanDetail.scan.id}_manifest.json`;
                      document.body.appendChild(a);
                      a.click();
                      document.body.removeChild(a);
                      URL.revokeObjectURL(url);
                    }
                  } catch (err) {
                    console.error('Failed to download scan manifest', err);
                  }
                }}
              >
                <Download size={14} />
                <span>Vault JSON Manifest</span>
              </button>
              <button
                type="button"
                className="webcare-btn webcare-btn-quarantine-vault"
                onClick={() => handleNavTabChange('quarantine')}
              >
                <Archive size={14} />
                <span>Quarantine Vault</span>
              </button>
              <button
                type="button"
                className="webcare-btn webcare-btn-close-inspector"
                onClick={() => {
                  setSelectedScanDetail(null);
                  try {
                    const url = new URL(window.location.href);
                    url.searchParams.delete('scanresults');
                    window.history.pushState({ tab: 'logs' }, '', url.toString());
                  } catch (e) {}
                }}
              >
                <XCircle size={14} />
                <span>Close Report</span>
              </button>
            </div>
          </div>

          {/* Interruption Forensic Incident Card (Rendered if scan was stopped prematurely) */}
          {(selectedScanDetail?.interruption || selectedScanDetail?.scan?.interruption || selectedScanDetail?.scan?.status === 'interrupted' || selectedScanDetail?.scan?.status === 'aborted') && (() => {
            const intData = selectedScanDetail?.interruption || selectedScanDetail?.scan?.interruption || {};
            const isAborted = selectedScanDetail?.scan?.status === 'aborted' || intData.reason_code === 'manual_abort';
            return (
              <div className={`webcare-interruption-dossier-card ${isAborted ? 'is-aborted' : 'is-error'}`}>
                <div className="webcare-interruption-header">
                  <div className="webcare-interruption-icon-wrap">
                    <ShieldAlert size={22} color={isAborted ? '#f59e0b' : '#ef4444'} />
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                      <span className={`webcare-interruption-badge ${isAborted ? 'is-amber' : 'is-red'}`}>
                        {isAborted ? 'SCAN MANUALLY ABORTED' : 'SCAN PREMATURELY INTERRUPTED'}
                      </span>
                      {intData.reason_code && (
                        <span className="webcare-interruption-code-pill">
                          Reason: {intData.reason_code}
                        </span>
                      )}
                    </div>
                    <h3 className="webcare-interruption-title">
                      {intData.title || (isAborted ? 'Audit Was Manually Stopped by Administrator' : 'Scan Stopped Before Full Filesystem Completion')}
                    </h3>
                    <p className="webcare-interruption-summary">
                      {intData.summary || 'The scan worker was terminated before all queued files could be analyzed.'}
                    </p>
                  </div>
                </div>

                <div className="webcare-interruption-grid">
                  <div className="webcare-interruption-cell">
                    <span className="webcare-interruption-label">Progress at Halt</span>
                    <strong className="webcare-interruption-val">
                      {intData.scanned_files !== undefined ? intData.scanned_files.toLocaleString() : (selectedScanDetail.scan.scanned_files || 0).toLocaleString()} / {intData.total_files !== undefined ? intData.total_files.toLocaleString() : (selectedScanDetail.scan.total_files || 0).toLocaleString()}
                      <span className="webcare-interruption-sub"> ({intData.progress_percent !== undefined ? `${intData.progress_percent}%` : 'Partial'})</span>
                    </strong>
                  </div>

                  <div className="webcare-interruption-cell">
                    <span className="webcare-interruption-label">Memory at Halt</span>
                    <strong className="webcare-interruption-val">
                      {intData.peak_memory_formatted || selectedScanDetail.diagnostics?.peak_memory_fmt || 'N/A'}
                      {intData.memory_limit && (
                        <span className="webcare-interruption-sub"> (Limit: {intData.memory_limit})</span>
                      )}
                    </strong>
                  </div>

                  <div className="webcare-interruption-cell">
                    <span className="webcare-interruption-label">Time Elapsed</span>
                    <strong className="webcare-interruption-val">
                      {intData.elapsed_seconds !== undefined ? `${intData.elapsed_seconds}s` : (selectedScanDetail.scan.duration ? `${selectedScanDetail.scan.duration}s` : 'N/A')}
                      {intData.max_execution_time ? (
                        <span className="webcare-interruption-sub"> (Timeout: {intData.max_execution_time}s)</span>
                      ) : null}
                    </strong>
                  </div>

                  <div className="webcare-interruption-cell">
                    <span className="webcare-interruption-label">PHP Environment</span>
                    <strong className="webcare-interruption-val">
                      PHP {intData.php_version || selectedScanDetail.diagnostics?.php_version || '8.x'}
                      <span className="webcare-interruption-sub"> ({intData.php_sapi || selectedScanDetail.diagnostics?.php_sapi || 'fpm'})</span>
                    </strong>
                  </div>
                </div>

                {intData.last_active_file && (
                  <div className="webcare-interruption-file-row">
                    <span className="webcare-interruption-file-label">Last Audited Target File:</span>
                    <code className="webcare-interruption-file-code">{intData.last_active_file}</code>
                  </div>
                )}

                {intData.technical_details && (
                  <div className="webcare-interruption-tech-box">
                    <strong>Technical Diagnostics:</strong> {intData.technical_details}
                  </div>
                )}

                {intData.remediation && (
                  <div className="webcare-interruption-remediation-box">
                    <strong>Recommended SysAdmin Remediation:</strong> {intData.remediation}
                  </div>
                )}

                {intData.last_php_error && (
                  <div className="webcare-interruption-error-dump">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px', color: '#ef4444', fontWeight: 700, fontSize: '11px' }}>
                      <Terminal size={13} />
                      <span>Captured PHP Low-Level Error:</span>
                    </div>
                    <code>{intData.last_php_error.message} (File: {intData.last_php_error.file}:{intData.last_php_error.line})</code>
                  </div>
                )}

                {intData.caught_exception && (
                  <div className="webcare-interruption-error-dump">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px', color: '#f59e0b', fontWeight: 700, fontSize: '11px' }}>
                      <Terminal size={13} />
                      <span>Exception Stack Trace:</span>
                    </div>
                    <code>{intData.caught_exception.message} in {intData.caught_exception.file}:{intData.caught_exception.line}</code>
                    {intData.caught_exception.trace && (
                      <pre style={{ margin: '6px 0 0 0', fontSize: '10.5px', color: '#94a3b8', whiteSpace: 'pre-wrap', maxHeight: '120px', overflowY: 'auto' }}>
                        {intData.caught_exception.trace}
                      </pre>
                    )}
                  </div>
                )}
              </div>
            );
          })()}

          {/* Telemetry Ribbon */}
          {(() => {
            const diag = selectedScanDetail.diagnostics || selectedScanDetail.scan.diagnostics;
            return (
              <div className="webcare-inspector-telemetry-ribbon">
                <div className="webcare-telemetry-items">
                  <div className="webcare-telemetry-metric">
                    <Clock size={14} color="#38bdf8" />
                    <span className="webcare-metric-label">Execution Duration:</span>
                    <strong className="webcare-metric-val webcare-telemetry-metric-val">
                      {diag?.duration_formatted || (selectedScanDetail.scan.duration_formatted ? selectedScanDetail.scan.duration_formatted : (selectedScanDetail.scan.duration ? `${selectedScanDetail.scan.duration}s` : 'N/A'))}
                    </strong>
                  </div>

                  <div className="webcare-telemetry-metric">
                    <Zap size={14} color="#a855f7" />
                    <span className="webcare-metric-label">Peak Memory:</span>
                    <strong className="webcare-metric-val webcare-telemetry-metric-val">
                      {diag?.peak_memory_fmt || 'N/A'}
                    </strong>
                    {diag?.memory_limit_raw && (
                      <span className="webcare-metric-sub">/ {diag.memory_limit_raw} ({diag.memory_percent}%)</span>
                    )}
                  </div>

                  <div className="webcare-telemetry-metric">
                    <Activity size={14} color="#10b981" />
                    <span className="webcare-metric-label">Throughput:</span>
                    <strong className="webcare-metric-val webcare-telemetry-metric-val">
                      {diag?.files_per_second ? `${diag.files_per_second} files/sec` : 'Optimal'}
                    </strong>
                  </div>

                  {diag?.cpu_load && (
                    <div className="webcare-telemetry-metric">
                      <Cpu size={14} color="#f59e0b" />
                      <span className="webcare-metric-label">CPU Load:</span>
                      <strong className="webcare-metric-val webcare-telemetry-metric-val">{diag.cpu_load['1m']}</strong>
                      <span className="webcare-metric-sub">(5m: {diag.cpu_load['5m']})</span>
                    </div>
                  )}
                </div>

                <div className="webcare-telemetry-pills">
                  <span className="webcare-pill-server">
                    <Server size={12} />
                    PHP {diag?.php_version || '8.x'} ({diag?.php_sapi || 'fpm'})
                  </span>
                  <span className="webcare-pill-engines">
                    <ShieldCheck size={12} color="#10b981" />
                    {diag?.engines_active || 10} Active Engines
                  </span>
                </div>
              </div>
            );
          })()}

          {/* Solo Freelancer 1-on-1 Assistance Banner */}
          {logIssues.length > 0 && (
            <div className="webcare-logs-assistance-banner">
              <div className="webcare-assistance-left">
                <div className="webcare-assistance-avatar">
                  <LifeBuoy size={20} color="#38bdf8" />
                </div>
                <div>
                  <h4 className="webcare-assistance-heading">Need Direct 1-on-1 Assistance Remediating Scan #{selectedScanDetail.scan.id}?</h4>
                  <p className="webcare-assistance-subheading">
                    Connect directly with Mir Alamin (WebCare Pro) for prompt malware eradication, code de-obfuscation, or custom emergency triage.
                  </p>
                </div>
              </div>

              <button
                type="button"
                className="webcare-btn webcare-btn-expert-connect"
                onClick={() => handleNavTabChange('settings', 'support')}
              >
                <Phone size={14} />
                <span>Connect with Mir Alamin Directly</span>
                <ArrowUpRight size={14} />
              </button>
            </div>
          )}

          {/* Interactive Findings Command Filters */}
          {logIssues.length > 0 && (
            <div className="webcare-findings-command-strip">
              {/* Status Tabs */}
              <div className="webcare-findings-status-pills">
                <button
                  type="button"
                  className={`webcare-status-pill ${logStatusFilter === 'all' ? 'is-active' : ''}`}
                  onClick={() => setLogStatusFilter('all')}
                >
                  All ({logIssues.length})
                </button>
                <button
                  type="button"
                  className={`webcare-status-pill is-active-threats ${logStatusFilter === 'open' ? 'is-active' : ''}`}
                  onClick={() => setLogStatusFilter('open')}
                >
                  <span className="webcare-pulse-dot webcare-pulse-dot-red" />
                  Active ({logOpenCount})
                </button>
                <button
                  type="button"
                  className={`webcare-status-pill ${logStatusFilter === 'ignored' ? 'is-active' : ''}`}
                  onClick={() => setLogStatusFilter('ignored')}
                >
                  <ShieldCheck size={12} color="#10b981" />
                  Whitelisted ({logIgnoredCount})
                </button>
              </div>

              {/* Category Filters */}
              <div className="webcare-findings-category-strip">
                <span className="webcare-filter-label">CATEGORY:</span>

                <button
                  type="button"
                  className={`webcare-category-chip ${logCategoryFilter === 'all' ? 'is-active' : ''}`}
                  onClick={() => setLogCategoryFilter('all')}
                >
                  All ({logIssues.length})
                </button>

                <button
                  type="button"
                  className={`webcare-category-chip ${logCategoryFilter === 'critical' ? 'is-active' : ''}`}
                  onClick={() => setLogCategoryFilter('critical')}
                >
                  <span className="webcare-chip-dot is-red" />
                  Critical & High ({logIssues.filter(i => i.severity === 'critical' || i.severity === 'high').length})
                </button>

                <button
                  type="button"
                  className={`webcare-category-chip ${logCategoryFilter === 'fim' ? 'is-active' : ''}`}
                  onClick={() => setLogCategoryFilter('fim')}
                >
                  <FileCode size={12} color="#38bdf8" />
                  Integrity & FIM ({logIssues.filter(i => i.type?.includes('modified') || i.type?.includes('integrity') || i.engine?.includes('fim')).length})
                </button>

                <button
                  type="button"
                  className={`webcare-category-chip ${logCategoryFilter === 'cve' ? 'is-active' : ''}`}
                  onClick={() => setLogCategoryFilter('cve')}
                >
                  <ShieldAlert size={12} color="#f59e0b" />
                  CVEs & Warnings ({logIssues.filter(isCveOrWarningIssue).length})
                </button>

                <button
                  type="button"
                  className={`webcare-category-chip ${logCategoryFilter === 'spam' ? 'is-active' : ''}`}
                  onClick={() => setLogCategoryFilter('spam')}
                >
                  <MessageSquare size={12} color="#a855f7" />
                  Comments & Spam ({logIssues.filter(i => i.is_comment || i.is_post || i.engine?.includes('comment') || i.engine?.includes('database') || i.engine?.includes('spam') || i.type?.includes('spam') || (i.file_path && i.file_path.startsWith('comment:'))).length})
                </button>

                <button
                  type="button"
                  className={`webcare-category-chip ${logCategoryFilter === 'users' ? 'is-active' : ''}`}
                  onClick={() => setLogCategoryFilter('users')}
                >
                  <UserCheck size={12} color="#f97316" />
                  User Accounts ({logIssues.filter(i => i.is_user || i.engine?.includes('user') || (i.file_path && i.file_path.startsWith('user:'))).length})
                </button>
              </div>

              {/* Search & Export Toolbar */}
              <div className="webcare-findings-search-row">
                <div className="webcare-search-box">
                  <Search size={14} className="webcare-search-icon" />
                  <input
                    type="text"
                    placeholder="Search findings by path, vector, or keyword..."
                    value={logIssueSearch}
                    onChange={(e) => setLogIssueSearch(e.target.value)}
                    className="webcare-search-input"
                  />
                  {logIssueSearch && (
                    <button
                      type="button"
                      className="webcare-search-clear-btn"
                      onClick={() => setLogIssueSearch('')}
                    >
                      <XCircle size={13} />
                    </button>
                  )}
                </div>

                <div className="webcare-filter-dropdown-wrap">
                  <select
                    value={logSeverityFilter}
                    onChange={(e) => setLogSeverityFilter(e.target.value)}
                    className="webcare-select-severity"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical Only</option>
                    <option value="high">High Only</option>
                    <option value="medium">Medium Only</option>
                    <option value="low">Low Only</option>
                    <option value="info">Info Only</option>
                  </select>

                  <select
                    value={findingsPageSize}
                    onChange={(e) => setFindingsPageSize(Number(e.target.value))}
                    className="webcare-select-severity"
                    style={{ minWidth: '105px' }}
                    title="Max findings per page to keep browser responsive"
                  >
                    <option value={25}>25 per page</option>
                    <option value={50}>50 per page</option>
                    <option value={100}>100 per page</option>
                    <option value={200}>200 per page</option>
                  </select>

                  <ExportResultsDropdown
                    issues={filteredLogIssues}
                    allIssues={logIssues}
                    scan={selectedScanDetail.scan}
                    summary={selectedScanDetail.summary}
                    diagnostics={selectedScanDetail.diagnostics || selectedScanDetail.scan?.diagnostics}
                  />
                </div>
              </div>
            </div>
          )}

          {/* 5. FINDINGS AND MITIGATION TABLE */}
          {logIssues.length === 0 ? (
            <div className="webcare-empty-state-clean">
              <div className="webcare-empty-state-icon-wrap">
                <CheckCircle2 size={38} color="#10b981" />
              </div>
              <h4 className="webcare-empty-state-title">Clean Audit Run &mdash; Zero Threats Discovered</h4>
              <p className="webcare-empty-state-desc">No webshells, backdoor code, modified core components, or database vulnerabilities were detected in this audit.</p>
            </div>
          ) : (
            <div className="webcare-table-responsive-wrapper">
              <table className="webcare-threat-table">
                <thead>
                  <tr>
                    <th style={{ width: '48px', textAlign: 'center' }}>#</th>
                    <th style={{ width: '110px' }}>Severity</th>
                    <th style={{ width: '240px' }}>Threat / Vector</th>
                    <th>Location & Context</th>
                    <th style={{ width: '115px' }}>Status</th>
                    <th style={{ textAlign: 'right', minWidth: '320px' }}>
                      <span className="webcare-mitigation-header-badge">MITIGATION & ACTIONS</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {filteredLogIssues.length === 0 ? (
                    <tr>
                      <td colSpan={6} style={{ padding: '48px', textAlign: 'center', color: '#94a3b8' }}>
                        No audit findings match your selected filter criteria.
                      </td>
                    </tr>
                  ) : (
                    paginatedLogIssues.map((issue, index) => {
                      const absoluteIndex = (findingsPage - 1) * findingsPageSize + index + 1;
                      const isExpanded = expandedLogIssue === issue.id;
                      const isComment = issue.is_comment || issue.engine === 'content-comments' || Boolean(issue.file_path && issue.file_path.startsWith('comment:'));
                      const isPost = !isComment && (issue.is_post || (Boolean(issue.post_id) && issue.engine !== 'content-comments') || issue.engine === 'content-spam');
                      const isCronHook = issue.engine === 'wordpress-cron' || issue.file_path?.startsWith('cron:') || issue.type?.includes('cron_hook');
                      const isUser = Boolean(
                        issue.is_user ||
                        issue.engine === 'wordpress-users' ||
                        issue.type?.startsWith('user_') ||
                        issue.type?.includes('user_capabilities') ||
                        issue.type?.includes('admin_user') ||
                        issue.type?.includes('weak_password') ||
                        issue.type?.includes('app_password') ||
                        issue.type?.includes('application_password') ||
                        issue.type?.includes('generic_admin_username') ||
                        issue.type?.includes('username_enumeration_risk') ||
                        issue.file_path?.startsWith('user:') ||
                        issue.file_path?.includes('_users:user_id_') ||
                        issue.file_path?.includes('_usermeta:user_id_') ||
                        issue.file_path?.includes('users.ID') ||
                        issue.title?.toLowerCase().includes('app password') ||
                        issue.display_title?.toLowerCase().includes('app password')
                      );
                      const isDbOption = issue.engine === 'database-options' || issue.file_path?.startsWith('wp_options:') || issue.file_path?.startsWith('wp_options.') || issue.type?.includes('option');
                      const isHook = issue.engine === 'lotl-hook-sentinel' || issue.engine === 'hook-sentinel' || issue.file_path?.startsWith('hook:') || isCronHook;
                      const isDbTable = !isUser && (issue.is_db_table || issue.engine === 'database-table' || isDbOption || Boolean(issue.file_path && !issue.file_path.includes('/') && !issue.file_path.includes('\\') && (issue.file_path.includes('.') || issue.file_path.includes(' [ID:'))));
                      const isDbRecord = !isUser && (isDbOption || isDbTable || issue.engine === 'database-scanner' || issue.engine === 'database-micro-anomaly' || issue.file_path?.startsWith('db:') || issue.file_path?.startsWith('table:'));
                      const isParsedDb = isDbTable ? parseDbFinding(issue) : null;
                      const isUpdate = issue.engine === 'wordpress-updates' || issue.is_software_update;
                      const isDir = Boolean(issue.is_dir) ||
                        issue.type === 'plugin_checksums_unavailable' ||
                        issue.type === 'theme_checksums_unavailable' ||
                        issue.type?.includes('_checksums_unavailable') ||
                        (issue.engine === 'integrity-theme' && (issue.file_path?.includes('/themes/') || issue.file_path?.includes('\\themes\\')) && !issue.file_path?.match(/\.[a-zA-Z0-9]{2,5}$/)) ||
                        (issue.engine === 'integrity-plugin' && (issue.file_path?.includes('/plugins/') || issue.file_path?.includes('\\plugins\\')) && !issue.file_path?.match(/\.[a-zA-Z0-9]{2,5}$/));

                      const isNonPhysical = Boolean(
                        isHook ||
                        isCronHook ||
                        isDbRecord ||
                        isDbTable ||
                        isDbOption ||
                        isUser ||
                        isPost ||
                        isComment ||
                        isUpdate ||
                        !issue.file_path ||
                        issue.file_path.startsWith('cron:') ||
                        issue.file_path.startsWith('wp_options:') ||
                        issue.file_path.startsWith('wp_options.') ||
                        issue.file_path.startsWith('db:') ||
                        issue.file_path.startsWith('table:') ||
                        issue.file_path.startsWith('user:') ||
                        issue.file_path.startsWith('comment:') ||
                        issue.file_path.startsWith('post:') ||
                        issue.file_path.startsWith('hook:') ||
                        issue.file_path.startsWith('author:') ||
                        issue.file_path.includes(' [ID:') ||
                        issue.file_path.includes('user_id_') ||
                        issue.file_path.includes('_usermeta:') ||
                        issue.file_path.includes('_users:') ||
                        issue.engine === 'database-table' ||
                        issue.engine === 'database-scanner' ||
                        issue.engine === 'database-micro-anomaly' ||
                        issue.engine === 'database-options' ||
                        issue.engine === 'content-spam' ||
                        issue.engine === 'content-comments' ||
                        issue.engine === 'content-posts' ||
                        issue.engine === 'wordpress-users' ||
                        issue.engine === 'wordpress-cron'
                      );

                      const isPhysicalFile = !isNonPhysical && !isDir && (issue.file_path.includes('/') || issue.file_path.includes('\\') || issue.file_path.endsWith('.php'));

                      const isUnknownFile = Boolean(
                        issue.type?.includes('unknown') ||
                        issue.type?.includes('extra') ||
                        issue.type?.includes('disguised') ||
                        issue.type?.includes('webshell') ||
                        issue.type?.includes('backdoor') ||
                        issue.type?.includes('malware') ||
                        issue.engine?.includes('uploads')
                      );

                      const isFimEligible = isPhysicalFile && !isUnknownFile && (
                        issue.type?.includes('modified') ||
                        issue.type?.includes('tampered') ||
                        issue.type?.includes('injected') ||
                        issue.type?.includes('mismatch') ||
                        issue.file_path.endsWith('wp-config.php')
                      );

                      const isEven = index % 2 === 0;
                      const rowSeverityClass =
                        issue.severity === 'critical'
                          ? (isEven ? 'is-critical-even' : 'is-critical-odd')
                          : issue.severity === 'high'
                          ? (isEven ? 'is-high-even' : 'is-high-odd')
                          : issue.severity === 'medium'
                          ? (isEven ? 'is-medium-even' : 'is-medium-odd')
                          : (isEven ? 'is-low-even' : 'is-low-odd');

                      const isCurrentUser = Boolean(issue.is_current_user || (issue.user_id && (window as any).webcareScannerSettings?.currentUserId && issue.user_id === (window as any).webcareScannerSettings?.currentUserId));
                      const isWeakPassword = issue.type === 'weak_password_detected' || issue.type?.includes('weak_password');
                      const rawUserId = issue.user_id || (issue.file_path && issue.file_path.match(/user(?:_id)?[:_]\s*(\d+)/i)?.[1]) || '';
                      const parsedUserId = Number(rawUserId);
                      const validUserId = Number.isInteger(parsedUserId) && parsedUserId > 0 ? parsedUserId : null;

                      return (
                        <Fragment key={`log-finding-${issue.id}`}>
                          <tr key={`log-row-${issue.id}`} className={`webcare-threat-row ${rowSeverityClass}`}>
                            {/* Row Index & Expand/Collapse Toggle */}
                            <td style={{ textAlign: 'center', padding: '12px 6px' }}>
                              <button
                                type="button"
                                style={{
                                  background: 'none',
                                  border: 'none',
                                  cursor: 'pointer',
                                  color: '#64748b',
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  justifyContent: 'center',
                                  padding: '4px',
                                  borderRadius: '4px'
                                }}
                                onClick={() => setExpandedLogIssue(isExpanded ? null : issue.id)}
                                title={isExpanded ? 'Collapse finding details' : 'Expand finding details'}
                              >
                                {isExpanded ? <ChevronDown size={14} color="#3b82f6" /> : <ChevronRight size={14} />}
                                <span style={{ fontSize: '11px', fontWeight: 600, marginLeft: '2px', color: '#94a3b8' }}>
                                  {absoluteIndex}
                                </span>
                              </button>
                            </td>

                            {/* Severity Badge */}
                            <td>
                              <span className={`webcare-badge webcare-badge-${issue.severity || 'low'}`}>
                                {issue.severity?.toUpperCase() || 'INFO'}
                              </span>
                            </td>

                            {/* Threat / Vector */}
                            <td>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                                  <span style={{ fontWeight: 700, fontSize: '13px', wordBreak: 'break-word' }}>
                                    {getFindingDisplayTitle(issue)}
                                  </span>
                                  {isComment ? (
                                    <span className="webcare-type-badge-comment">COMMENT</span>
                                  ) : isPost ? (
                                    <span className="webcare-type-badge-post">SPAM POST</span>
                                  ) : isCronHook ? (
                                    <span className="webcare-type-badge-cron">CRON HOOK</span>
                                  ) : isHook ? (
                                    <span className="webcare-type-badge-hook">HOOK</span>
                                  ) : isUser ? (
                                    <span className="webcare-type-badge-user">USER {validUserId ? `#${validUserId}` : ''}</span>
                                  ) : isDbTable ? (
                                    <span className="webcare-type-badge-db">DB TABLE</span>
                                  ) : isDbOption ? (
                                    <span className="webcare-type-badge-option">DB OPTION</span>
                                  ) : isUpdate ? (
                                    <span className="webcare-type-badge-update">UPDATE</span>
                                  ) : isDir ? (
                                    <span className="webcare-type-badge-dir">FOLDER</span>
                                  ) : (
                                    <span className="webcare-type-badge-file">FILE</span>
                                  )}

                                  {issue.cves && issue.cves.length > 0 && (
                                    <button
                                      type="button"
                                      className="webcare-cve-badge-btn"
                                      onClick={() => setCveModal({ isOpen: true, issue })}
                                      title="Inspect official National Vulnerability Database (NVD) CVE Advisory"
                                    >
                                      <ShieldAlert size={11} />
                                      <span>
                                        {issue.cves.length === 1 ? issue.cves[0] : `${issue.cves[0]} (+${issue.cves.length - 1})`}
                                      </span>
                                    </button>
                                  )}
                                </div>
                                <span style={{ fontSize: '11px', color: '#64748b' }}>Engine: {issue.engine}</span>
                              </div>
                            </td>

                            {/* Location & Context */}
                            <td>
                              {isComment ? (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', maxWidth: '360px' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                                    <MessageSquare size={13} color="#7c3aed" style={{ flexShrink: 0 }} />
                                    <span style={{ fontWeight: 600, fontSize: '12px' }}>
                                      {issue.author_name ? `Author: ${issue.author_name}` : (issue.file_path || 'Comment')}
                                    </span>
                                    <span className="webcare-version-tag">
                                      {issue.author_id && issue.author_id > 0 ? `User ID: #${issue.author_id}` : 'Guest (ID: #0)'}
                                    </span>
                                  </div>
                                  {issue.post_title && (
                                    <div style={{ fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                      <span style={{ color: '#94a3b8' }}>on:</span>
                                      {issue.post_url ? (
                                        <a href={issue.post_url} target="_blank" rel="noopener noreferrer" className="webcare-link-subtle" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                          {issue.post_title} <ArrowUpRight size={10} />
                                        </a>
                                      ) : (
                                        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{issue.post_title}</span>
                                      )}
                                    </div>
                                  )}
                                </div>
                              ) : isPost ? (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', maxWidth: '340px' }}>
                                  <div style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <FileText size={14} color="#6366f1" style={{ flexShrink: 0 }} />
                                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={issue.post_title || issue.file_path}>
                                      {issue.post_title || issue.file_path}
                                    </span>
                                  </div>
                                  {issue.view_url && (
                                    <a
                                      href={issue.view_url}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="webcare-link-subtle"
                                      style={{ fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px' }}
                                    >
                                      <Globe size={11} color="#0ea5e9" />
                                      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{issue.view_url}</span>
                                      <ArrowUpRight size={11} />
                                    </a>
                                  )}
                                </div>
                              ) : isUser ? (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', maxWidth: '360px' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                                    <User size={13} color="#15803d" style={{ flexShrink: 0 }} />
                                    <span style={{ fontWeight: 600, fontSize: '12px' }}>
                                      {issue.user_display_name || issue.user_login || issue.file_path}
                                    </span>
                                    {issue.user_id && (
                                      <span className="webcare-version-tag">
                                        ID: #{issue.user_id}
                                      </span>
                                    )}
                                    {isCurrentUser && (
                                      <span className="webcare-component-status-tag is-active">
                                        YOU (LOGGED IN)
                                      </span>
                                    )}
                                    {issue.user_roles && (
                                      <span className="webcare-version-tag" style={{ textTransform: 'uppercase' }}>
                                        {issue.user_roles}
                                      </span>
                                    )}
                                  </div>
                                  {issue.user_email && (
                                    <div style={{ fontSize: '11px', color: '#64748b' }}>
                                      Email: {issue.user_email}
                                    </div>
                                  )}
                                </div>
                              ) : issue.is_dir || issue.component_meta ? (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', maxWidth: '380px' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                                    <Folder size={13} color="#64748b" style={{ flexShrink: 0 }} />
                                    <span style={{ fontWeight: 600, fontSize: '13px' }}>
                                      {issue.component_name || issue.component_meta?.name || issue.file_path?.split(/[/|\\]/).filter(Boolean).pop()}
                                    </span>
                                    {(issue.installed_version || issue.component_meta?.version) && (
                                      <span className="webcare-version-tag">
                                        v{issue.installed_version || issue.component_meta?.version}
                                      </span>
                                    )}
                                    {issue.component_meta?.status_label && (
                                      <span className={`webcare-component-status-tag ${issue.component_meta?.is_active ? 'is-active' : 'is-inactive'}`}>
                                        {issue.component_meta?.status_label}
                                      </span>
                                    )}
                                  </div>
                                  <div style={{ fontFamily: 'monospace', fontSize: '11px', color: '#64748b', wordBreak: 'break-all' }}>
                                    {issue.file_path}
                                  </div>
                                </div>
                              ) : isUpdate ? (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                                  <div style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <Layers size={14} color="#0284c7" style={{ flexShrink: 0 }} />
                                    <span>{issue.component_name || issue.file_path}</span>
                                  </div>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '11px', color: '#64748b' }}>
                                    <span>Installed: <strong>{issue.installed_version || 'v?'}</strong></span>
                                    {issue.latest_version && (
                                      <span>Available: <strong style={{ color: '#16a34a' }}>{issue.latest_version}</strong></span>
                                    )}
                                  </div>
                                </div>
                              ) : isDbTable ? (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', maxWidth: '380px' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                                    <Database size={13} color="#7e22ce" style={{ flexShrink: 0 }} />
                                    <span style={{ fontWeight: 600, fontSize: '12px', fontFamily: 'monospace' }}>
                                      {isParsedDb?.tableName || issue.table_name || (issue.file_path ? issue.file_path.split('.')[0] : 'Table')}
                                    </span>
                                    {(isParsedDb?.columnName || issue.column_name) && (
                                      <span className="webcare-version-tag">
                                        .{isParsedDb?.columnName || issue.column_name}
                                      </span>
                                    )}
                                    {(isParsedDb?.rowId || issue.row_id) && (
                                      <span className="webcare-version-tag">
                                        Row #{isParsedDb?.rowId || issue.row_id}
                                      </span>
                                    )}
                                  </div>
                                </div>
                              ) : (
                                <div className="webcare-path-pill">
                                  <span>{issue.file_path}</span>
                                  {issue.line_number ? (
                                    <span style={{ color: '#0284c7', fontWeight: 700, fontSize: '11px' }}>
                                      :{issue.line_number}
                                    </span>
                                  ) : null}
                                  {issue.file_path && (
                                    <button
                                      type="button"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        copyToClipboard(issue.file_path);
                                      }}
                                      style={{ background: 'none', border: 'none', padding: '2px', cursor: 'pointer', display: 'inline-flex', alignItems: 'center' }}
                                      title="Copy file path"
                                    >
                                      {copiedIssuePath === issue.file_path ? <Check size={12} color="#16a34a" /> : <Copy size={12} />}
                                    </button>
                                  )}
                                </div>
                              )}
                              <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px', lineHeight: 1.4 }}>
                                {issue.description}
                              </div>
                            </td>

                            {/* Status Badge */}
                            <td>
                              <span className={`webcare-status-chip webcare-status-chip-${issue.status || 'open'}`}>
                                {(!issue.status || issue.status === 'open') && <span className="webcare-pulse-dot webcare-pulse-dot-red" />}
                                {issue.status === 'quarantined' && <Archive size={11} />}
                                {issue.status === 'repaired' && <Check size={11} />}
                                {issue.status === 'ignored' && <ShieldCheck size={11} />}
                                <span>{issue.status === 'repaired' ? 'SOLVED' : (issue.status || 'open').toUpperCase()}</span>
                              </span>
                            </td>

                            {/* MITIGATION & ACTIONS COLUMN */}
                            <td style={{ textAlign: 'right' }}>
                              <div style={{ display: 'inline-flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                                {issue.status === 'repaired' ? (
                                  <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
                                    <span
                                      style={{
                                        display: 'inline-flex',
                                        alignItems: 'center',
                                        gap: '5px',
                                        background: '#ecfdf5',
                                        color: '#059669',
                                        border: '1px solid #a7f3d0',
                                        padding: '5px 12px',
                                        borderRadius: '6px',
                                        fontSize: '12px',
                                        fontWeight: 700,
                                      }}
                                    >
                                      <CheckCircle2 size={13} color="#10b981" />
                                      <span>Issue Solved & Restored</span>
                                    </span>
                                    <button
                                      type="button"
                                      className="webcare-btn-ignore-alt"
                                      style={{ fontSize: '11px', padding: '3px 8px' }}
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        handleUpdateIssue(issue.id, 'open');
                                      }}
                                      title="Reopen finding if needed"
                                    >
                                      Reopen
                                    </button>
                                  </div>
                                ) : issue.status === 'ignored' || Boolean(issue.is_whitelisted) ? (
                                  <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
                                    <span
                                      style={{
                                        display: 'inline-flex',
                                        alignItems: 'center',
                                        gap: '5px',
                                        background: '#f0fdf4',
                                        color: '#15803d',
                                        border: '1px solid #bbf7d0',
                                        padding: '5px 10px',
                                        borderRadius: '6px',
                                        fontSize: '11px',
                                        fontWeight: 700,
                                      }}
                                    >
                                      <ShieldCheck size={12} color="#16a34a" />
                                      <span>Whitelisted & Ignored</span>
                                    </span>
                                    <button
                                      type="button"
                                      className="webcare-btn-ignore-alt"
                                      style={{ fontSize: '11px', padding: '3px 8px' }}
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        handleUpdateIssue(issue.id, 'open');
                                      }}
                                      title="Remove from whitelist and reopen"
                                    >
                                      Reopen
                                    </button>
                                  </div>
                                ) : (
                                  <Fragment>
                                    {/* Visual Code Diff (FIM) */}
                                    {isFimEligible && (
                                      <button
                                        type="button"
                                        className="webcare-btn-diff"
                                        onClick={() => {
                                          setVisualDiffModal({
                                            isOpen: true,
                                            filePath: issue.file_path,
                                            issueId: issue.id,
                                          });
                                        }}
                                        title="Compare this file against official WordPress.org release code diff"
                                      >
                                        <FileCode size={13} /> Visual Code Diff (FIM)
                                      </button>
                                    )}

                                    {/* WP_DEBUG 1-Click Disable */}
                                    {(issue.type === 'wp_debug_enabled' || (Boolean(issue.file_path && issue.file_path.endsWith('wp-config.php')) && (issue.type?.includes('debug') || issue.description?.includes('WP_DEBUG')))) && handleDisableWpDebug && (
                                      <button
                                        type="button"
                                        className="webcare-btn"
                                        style={{ background: '#ecfdf5', color: '#047857', border: '1px solid #6ee7b7', fontSize: '11px', padding: '4px 9px', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                        onClick={() => handleDisableWpDebug(issue)}
                                        title="1-Click Fix: Intelligently comment out debugging and disable WP_DEBUG in wp-config.php"
                                      >
                                        <ShieldCheck size={12} color="#059669" /> Disable Debugging
                                      </button>
                                    )}

                                                                        {/* Unsafe Permissions 1-Click Fix */}
                                    {issue.type === 'unsafe_permissions' && (
                                      <button
                                        type="button"
                                        className="webcare-btn"
                                        style={{ background: '#ecfdf5', color: '#047857', border: '1px solid #6ee7b7', fontSize: '11px', padding: '4px 9px', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                        onClick={() => handleFixPermissions(issue)}
                                        title="1-Click Fix: Harden permissions immediately to safe 0644"
                                      >
                                        <ShieldCheck size={12} color="#059669" /> Fix Permissions
                                      </button>
                                    )}

                                    {/* View Full File Modal */}
                                    {isPhysicalFile && issue.can_view !== false && (
                                      <button
                                        type="button"
                                        className="webcare-btn-view-file-alt"
                                        onClick={() => handleOpenFileViewer(issue)}
                                        title="View complete source code in popup window with threat highlight"
                                      >
                                        <Eye size={13} /> View File
                                      </button>
                                    )}

                                    {/* Comment Moderation Actions */}
                                    {isComment && (
                                      <Fragment>
                                        {issue.edit_url && (
                                          <a
                                            href={issue.edit_url}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="webcare-btn"
                                            style={{ padding: '4px 8px', fontSize: '11px', fontWeight: 600 }}
                                          >
                                            <Edit3 size={11} /> Edit
                                          </a>
                                        )}
                                        <button
                                          type="button"
                                          className="webcare-btn"
                                          style={{ background: '#fffbeb', color: '#b45309', border: '1px solid #fde68a', fontSize: '11px', padding: '4px 8px', fontWeight: 600 }}
                                          onClick={() => handleModerateComment(issue, 'trash')}
                                          title="Move comment to WordPress Trash"
                                        >
                                          <Trash2 size={11} /> Trash
                                        </button>
                                        <button
                                          type="button"
                                          className="webcare-btn"
                                          style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fca5a5', fontSize: '11px', padding: '4px 8px', fontWeight: 600 }}
                                          onClick={() => handleModerateComment(issue, 'delete')}
                                          title="Permanently delete comment record"
                                        >
                                          <XCircle size={11} /> Delete
                                        </button>
                                      </Fragment>
                                    )}

                                    {/* Inspect Post Database Content */}
                                    {isPost && (
                                      <Fragment>
                                        {issue.edit_url && (
                                          <a
                                            href={issue.edit_url}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="webcare-btn webcare-btn-edit-post"
                                            title="Open WordPress editor in a new tab"
                                          >
                                            <Edit3 size={11} /> Edit
                                          </a>
                                        )}
                                        <button
                                          type="button"
                                          className="webcare-btn webcare-btn-view-preview"
                                          onClick={() => handleOpenPostViewer(issue)}
                                          title="Inspect post database content"
                                        >
                                          <FileText size={13} /> Inspect
                                        </button>
                                      </Fragment>
                                    )}

                                    {/* User Remediation Actions */}
                                    {isUser && (() => {
                                      if (isCurrentUser) {
                                        return (
                                          <a
                                            href={issue.password_url || 'profile.php#password'}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="webcare-btn"
                                            style={{ background: '#fef2f2', color: '#b91c1c', border: '1px solid #fecaca', fontSize: '11px', padding: '4px 9px', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                            title="Change your administrator password in your profile"
                                          >
                                            <Key size={11} color="#dc2626" /> Change Your Password
                                          </a>
                                        );
                                      }

                                      if (isWeakPassword) {
                                        return (
                                          <a
                                            href={issue.password_url || (issue.edit_url ? `${issue.edit_url}#password` : (validUserId ? `user-edit.php?user_id=${validUserId}#password` : 'users.php'))}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="webcare-btn"
                                            style={{ background: '#fef2f2', color: '#b91c1c', border: '1px solid #fecaca', fontSize: '11px', padding: '4px 9px', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                            title="Change user password"
                                          >
                                            <Key size={11} color="#dc2626" /> Change Password
                                          </a>
                                        );
                                      }

                                      if (issue.type === 'user_missing_capabilities' || issue.type === 'suspicious_user_capabilities') {
                                        return (
                                          <Fragment>
                                            <button
                                              type="button"
                                              className="webcare-btn"
                                              style={{ background: '#fffbeb', color: '#b45309', border: '1px solid #fde68a', fontSize: '11px', padding: '4px 8px', fontWeight: 600 }}
                                              onClick={() => handleRemediateUser(issue, 'assign_default_role', 'subscriber')}
                                              title="Reset role to standard Subscriber"
                                            >
                                              <UserCheck size={11} /> Demote to Subscriber
                                            </button>
                                            <button
                                              type="button"
                                              className="webcare-btn"
                                              style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fca5a5', fontSize: '11px', padding: '4px 8px', fontWeight: 600 }}
                                              onClick={() => handleRemediateUser(issue, 'delete_user')}
                                              title="Safely delete user account"
                                            >
                                              <Trash2 size={11} /> Delete User
                                            </button>
                                          </Fragment>
                                        );
                                      }

                                      return null;
                                    })()}

                                    {/* User Profile Link */}
                                    {isUser && (
                                      <a
                                        href={isCurrentUser ? (issue.profile_url || 'profile.php') : (issue.edit_url || (validUserId ? `user-edit.php?user_id=${validUserId}` : 'users.php'))}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="webcare-btn"
                                        style={{ padding: '4px 8px', fontSize: '11px', fontWeight: 600 }}
                                        title={isCurrentUser ? "Open your WordPress Profile in a new tab" : "Open WordPress User Profile editor in a new tab"}
                                      >
                                        <Edit3 size={11} /> {isCurrentUser ? 'My Profile' : 'Edit Profile'}
                                      </a>
                                    )}

                                    {/* Software Update Action */}
                                    {isUpdate && issue.update_url && (
                                      <a
                                        href={issue.update_url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="webcare-btn-update-software"
                                        title="Open WordPress update page in new tab"
                                      >
                                        <RefreshCw size={12} /> Update Now <ArrowUpRight size={11} />
                                      </a>
                                    )}

                                    {/* Component Changelog */}
                                    {(issue.is_dir || issue.component_meta || issue.engine === 'integrity-theme' || issue.engine === 'integrity-plugin') && (
                                      <button
                                        type="button"
                                        className="webcare-btn"
                                        style={{ background: '#f0f9ff', color: '#0369a1', border: '1px solid #bae6fd', fontSize: '11px', padding: '4px 8px', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                        onClick={() => handleOpenChangelog(issue)}
                                        title="Read component release notes and changelog history in modal"
                                      >
                                        <BookOpen size={11} color="#0284c7" /> Changelog
                                      </button>
                                    )}

                                    {/* Quarantine File Action */}
                                    {canQuarantineIssue(issue) && (
                                      <button
                                        type="button"
                                        className="webcare-btn-quarantine-alt"
                                        onClick={() => handleQuarantine(issue)}
                                        title="Safely isolate this file in protected quarantine vault"
                                      >
                                        <Archive size={13} /> Quarantine
                                      </button>
                                    )}

                                    {/* Database Record Actions */}
                                    {isDbTable && (
                                      <Fragment>
                                        <button
                                          type="button"
                                          className="webcare-btn"
                                          style={{ background: '#f5f3ff', color: '#6d28d9', border: '1px solid #ddd6fe', fontSize: '11px', padding: '4px 9px', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                          onClick={() => handleOpenDbInspector(issue)}
                                          title="Inspect complete database row data and columns"
                                        >
                                          <FileText size={12} /> Inspect Row
                                        </button>
                                        <button
                                          type="button"
                                          className="webcare-btn"
                                          style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fecaca', fontSize: '11px', padding: '4px 9px', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                          onClick={() => handleRemediateDbRow(issue, 'delete_row')}
                                          title="Safely backup to Quarantine Vault and delete this infected row from database"
                                        >
                                          <Trash2 size={12} /> Delete Row
                                        </button>
                                      </Fragment>
                                    )}

                                    {/* Delete Cron Hook Action */}
                                    {isCronHook && (
                                      <button
                                        type="button"
                                        className="webcare-btn-quarantine-alt"
                                        style={{ background: '#fef2f2', color: '#dc2626', borderColor: '#fca5a5' }}
                                        onClick={() => handleDeleteCronHook(issue)}
                                        title="Delete and unschedule this cron hook from WordPress database"
                                      >
                                        <Trash2 size={13} /> Delete Hook
                                      </button>
                                    )}

                                    {/* Whitelist / Mark Safe / Ignore Action */}
                                    <button
                                      type="button"
                                      className="webcare-btn-ignore-alt"
                                      style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', borderColor: '#a7f3d0', background: '#f0fdf4', color: '#047857', fontWeight: 600 }}
                                      onClick={() => setWhitelistModal({ isOpen: true, issue })}
                                      title="Whitelist finding with 1-click cryptographic SHA-256 hash-lock & auto-expiration"
                                    >
                                      <ShieldCheck size={12} color="#059669" /> Mark Safe / Ignore
                                    </button>
                                  </Fragment>
                                )}
                              </div>
                            </td>
                          </tr>

                          {/* Expandable Finding Detail Row */}
                          {isExpanded && (
                            <tr key={`log-expanded-${issue.id}`} className="webcare-threat-expanded-row">
                              <td></td>
                              <td colSpan={5} style={{ padding: '14px 20px', background: 'transparent' }}>
                                <FindingForensicsDrawer
                                  issue={issue}
                                  onOpenFileViewer={handleOpenFileViewer}
                                  onOpenChangelog={handleOpenChangelog}
                                  onOpenPostViewer={handleOpenPostViewer}
                                  onOpenDbInspector={handleOpenDbInspector}
                                  onRemediateDbRow={handleRemediateDbRow}
                                  onDeleteCronHook={handleDeleteCronHook}
                                  onRemediateUser={handleRemediateUser}
                                  onDisableWpDebug={handleDisableWpDebug}
                                  onCopyPath={copyToClipboard}
                                  copiedPath={copiedIssuePath}
                                />
                              </td>
                            </tr>
                          )}
                        </Fragment>
                      );
                    })
                  )}
                </tbody>
              </table>

              {/* Findings Pagination Controls Bar */}
              {totalFindingsCount > 0 && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '12px 18px',
                    borderTop: '1px solid var(--webcare-border, #e2e8f0)',
                    background: 'var(--webcare-bg-surface, #f8fafc)',
                    borderBottomLeftRadius: '8px',
                    borderBottomRightRadius: '8px',
                    flexWrap: 'wrap',
                    gap: '12px',
                    fontSize: '12px'
                  }}
                >
                  <div style={{ color: 'var(--webcare-text-muted, #64748b)' }}>
                    Showing findings <strong>{(findingsPage - 1) * findingsPageSize + 1}</strong> &ndash; <strong>{Math.min(totalFindingsCount, findingsPage * findingsPageSize)}</strong> of <strong>{totalFindingsCount.toLocaleString()}</strong> total threats
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <button
                      type="button"
                      className="webcare-btn-micro"
                      disabled={findingsPage <= 1}
                      onClick={() => {
                        setFindingsPage(prev => Math.max(1, prev - 1));
                        const el = document.getElementById('webcare-scan-log-inspector');
                        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
                      }}
                      style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', cursor: findingsPage <= 1 ? 'not-allowed' : 'pointer' }}
                    >
                      <ChevronLeft size={14} /> Previous
                    </button>

                    <span style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', padding: '0 6px', fontWeight: 600 }}>
                      Page {findingsPage} of {totalFindingsPages}
                    </span>

                    <button
                      type="button"
                      className="webcare-btn-micro"
                      disabled={findingsPage >= totalFindingsPages}
                      onClick={() => {
                        setFindingsPage(prev => Math.min(totalFindingsPages, prev + 1));
                        const el = document.getElementById('webcare-scan-log-inspector');
                        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
                      }}
                      style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', cursor: findingsPage >= totalFindingsPages ? 'not-allowed' : 'pointer' }}
                    >
                      Next <ChevronRight size={14} />
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Scan History Export Modal */}
      {isHistoryExportModalOpen && (
        <div
          className="webcare-modal-backdrop"
          onClick={() => !isExportingHistory && setIsHistoryExportModalOpen(false)}
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.65)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 999999,
            padding: '20px',
          }}
        >
          <div
            className="webcare-modal-card"
            onClick={(e) => e.stopPropagation()}
            style={{
              background: 'var(--webcare-bg-panel, #ffffff)',
              border: '1px solid var(--webcare-border, #e2e8f0)',
              borderRadius: '12px',
              maxWidth: '520px',
              width: '100%',
              boxShadow: '0 20px 40px rgba(0, 0, 0, 0.35)',
              overflow: 'hidden',
              animation: 'webcareModalIn 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
            }}
          >
            {/* Modal Header */}
            <div
              style={{
                padding: '18px 24px',
                borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div
                  style={{
                    width: '36px',
                    height: '36px',
                    borderRadius: '8px',
                    background: 'rgba(79, 70, 229, 0.1)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#4f46e5',
                  }}
                >
                  <Download size={20} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                    Export Scan History Ledger
                  </h3>
                  <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    Download historical security audit records with domain stamping
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => !isExportingHistory && setIsHistoryExportModalOpen(false)}
                disabled={isExportingHistory}
                style={{
                  background: 'transparent',
                  border: 'none',
                  cursor: isExportingHistory ? 'not-allowed' : 'pointer',
                  color: 'var(--webcare-text-muted, #64748b)',
                  padding: '4px',
                }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ padding: '22px 24px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
              {/* Scope Selection */}
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '8px' }}>
                  Select History Scope
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '8px' }}>
                  <label
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '10px',
                      padding: '10px 14px',
                      borderRadius: '8px',
                      border: `1px solid ${historyExportScope === 'all' ? '#4f46e5' : 'var(--webcare-border, #e2e8f0)'}`,
                      background: historyExportScope === 'all' ? 'rgba(79, 70, 229, 0.05)' : 'transparent',
                      cursor: 'pointer',
                    }}
                  >
                    <input
                      type="radio"
                      name="scanHistoryExportScope"
                      checked={historyExportScope === 'all'}
                      onChange={() => setHistoryExportScope('all')}
                      style={{ accentColor: '#4f46e5' }}
                    />
                    <div>
                      <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                        All Scan Runs ({scanHistory.length} audits)
                      </div>
                      <div style={{ fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                        Complete historical ledger of all manual and scheduled security audits
                      </div>
                    </div>
                  </label>

                  <label
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '10px',
                      padding: '10px 14px',
                      borderRadius: '8px',
                      border: `1px solid ${historyExportScope === 'date' ? '#4f46e5' : 'var(--webcare-border, #e2e8f0)'}`,
                      background: historyExportScope === 'date' ? 'rgba(79, 70, 229, 0.05)' : 'transparent',
                      cursor: 'pointer',
                    }}
                  >
                    <input
                      type="radio"
                      name="scanHistoryExportScope"
                      checked={historyExportScope === 'date'}
                      onChange={() => setHistoryExportScope('date')}
                      style={{ accentColor: '#4f46e5' }}
                    />
                    <div>
                      <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                        Specific Date Audits
                      </div>
                      <div style={{ fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                        Export only security scans initiated on a chosen date
                      </div>
                    </div>
                  </label>
                </div>
              </div>

              {/* Date Input */}
              {historyExportScope === 'date' && (
                <div style={{ padding: '12px 14px', background: 'var(--webcare-bg-surface-elevated, #f8fafc)', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '6px' }}>
                    Choose Date (YYYY-MM-DD):
                  </label>
                  <input
                    type="date"
                    value={historyExportDate}
                    onChange={(e) => setHistoryExportDate(e.target.value)}
                    className="webcare-input"
                    style={{ width: '100%', fontSize: '13px', padding: '7px 12px' }}
                  />
                </div>
              )}

              {/* Format Selection */}
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '8px' }}>
                  Download Format
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                  <button
                    type="button"
                    onClick={() => setHistoryExportFormat('json')}
                    style={{
                      padding: '12px',
                      borderRadius: '8px',
                      border: `2px solid ${historyExportFormat === 'json' ? '#4f46e5' : 'var(--webcare-border, #e2e8f0)'}`,
                      background: historyExportFormat === 'json' ? 'rgba(79, 70, 229, 0.05)' : 'transparent',
                      cursor: 'pointer',
                      textAlign: 'left',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                      <FileCode size={16} color="#3b82f6" />
                      <span>JSON (.json)</span>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                      Raw JSON audit run ledger
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() => setHistoryExportFormat('csv')}
                    style={{
                      padding: '12px',
                      borderRadius: '8px',
                      border: `2px solid ${historyExportFormat === 'csv' ? '#4f46e5' : 'var(--webcare-border, #e2e8f0)'}`,
                      background: historyExportFormat === 'csv' ? 'rgba(79, 70, 229, 0.05)' : 'transparent',
                      cursor: 'pointer',
                      textAlign: 'left',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                      <FileText size={16} color="#10b981" />
                      <span>CSV (.csv)</span>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                      Spreadsheet &amp; Microsoft Excel compatible
                    </div>
                  </button>
                </div>
              </div>

              {/* Filename Preview Info Box */}
              <div
                style={{
                  padding: '10px 14px',
                  borderRadius: '8px',
                  background: 'var(--webcare-bg-surface-elevated, #f8fafc)',
                  border: '1px solid var(--webcare-border, #e2e8f0)',
                  fontSize: '11.5px',
                  color: 'var(--webcare-text-muted, #64748b)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                }}
              >
                <Info size={15} style={{ flexShrink: 0, color: '#4f46e5' }} />
                <span>
                  Log file will be stamped with site domain: <code>scan-history-{historyExportScope === 'date' ? historyExportDate : new Date().toISOString().slice(0, 10)}-[time]-[domain]-[hash].{historyExportFormat}</code>
                </span>
              </div>
            </div>

            {/* Modal Footer */}
            <div
              style={{
                padding: '14px 24px',
                borderTop: '1px solid var(--webcare-border, #e2e8f0)',
                background: 'var(--webcare-bg-surface-elevated, #f8fafc)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'flex-end',
                gap: '10px',
              }}
            >
              <button
                type="button"
                onClick={() => setIsHistoryExportModalOpen(false)}
                disabled={isExportingHistory}
                className="webcare-btn webcare-btn-secondary"
                style={{ padding: '8px 16px', fontSize: '13px', fontWeight: 600 }}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={executeHistoryExport}
                disabled={isExportingHistory}
                className="webcare-btn webcare-btn-primary"
                style={{
                  padding: '8px 20px',
                  fontSize: '13px',
                  fontWeight: 600,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  background: '#4f46e5',
                  color: '#ffffff',
                }}
              >
                {isExportingHistory ? <RefreshCw size={14} className="webcare-spin-icon" /> : <Download size={14} />}
                <span>{isExportingHistory ? 'Generating Export...' : `Download ${historyExportFormat.toUpperCase()}`}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Helper SVG Icon for Files
function FilesIcon({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M15.5 2H8.6c-.4 0-.8.2-1.1.5-.3.3-.5.7-.5 1.1V17" />
      <path d="M4 8.5v11c0 .4.2.8.5 1.1.3.3.7.5 1.1.5h10.8c.4 0 .8-.2 1.1-.5.3-.3.5-.7.5-1.1V8.5L13.5 4H5.6c-.4 0-.8.2-1.1.5-.3.3-.5.7-.5 1.1z" />
    </svg>
  );
}
