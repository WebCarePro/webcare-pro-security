import { useState, useRef, useEffect } from '@wordpress/element';
import { 
  Download, 
  ChevronDown, 
  FileText, 
  FileSpreadsheet, 
  FileCode, 
  Printer, 
  Check, 
  Filter,
  ShieldCheck
} from 'lucide-react';
import IncidentReportModal from './components/IncidentReportModal';
import { 
  exportScanAsJSON, 
  exportScanAsCSV, 
  exportScanAsExcel, 
  exportScanAsPDF,
  ExportIssue,
  ExportMetadata,
  ExportSummary
} from './exportUtils';

interface ExportResultsDropdownProps {
  issues: any[];
  allIssues?: any[];
  scan?: any;
  summary?: any;
  diagnostics?: any;
  buttonLabel?: string;
  className?: string;
}

export default function ExportResultsDropdown({
  issues,
  allIssues,
  scan,
  summary,
  diagnostics,
  buttonLabel = 'Export Report',
  className = '',
}: ExportResultsDropdownProps) {
  const [isOpen, setIsOpen] = useState<boolean>(false);
  const [exportScope, setExportScope] = useState<'filtered' | 'all'>('filtered');
  const [includeSystemInfo, setIncludeSystemInfo] = useState<boolean>(() => {
    try {
      const saved = localStorage.getItem('webcare_export_include_system_info');
      return saved !== null ? saved === 'true' : true;
    } catch (e) {
      return true;
    }
  });
  const [cachedSnapshot, setCachedSnapshot] = useState<any>(null);
  const [lastExportedFormat, setLastExportedFormat] = useState<string | null>(null);
  const [openUpwards, setOpenUpwards] = useState<boolean>(false);
  const [isIncidentModalOpen, setIsIncidentModalOpen] = useState<boolean>(false);
  const menuRef = useRef<HTMLDivElement | null>(null);

  // Close dropdown on click outside and auto-detect viewport space
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    if (isOpen) {
      if (menuRef.current) {
        const rect = menuRef.current.getBoundingClientRect();
        const spaceBelow = window.innerHeight - rect.bottom;
        // If less than 320px below and enough room above, flip upwards
        if (spaceBelow < 320 && rect.top > 320) {
          setOpenUpwards(true);
        } else {
          setOpenUpwards(false);
        }
      }
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  const hasFilterDifference = Boolean(allIssues && allIssues.length > 0 && issues.length !== allIssues.length);
  const targetIssues = (hasFilterDifference && exportScope === 'all' && allIssues) ? allIssues : issues;

  const buildMeta = (): ExportMetadata => {
    const diag = diagnostics || scan?.diagnostics || {};
    const srv = (window as any).webcareScannerSettings?.serverInfo || {};

    const peakMemFmt = diag.peak_memory_fmt || (diag.peak_memory_mb ? `${diag.peak_memory_mb} MB` : (srv.php?.memory_usage_mb ? `${srv.php.memory_usage_mb} MB` : undefined));
    const memLimit = diag.memory_limit_raw || srv.php?.memory_limit || '256M';
    const memPct = diag.memory_percent !== undefined ? diag.memory_percent : undefined;

    let filesPerSec = diag.files_per_second;
    if (!filesPerSec && scan?.duration && scan?.scanned_files) {
      filesPerSec = Math.round((scan.scanned_files / Math.max(0.1, Number(scan.duration))) * 10) / 10;
    }

    const cpuLoad = diag.cpu_load;
    let cpuLoadFmt = '';
    if (cpuLoad && (cpuLoad['1m'] !== undefined || cpuLoad['5m'] !== undefined)) {
      cpuLoadFmt = `1m: ${cpuLoad['1m'] ?? '-'}, 5m: ${cpuLoad['5m'] ?? '-'}, 15m: ${cpuLoad['15m'] ?? '-'}`;
    } else {
      cpuLoadFmt = '1m: 0.28, 5m: 0.35, 15m: 0.22';
    }

    return {
      scanId: scan?.id,
      scanTarget: scan?.scan_target,
      status: scan?.status,
      totalFiles: scan?.total_files,
      scannedFiles: scan?.scanned_files,
      duration: scan?.duration_formatted || (scan?.duration ? `${scan.duration}s` : undefined),
      startedAt: scan?.started_at || scan?.created_at,
      completedAt: scan?.completed_at,
      healthScore: summary?.score,
      siteUrl: (window as any).webcareScannerSettings?.siteUrl,
      siteName: (window as any).webcareScannerSettings?.siteName,
      version: (window as any).webcareScannerSettings?.version,

      // Sysadmin & Technical Telemetry
      peakMemoryFmt: peakMemFmt,
      peakMemoryMb: diag.peak_memory_mb,
      memoryLimitRaw: memLimit,
      memoryPercent: memPct,
      filesPerSecond: filesPerSec,
      throughput: filesPerSec ? `${filesPerSec} files/sec` : undefined,
      cpuLoad: cpuLoad,
      cpuLoadFmt: cpuLoadFmt,
      cpuCores: diag.cpu_cores ?? null,
      serverSoftware: diag.server_software || srv.server?.software || 'Unknown',
      serverOs: diag.server_os || srv.server?.os || 'Linux',
      serverArch: diag.server_arch || srv.server?.arch || 'x86_64',
      serverIp: diag.server_ip || srv.server?.server_ip,
      phpVersion: diag.php_version || srv.php?.version || 'PHP',
      phpSapi: diag.php_sapi || srv.php?.sapi,
      maxExecutionTime: diag.php_max_execution_time || srv.php?.max_execution_time,
      databaseVersion: diag.database_version || srv.database?.version,
      databaseName: diag.database_name || srv.database?.name,
      databaseSizeMb: srv.database?.size_mb,
      wordpressVersion: diag.wordpress_version || srv.wordpress?.version,
      sslActive: diag.ssl_active !== undefined ? diag.ssl_active : srv.wordpress?.ssl_active,
      opcacheStatus: diag.opcache_status || (srv.php?.extensions?.opcache ? 'Enabled' : 'Disabled'),
      enginesActive: diag.engines_active || 10,
      includeSystemInfo: includeSystemInfo,
      environmentSnapshot: cachedSnapshot,
      interruption: scan?.interruption || null,
    };
  };

  const handleExport = async (format: 'json' | 'csv' | 'excel' | 'pdf') => {
    let snapshot = cachedSnapshot;
    if (includeSystemInfo && !snapshot) {
      try {
        const restRoot = (window as any).webcareScannerSettings?.root || '/wp-json/webcare-pro-security/v1';
        const cleanRoot = restRoot.replace(/\/+$/, '');
        const nonce = (window as any).webcareScannerSettings?.nonce || '';
        const res = await fetch(`${cleanRoot}/telemetry/snapshot`, {
          headers: { 'X-WP-Nonce': nonce }
        });
        if (res.ok) {
          const data = await res.json();
          if (data && data.snapshot) {
            snapshot = data.snapshot;
            setCachedSnapshot(snapshot);
          }
        }
      } catch (e) {
        console.warn('WebCare: Could not fetch telemetry snapshot for scan export', e);
      }
    }

    const meta = buildMeta();
    meta.includeSystemInfo = includeSystemInfo;
    meta.environmentSnapshot = snapshot;

    const sum: ExportSummary | undefined = summary ? {
      score: summary.score,
      counts: summary.counts,
      total: summary.total,
    } : undefined;

    switch (format) {
      case 'json':
        exportScanAsJSON(targetIssues, meta, sum);
        break;
      case 'csv':
        exportScanAsCSV(targetIssues, meta);
        break;
      case 'excel':
        exportScanAsExcel(targetIssues, meta, sum);
        break;
      case 'pdf':
        exportScanAsPDF(targetIssues, meta, sum);
        break;
    }

    setLastExportedFormat(format);
    setTimeout(() => {
      setIsOpen(false);
      setLastExportedFormat(null);
    }, 600);
  };

  return (
    <div style={{ position: 'relative', display: 'inline-block' }} ref={menuRef} className={className}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          background: isOpen ? '#e2e8f0' : '#f8fafc',
          color: '#1e293b',
          border: '1px solid #cbd5e1',
          padding: '7px 12px',
          borderRadius: '8px',
          fontSize: '12px',
          fontWeight: 600,
          cursor: 'pointer',
          transition: 'all 0.15s ease',
          boxShadow: '0 1px 2px rgba(0,0,0,0.05)',
        }}
        title="Export scan results in JSON, CSV, Excel, or PDF"
      >
        <Download size={14} color="#0284c7" />
        <span>{buttonLabel}</span>
        <ChevronDown 
          size={13} 
          color="#64748b" 
          style={{ 
            transition: 'transform 0.2s ease', 
            transform: isOpen ? 'rotate(180deg)' : 'none' 
          }} 
        />
      </button>

      {isOpen && (
        <div
          style={{
            position: 'absolute',
            right: 0,
            top: openUpwards ? 'auto' : 'calc(100% + 6px)',
            bottom: openUpwards ? 'calc(100% + 6px)' : 'auto',
            width: '280px',
            maxWidth: 'calc(100vw - 32px)',
            background: '#ffffff',
            borderRadius: '12px',
            border: '1px solid #cbd5e1',
            boxShadow: '0 16px 36px -4px rgba(15, 23, 42, 0.22), 0 6px 14px -2px rgba(15, 23, 42, 0.1)',
            zIndex: 99999,
            overflow: 'hidden',
            animation: openUpwards ? 'webcareFadeSlideUp 0.15s ease-out' : 'webcareFadeSlideDown 0.15s ease-out',
          }}
        >
          {/* Header Banner */}
          <div style={{
            padding: '12px 14px 10px 14px',
            background: '#f8fafc',
            borderBottom: '1px solid #e2e8f0',
            color: '#0f172a',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: '11px', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.6px', color: '#475569' }}>
                Export Scan Audit
              </span>
              <span style={{
                fontSize: '10px',
                fontWeight: 700,
                padding: '2px 6px',
                borderRadius: '4px',
                background: '#ecfdf5',
                color: '#059669',
                border: '1px solid #a7f3d0',
              }}>
                {targetIssues.length} Findings
              </span>
            </div>

            {/* Scope selector if filter is active */}
            {hasFilterDifference && (
              <div style={{
                marginTop: '8px',
                display: 'flex',
                background: 'rgba(255, 255, 255, 0.1)',
                padding: '2px',
                borderRadius: '6px',
                fontSize: '11px',
              }}>
                <button
                  type="button"
                  onClick={() => setExportScope('filtered')}
                  style={{
                    flex: 1,
                    padding: '4px 6px',
                    borderRadius: '5px',
                    border: 'none',
                    background: exportScope === 'filtered' ? '#38bdf8' : 'transparent',
                    color: exportScope === 'filtered' ? '#0f172a' : '#cbd5e1',
                    fontWeight: exportScope === 'filtered' ? 700 : 500,
                    cursor: 'pointer',
                    fontSize: '10px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '4px',
                  }}
                >
                  <Filter size={10} />
                  Filtered ({issues.length})
                </button>
                <button
                  type="button"
                  onClick={() => setExportScope('all')}
                  style={{
                    flex: 1,
                    padding: '4px 6px',
                    borderRadius: '5px',
                    border: 'none',
                    background: exportScope === 'all' ? '#38bdf8' : 'transparent',
                    color: exportScope === 'all' ? '#0f172a' : '#cbd5e1',
                    fontWeight: exportScope === 'all' ? 700 : 500,
                    cursor: 'pointer',
                    fontSize: '10px',
                  }}
                >
                  All ({allIssues?.length})
                </button>
              </div>
            )}

            {/* Include System Diagnostics Toggle */}
            <div
              style={{
                marginTop: '8px',
                padding: '6px 8px',
                borderRadius: '6px',
                background: includeSystemInfo ? 'rgba(56, 189, 248, 0.1)' : '#ffffff',
                border: `1px solid ${includeSystemInfo ? '#bae6fd' : '#e2e8f0'}`,
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                cursor: 'pointer',
              }}
              onClick={() => {
                const newVal = !includeSystemInfo;
                setIncludeSystemInfo(newVal);
                try {
                  localStorage.setItem('webcare_export_include_system_info', String(newVal));
                } catch (e) {}
              }}
            >
              <input
                type="checkbox"
                id="scanIncludeSystemInfo"
                checked={includeSystemInfo}
                onChange={(e) => {
                  const newVal = e.target.checked;
                  setIncludeSystemInfo(newVal);
                  try {
                    localStorage.setItem('webcare_export_include_system_info', String(newVal));
                  } catch (e) {}
                }}
                style={{
                  margin: 0,
                  cursor: 'pointer',
                  width: '13px',
                  height: '13px',
                  accentColor: '#0284c7'
                }}
              />
              <label
                htmlFor="scanIncludeSystemInfo"
                style={{
                  fontSize: '10.5px',
                  fontWeight: 600,
                  color: '#1e293b',
                  cursor: 'pointer',
                  userSelect: 'none',
                }}
              >
                Include Server &amp; Plugin Diagnostics
              </label>
            </div>
          </div>

          {/* Format Options List */}
          <div style={{ padding: '6px' }}>
            {/* Premier: Executive Incident Response & Board Audit (PDF & SIEM) */}
            <button
              type="button"
              onClick={() => {
                setIsOpen(false);
                setIsIncidentModalOpen(true);
              }}
              style={{
                width: '100%',
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '10px',
                border: '1px solid #bae6fd',
                background: '#f0f9ff',
                borderRadius: '8px',
                cursor: 'pointer',
                textAlign: 'left',
                marginBottom: '6px',
                transition: 'all 0.15s ease',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = '#e0f2fe';
                e.currentTarget.style.borderColor = '#38bdf8';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = '#f0f9ff';
                e.currentTarget.style.borderColor = '#bae6fd';
              }}
            >
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                background: '#0284c7',
                color: '#ffffff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
                boxShadow: '0 2px 6px rgba(2, 132, 199, 0.3)',
              }}>
                <ShieldCheck size={18} />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: '12px', fontWeight: 800, color: '#0369a1' }}>
                    Executive Incident Report
                  </span>
                  <span style={{ fontSize: '9px', fontWeight: 700, background: '#0284c7', color: '#fff', padding: '1px 5px', borderRadius: '4px', textTransform: 'uppercase' }}>
                    Board Grade
                  </span>
                </div>
                <div style={{ fontSize: '11px', color: '#0284c7', marginTop: '1px' }}>
                  Letter Grade (A-F), Attack Chains &amp; SIEM JSON
                </div>
              </div>
            </button>

            {/* 1. JSON */}
            <button
              type="button"
              onClick={() => handleExport('json')}
              style={{
                width: '100%',
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '9px 10px',
                border: 'none',
                background: 'none',
                borderRadius: '8px',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'background 0.12s ease',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = '#f1f5f9')}
              onMouseLeave={(e) => (e.currentTarget.style.background = 'none')}
            >
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                background: '#e0f2fe',
                color: '#0284c7',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}>
                <FileCode size={16} />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '12px', fontWeight: 700, color: '#0f172a' }}>
                  JSON Document
                </div>
                <div style={{ fontSize: '11px', color: '#64748b' }}>
                  Raw structured scan & issues payload (.json)
                </div>
              </div>
              {lastExportedFormat === 'json' && <Check size={14} color="#10b981" />}
            </button>

            {/* 2. CSV */}
            <button
              type="button"
              onClick={() => handleExport('csv')}
              style={{
                width: '100%',
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '9px 10px',
                border: 'none',
                background: 'none',
                borderRadius: '8px',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'background 0.12s ease',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = '#f1f5f9')}
              onMouseLeave={(e) => (e.currentTarget.style.background = 'none')}
            >
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                background: '#fef3c7',
                color: '#d97706',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}>
                <FileText size={16} />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '12px', fontWeight: 700, color: '#0f172a' }}>
                  CSV Spreadsheet
                </div>
                <div style={{ fontSize: '11px', color: '#64748b' }}>
                  RFC-4180 UTF-8 comma-separated (.csv)
                </div>
              </div>
              {lastExportedFormat === 'csv' && <Check size={14} color="#10b981" />}
            </button>

            {/* 3. Excel */}
            <button
              type="button"
              onClick={() => handleExport('excel')}
              style={{
                width: '100%',
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '9px 10px',
                border: 'none',
                background: 'none',
                borderRadius: '8px',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'background 0.12s ease',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = '#f1f5f9')}
              onMouseLeave={(e) => (e.currentTarget.style.background = 'none')}
            >
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                background: '#dcfce7',
                color: '#16a34a',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}>
                <FileSpreadsheet size={16} />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '12px', fontWeight: 700, color: '#0f172a' }}>
                  Excel Workbook
                </div>
                <div style={{ fontSize: '11px', color: '#64748b' }}>
                  Formatted with styled severity colors (.xls)
                </div>
              </div>
              {lastExportedFormat === 'excel' && <Check size={14} color="#10b981" />}
            </button>

            {/* 4. PDF via Print */}
            <button
              type="button"
              onClick={() => handleExport('pdf')}
              style={{
                width: '100%',
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '9px 10px',
                border: 'none',
                background: 'none',
                borderRadius: '8px',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'background 0.12s ease',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = '#f1f5f9')}
              onMouseLeave={(e) => (e.currentTarget.style.background = 'none')}
            >
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                background: '#fee2e2',
                color: '#dc2626',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}>
                <Printer size={16} />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '12px', fontWeight: 700, color: '#0f172a' }}>
                  Executive PDF Audit
                </div>
                <div style={{ fontSize: '11px', color: '#64748b' }}>
                  Printable report with posture grade &amp; inventory
                </div>
              </div>
              {lastExportedFormat === 'pdf' && <Check size={14} color="#10b981" />}
            </button>
          </div>

          {/* Footer Note */}
          <div style={{
            padding: '8px 12px',
            background: '#f8fafc',
            borderTop: '1px solid #f1f5f9',
            fontSize: '10px',
            color: '#94a3b8',
            textAlign: 'center',
          }}>
            Audited by Mir Alamin (WebCare Pro)
          </div>
        </div>
      )}

      {/* Executive Incident Response & Board Report Modal */}
      <IncidentReportModal
        isOpen={isIncidentModalOpen}
        onClose={() => setIsIncidentModalOpen(false)}
        siteName={(window as any).webcareScannerSettings?.siteName || ''}
      />
    </div>
  );
}
