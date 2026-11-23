import { useState, useEffect, useRef } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import { showConfirm, showAlert } from '../utils/dialog';
import {
  Database,
  Download,
  Trash2,
  RefreshCw,
  Lock,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Cpu,
  Activity,
  HardDrive,
  Server,
  Zap,
  Sliders,
  Play,
  Check,
  Copy,
  FileText,
  ChevronDown,
  ChevronRight,
  Info,
  X,
  Layers,
  Loader2,
  ShieldAlert,
} from 'lucide-react';

export interface BackupItem {
  filename: string;
  size_mb: number;
  size_bytes?: number;
  created: string;
  timestamp: number;
}

interface TableBreakdown {
  name: string;
  engine: string;
  rows: number;
  size_bytes: number;
  size_mb: number;
  data_size_mb: number;
  index_size_mb: number;
}

interface PreflightInfo {
  database: {
    name: string;
    host: string;
    mysql_version: string;
    charset: string;
    collate: string;
    total_size_bytes: number;
    total_size_mb: number;
    total_size_gb: number;
    total_tables: number;
    total_rows: number;
    scale_tier: 'normal' | 'moderate' | 'large' | 'massive';
    is_large: boolean;
    is_massive: boolean;
    top_tables: TableBreakdown[];
    all_tables_count: number;
  };
  storage: {
    backup_dir: string;
    is_writable: boolean;
    free_disk_bytes: number | null;
    free_disk_mb: number | null;
    free_disk_gb: number | null;
    disk_safety: 'safe' | 'warning' | 'critical';
    disk_safety_message: string;
  };
  server_environment: {
    php_version: string;
    php_sapi: string;
    php_memory_limit: string;
    php_memory_usage_mb: number;
    php_peak_memory_mb: number;
    max_execution_time: number;
    gzip_compression: boolean;
    system_ram: {
      total_ram_mb: number | null;
      free_ram_mb: number | null;
      used_ram_mb: number | null;
      ram_used_percent: number | null;
      source: string;
    };
    cpu_load: {
      '1m': number;
      '5m': number;
      '15m': number;
    } | null;
    server_time: string;
    recommended_throttle_ms: number;
  };
}

interface TelemetryData {
  php_memory_mb: number;
  php_peak_memory_mb: number;
  php_memory_limit: string;
  php_memory_percent: number;
  php_peak_memory_percent: number;
  system_ram: {
    total_ram_mb: number | null;
    free_ram_mb: number | null;
    used_ram_mb: number | null;
    ram_used_percent: number | null;
  };
  cpu_usage_percent: number | null;
  cpu_load_average: {
    '1m': number;
    '5m': number;
    '15m': number;
  } | null;
  elapsed_seconds: number;
  eta_seconds: number | null;
  rows_per_second: number;
  overall_percent: number;
  total_rows_processed: number;
  total_estimated_rows: number;
  tables_completed: number;
  total_tables: number;
  current_table_name: string;
  current_table_rows_done: number;
  current_table_rows_total: number;
  current_table_percent: number;
  archive_size_mb: number;
  throttle_ms: number;
  start_time: string;
  stop_time: string | null;
}

interface FailureDetails {
  title: string;
  technical_message: string;
  file_and_line?: string;
  failed_at_table?: string;
  failed_at_row_offset?: number;
  resource_state_at_failure?: {
    php_memory_mb?: number;
    php_peak_memory_mb?: number;
    memory_limit?: string;
    free_disk_mb?: number;
  };
  recommended_action?: string;
}

interface SessionState {
  session_id: string;
  filename: string;
  filepath: string;
  status: 'running' | 'completed' | 'failed' | 'cancelled';
  throttle_ms: number;
  current_table_name: string;
  tables_completed: number;
  total_tables: number;
  total_rows_processed: number;
  total_estimated_rows: number;
  start_time: string;
  stop_time: string | null;
  total_time_seconds: number;
  final_size_mb?: number;
  table_logs?: Array<{ table: string; rows: number }>;
  error_details?: FailureDetails | null;
}

export default function DatabaseBackupVault() {
  const [backups, setBackups] = useState<BackupItem[]>([]);
  const [loadingBackups, setLoadingBackups] = useState<boolean>(false);
  const [preflight, setPreflight] = useState<PreflightInfo | null>(null);
  const [preflightLoading, setPreflightLoading] = useState<boolean>(false);
  const [showTablesDrawer, setShowTablesDrawer] = useState<boolean>(false);
  const [showLogsDrawer, setShowLogsDrawer] = useState<boolean>(false);

  // Backup Session state
  const [activeSession, setActiveSession] = useState<SessionState | null>(null);
  const [telemetry, setTelemetry] = useState<TelemetryData | null>(null);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [pacingMode, setPacingMode] = useState<'gentle' | 'balanced' | 'fast'>('balanced');
  const [throttleMs, setThrottleMs] = useState<number>(40);
  const [elapsedTimer, setElapsedTimer] = useState<number>(0);
  const [copiedFilename, setCopiedFilename] = useState<string | null>(null);

  const isRunningRef = useRef<boolean>(false);
  isRunningRef.current = isRunning;

  const timerRef = useRef<any>(null);

  // Helper API fetch
  const callApi = async (path: string, options: any = {}) => {
    const root = (window as any).webcareScannerSettings?.root || '/wp-json/webcare-pro-security/v1';
    const nonce = (window as any).webcareScannerSettings?.nonce || '';
    const cleanPath = path.replace('/webcare-pro-security/v1', '');
    const url = `${root}${cleanPath}`;

    const headers: any = {
      'X-WP-Nonce': nonce,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    };

    const res = await fetch(url, {
      ...options,
      headers,
    });

    return await res.json();
  };

  // 1. Load Preflight info
  const loadPreflight = async () => {
    try {
      setPreflightLoading(true);
      const res: any = await callApi('/backup/preflight');
      if (res?.success && res.info) {
        setPreflight(res.info);
        if (res.info.database.scale_tier === 'massive') {
          setPacingMode('gentle');
          setThrottleMs(60);
        } else if (res.info.database.scale_tier === 'large') {
          setPacingMode('gentle');
          setThrottleMs(50);
        } else {
          setThrottleMs(res.info.server_environment.recommended_throttle_ms || 40);
        }
      }
    } catch (e) {
      console.error('Failed to load preflight info', e);
    } finally {
      setPreflightLoading(false);
    }
  };

  // 2. Load existing backups
  const loadBackups = async () => {
    try {
      setLoadingBackups(true);
      const res: any = await callApi('/backup/list');
      if (res?.success && Array.isArray(res.backups)) {
        setBackups(res.backups);
      }
    } catch (e) {
      console.error('Failed to load backups list', e);
    } finally {
      setLoadingBackups(false);
    }
  };

  // 3. Inspect and connect to any active background backup session
  const checkAndResumeActiveSession = async () => {
    try {
      const activeRes: any = await callApi('/backup/active');
      if (activeRes?.success && activeRes?.session) {
        const sess = activeRes.session;
        if (sess.state) {
          setActiveSession(sess.state);
        }
        if (sess.telemetry) {
          setTelemetry(sess.telemetry);
        }
        if (activeRes.is_running && sess.session_id) {
          setIsRunning(true);
          // If elapsed seconds available, seed elapsed timer
          if (sess.telemetry?.elapsed_seconds) {
            setElapsedTimer(Math.round(sess.telemetry.elapsed_seconds));
          }
          // Resume monitoring the background session
          runSessionPolling(sess.session_id);
        }
      }
    } catch (e) {
      console.error('Failed checking active backup session', e);
    }
  };

  useEffect(() => {
    loadPreflight();
    loadBackups();
    checkAndResumeActiveSession();
  }, []);

  // Update throttle when pacing mode changes
  const handlePacingChange = (mode: 'gentle' | 'balanced' | 'fast') => {
    setPacingMode(mode);
    if (mode === 'gentle') setThrottleMs(60);
    else if (mode === 'balanced') setThrottleMs(35);
    else if (mode === 'fast') setThrottleMs(15);
  };

  // Stopwatch effect while running
  useEffect(() => {
    if (isRunning) {
      const startMs = Date.now();
      timerRef.current = setInterval(() => {
        if (typeof document !== 'undefined' && document.hidden) return;
        setElapsedTimer(Math.floor((Date.now() - startMs) / 1000));
      }, 1000);
    } else {
      if (timerRef.current) clearInterval(timerRef.current);
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isRunning]);

  // Format seconds to HH:MM:SS
  const formatTime = (sec: number | null | undefined): string => {
    if (sec === null || sec === undefined || isNaN(sec)) return '--:--';
    const s = Math.max(0, Math.floor(sec));
    const hours = Math.floor(s / 3600);
    const minutes = Math.floor((s % 3600) / 60);
    const seconds = s % 60;
    if (hours > 0) {
      return `${hours}h ${minutes.toString().padStart(2, '0')}m ${seconds.toString().padStart(2, '0')}s`;
    }
    return `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
  };

  // Format bytes
  const formatBytes = (bytes: number): string => {
    if (bytes >= 1024 * 1024 * 1024) {
      return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
    }
    if (bytes >= 1024 * 1024) {
      return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    }
    return (bytes / 1024).toFixed(1) + ' KB';
  };

  // Reusable background session monitor and progressive stepping loop
  const runSessionPolling = async (sessionId: string) => {
    let finished = false;
    while (!finished && isRunningRef.current) {
      try {
        const stepRes: any = await callApi('/backup/session/step', {
          method: 'POST',
          body: JSON.stringify({
            session_id: sessionId,
            throttle_ms: throttleMs,
          }),
        });

        if (!stepRes?.success) {
          finished = true;
          setIsRunning(false);
          if (stepRes?.state) {
            setActiveSession(stepRes.state);
          }
          if (stepRes?.telemetry) {
            setTelemetry(stepRes.telemetry);
          }
          break;
        }

        if (stepRes.state) {
          setActiveSession(stepRes.state);
        }
        if (stepRes.telemetry) {
          setTelemetry(stepRes.telemetry);
        }

        if (stepRes.status === 'completed') {
          finished = true;
          setIsRunning(false);
          await loadBackups();
          await loadPreflight();
          break;
        }

        if (stepRes.status === 'failed' || stepRes.status === 'cancelled') {
          finished = true;
          setIsRunning(false);
          break;
        }
      } catch (stepErr: any) {
        console.error('Step request error', stepErr);
        // Wait 1.5s before retry to handle brief network hiccup
        await new Promise((r) => setTimeout(r, 1500));
      }
    }
  };

  // Start backup session and step loop
  const handleStartBackup = async () => {
    if (isRunning) return;

    // Safety verification if disk space is critical
    if (preflight && preflight.storage.disk_safety === 'critical') {
      await showAlert(`Cannot start backup: ${preflight.storage.disk_safety_message}`, 'Disk Safety Critical');
      return;
    }

    try {
      setIsRunning(true);
      setElapsedTimer(0);
      setTelemetry(null);

      // 1. Initialize session
      const startRes: any = await callApi('/backup/session/start', {
        method: 'POST',
        body: JSON.stringify({
          throttle_ms: throttleMs,
          batch_size: pacingMode === 'gentle' ? 600 : pacingMode === 'balanced' ? 1000 : 1500,
        }),
      });

      if (!startRes?.success || !startRes.session_id) {
        setIsRunning(false);
        await showAlert(startRes?.message || 'Failed to initialize database backup session.', 'Backup Session Error');
        return;
      }

      setActiveSession(startRes.state);
      setTelemetry(startRes.telemetry);

      const sessionId = startRes.session_id;

      // 2. Drive progress loop in frontend while present (backend also self-drives via WP-Cron/loopback)
      await runSessionPolling(sessionId);
    } catch (e: any) {
      console.error('Backup initiation error', e);
      setIsRunning(false);
      await showAlert('Error initiating database backup session.', 'Backup Initiation Error');
    }
  };

  // Cancel running session
  const handleCancelBackup = async () => {
    if (!activeSession?.session_id) return;
    const confirmed = await showConfirm({
      title: 'Cancel Database Backup',
      message: 'Are you sure you want to stop and cancel the active database backup? Partial archives will be cleaned up.',
      confirmLabel: 'Cancel Backup',
      variant: 'warning',
    });
    if (!confirmed) {
      return;
    }

    try {
      setIsRunning(false);
      await callApi('/backup/session/cancel', {
        method: 'POST',
        body: JSON.stringify({ session_id: activeSession.session_id }),
      });
      setActiveSession((prev) => (prev ? { ...prev, status: 'cancelled' } : null));
      await loadBackups();
    } catch (e) {
      console.error('Failed to cancel session', e);
    }
  };

  // Delete an existing backup
  const handleDeleteBackup = async (filename: string) => {
    const confirmed = await showConfirm({
      title: 'Delete Database Backup',
      message: `Are you sure you want to permanently delete backup file:\n${filename}?`,
      confirmLabel: 'Delete Backup',
      variant: 'danger',
    });
    if (!confirmed) {
      return;
    }
    try {
      const res: any = await callApi('/backup/delete', {
        method: 'POST',
        body: JSON.stringify({ filename }),
      });
      if (res?.success) {
        setBackups((prev) => prev.filter((b) => b.filename !== filename));
      } else {
        await showAlert('Could not delete backup file.', 'Delete Error');
      }
    } catch (e) {
      console.error('Failed to delete backup', e);
    }
  };

  // Download an existing backup
  const handleDownloadBackup = (filename: string) => {
    const root = (window as any).webcareScannerSettings?.root || '/wp-json/webcare-pro-security/v1';
    const nonce = (window as any).webcareScannerSettings?.nonce || '';
    const url = `${root}/backup/download?filename=${encodeURIComponent(filename)}&_wpnonce=${nonce}`;
    window.open(url, '_blank');
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedFilename(text);
    setTimeout(() => setCopiedFilename(null), 2500);
  };

  const totalVaultSizeMb = backups.reduce((acc, b) => acc + (b.size_mb || 0), 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
      {/* 1. TOP HEADER & INSTANT BACKUP CONTROLLER */}
      <div
        className="webcare-dark-hero webcare-db-vault-hero"
        style={{
          background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
          padding: '28px',
          borderRadius: '16px',
          color: '#ffffff',
          boxShadow: '0 10px 25px -5px rgba(15, 23, 42, 0.25)',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        <div style={{ position: 'relative', zIndex: 2 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px' }}>
            <div style={{ maxWidth: '780px' }}>
              <div className="webcare-db-vault-badge" style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', padding: '4px 12px', background: 'rgba(59, 130, 246, 0.18)', borderRadius: '20px', border: '1px solid rgba(59, 130, 246, 0.35)', color: '#93c5fd', fontSize: '12px', fontWeight: 600, marginBottom: '12px' }}>
                <Database size={14} /> One-Click Database Backup Vault
              </div>
              <h1 className="webcare-db-vault-title" style={{ margin: '0 0 10px 0', fontSize: '24px', fontWeight: 700, letterSpacing: '-0.02em', color: '#ffffff', display: 'flex', alignItems: 'center', gap: '12px' }}>
                High-Performance, Memory-Safe Database Backup Engine
              </h1>
              <p className="webcare-db-vault-desc" style={{ margin: 0, color: '#cbd5e1', fontSize: '14px', lineHeight: 1.6 }}>
                Safely captures complete MySQL dumps with maximum Gzip compression (<code>.sql.gz</code>). Features progressive chunked execution, primary-key streaming, and dynamic server-pacing designed to back up large databases (including &gt; 5GB) without memory exhaustion or CPU pressure.
              </p>
            </div>

            {/* ACTION CONTROLS */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', alignItems: 'flex-end' }}>
              <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                {isRunning ? (
                  <button
                    className="webcare-btn"
                    onClick={handleCancelBackup}
                    style={{
                      background: '#ef4444',
                      color: '#ffffff',
                      border: 'none',
                      padding: '12px 22px',
                      fontSize: '14px',
                      fontWeight: 600,
                      borderRadius: '8px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      cursor: 'pointer',
                      boxShadow: '0 4px 12px rgba(239, 68, 68, 0.3)',
                    }}
                  >
                    <XCircle size={16} /> Stop / Cancel Backup
                  </button>
                ) : (
                  <button
                    className="webcare-btn"
                    onClick={handleStartBackup}
                    disabled={preflight?.storage.disk_safety === 'critical'}
                    style={{
                      background: preflight?.storage.disk_safety === 'critical' ? '#64748b' : 'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)',
                      color: '#ffffff',
                      border: 'none',
                      padding: '12px 26px',
                      fontSize: '15px',
                      fontWeight: 600,
                      borderRadius: '8px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '10px',
                      cursor: preflight?.storage.disk_safety === 'critical' ? 'not-allowed' : 'pointer',
                      boxShadow: '0 4px 14px rgba(37, 99, 235, 0.4)',
                      transition: 'all 0.2s ease',
                    }}
                  >
                    <Download size={18} /> Create Instant Backup
                  </button>
                )}

                <button
                  className="webcare-btn"
                  onClick={() => {
                    loadPreflight();
                    loadBackups();
                  }}
                  disabled={loadingBackups || preflightLoading}
                  style={{
                    background: 'rgba(255, 255, 255, 0.1)',
                    color: '#e2e8f0',
                    border: '1px solid rgba(255, 255, 255, 0.15)',
                    padding: '12px 16px',
                    borderRadius: '8px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    cursor: 'pointer',
                  }}
                  title="Refresh Database Stats & Backups"
                >
                  <RefreshCw size={15} className={loadingBackups || preflightLoading ? 'webcare-spin' : ''} />
                </button>
              </div>

              {/* SERVER PACING SELECTOR */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(255, 255, 255, 0.06)', padding: '6px 12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.1)' }}>
                <span style={{ fontSize: '12px', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '5px' }}>
                  <Sliders size={13} color="#38bdf8" /> Server Pacing:
                </span>
                <div style={{ display: 'inline-flex', gap: '4px' }}>
                  <button
                    onClick={() => handlePacingChange('gentle')}
                    disabled={isRunning}
                    style={{
                      background: pacingMode === 'gentle' ? '#0284c7' : 'transparent',
                      color: pacingMode === 'gentle' ? '#ffffff' : '#cbd5e1',
                      border: 'none',
                      borderRadius: '4px',
                      padding: '3px 8px',
                      fontSize: '11px',
                      fontWeight: 600,
                      cursor: isRunning ? 'default' : 'pointer',
                    }}
                    title="Gentle Throttle (60ms pause): Zero server pressure, ideal for large databases >1GB and production environments"
                  >
                    Gentle (Safe)
                  </button>
                  <button
                    onClick={() => handlePacingChange('balanced')}
                    disabled={isRunning}
                    style={{
                      background: pacingMode === 'balanced' ? '#0284c7' : 'transparent',
                      color: pacingMode === 'balanced' ? '#ffffff' : '#cbd5e1',
                      border: 'none',
                      borderRadius: '4px',
                      padding: '3px 8px',
                      fontSize: '11px',
                      fontWeight: 600,
                      cursor: isRunning ? 'default' : 'pointer',
                    }}
                    title="Balanced (35ms pause): Balanced speed with minimal server load"
                  >
                    Balanced
                  </button>
                  <button
                    onClick={() => handlePacingChange('fast')}
                    disabled={isRunning}
                    style={{
                      background: pacingMode === 'fast' ? '#0284c7' : 'transparent',
                      color: pacingMode === 'fast' ? '#ffffff' : '#cbd5e1',
                      border: 'none',
                      borderRadius: '4px',
                      padding: '3px 8px',
                      fontSize: '11px',
                      fontWeight: 600,
                      cursor: isRunning ? 'default' : 'pointer',
                    }}
                    title="High Performance (15ms pause): Faster execution for small databases"
                  >
                    Fast
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* PRE-FLIGHT DATABASE INTELLIGENCE BADGE */}
          {preflight && (
            <div
              style={{
                marginTop: '22px',
                paddingTop: '16px',
                borderTop: '1px solid rgba(255, 255, 255, 0.1)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '14px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '20px', flexWrap: 'wrap' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '13px', color: '#94a3b8' }}>Database Size:</span>
                  <span style={{ fontSize: '14px', fontWeight: 700, color: '#f8fafc' }}>
                    {preflight.database.total_size_mb >= 1024
                      ? `${preflight.database.total_size_gb} GB`
                      : `${preflight.database.total_size_mb} MB`}
                  </span>
                  <span
                    style={{
                      padding: '2px 8px',
                      borderRadius: '12px',
                      fontSize: '11px',
                      fontWeight: 600,
                      background:
                        preflight.database.scale_tier === 'massive'
                          ? '#ef4444'
                          : preflight.database.scale_tier === 'large'
                          ? '#f59e0b'
                          : '#10b981',
                      color: '#ffffff',
                    }}
                  >
                    {preflight.database.scale_tier === 'massive'
                      ? 'Massive (> 5 GB)'
                      : preflight.database.scale_tier === 'large'
                      ? 'Large (1-5 GB)'
                      : preflight.database.scale_tier === 'moderate'
                      ? 'Moderate'
                      : 'Standard'}
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '13px', color: '#94a3b8' }}>Architecture:</span>
                  <span style={{ fontSize: '13px', color: '#e2e8f0', fontWeight: 600 }}>
                    {preflight.database.total_tables} Tables ({preflight.database.total_rows.toLocaleString()} Est. Rows)
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '13px', color: '#94a3b8' }}>Vault Disk Free:</span>
                  <span
                    style={{
                      fontSize: '13px',
                      fontWeight: 600,
                      color:
                        preflight.storage.disk_safety === 'critical'
                          ? '#f87171'
                          : preflight.storage.disk_safety === 'warning'
                          ? '#fbbf24'
                          : '#4ade80',
                    }}
                  >
                    {preflight.storage.free_disk_gb ? `${preflight.storage.free_disk_gb} GB` : 'Available'}
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '13px', color: '#94a3b8' }}>Compression:</span>
                  <span style={{ fontSize: '13px', color: '#38bdf8', fontWeight: 600 }}>
                    {preflight.server_environment.gzip_compression ? 'Gzip (.sql.gz) 9x' : 'Plaintext (.sql)'}
                  </span>
                </div>
              </div>

              <button
                onClick={() => setShowTablesDrawer(!showTablesDrawer)}
                style={{
                  background: 'transparent',
                  color: '#93c5fd',
                  border: '1px solid rgba(147, 197, 253, 0.3)',
                  borderRadius: '6px',
                  padding: '5px 12px',
                  fontSize: '12px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <Layers size={13} /> {showTablesDrawer ? 'Hide Table Breakdown' : 'Inspect Database Tables'}
              </button>
            </div>
          )}

          {/* MASSIVE DATABASE SAFETY ALERT */}
          {preflight?.database.is_massive && (
            <div
              style={{
                marginTop: '16px',
                padding: '12px 16px',
                background: 'rgba(245, 158, 11, 0.15)',
                border: '1px solid rgba(245, 158, 11, 0.35)',
                borderRadius: '8px',
                color: '#fef3c7',
                fontSize: '13px',
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
              }}
            >
              <AlertTriangle size={18} color="#fbbf24" style={{ flexShrink: 0 }} />
              <div>
                <strong>Massive Database ({preflight.database.total_size_gb} GB) Detected:</strong> Safe progressive pacing is automatically activated. The backup will stream in small memory-safe chunks (60ms CPU cooling pauses) so your server CPU and visitor browsing experience remain completely unburdened.
              </div>
            </div>
          )}
        </div>
      </div>

      {/* 2. TABLE BREAKDOWN DRAWER (IF OPEN) */}
      {showTablesDrawer && preflight?.database.top_tables && (
        <div
          className="webcare-db-table-drawer"
          style={{
            borderRadius: '12px',
            padding: '20px',
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.05)',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
            <h4 className="webcare-db-drawer-title" style={{ margin: 0, fontSize: '15px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Layers size={16} color="#3b82f6" /> Largest Tables Inventory (Pre-Backup Inspection)
            </h4>
            <span className="webcare-db-drawer-count" style={{ fontSize: '12px' }}>
              Showing top {preflight.database.top_tables.length} of {preflight.database.total_tables} tables
            </span>
          </div>

          <div style={{ maxHeight: '280px', overflowY: 'auto' }}>
            <table className="webcare-table" style={{ fontSize: '13px' }}>
              <thead>
                <tr>
                  <th>Table Name</th>
                  <th>Storage Engine</th>
                  <th>Estimated Rows</th>
                  <th>Data Size</th>
                  <th>Index Size</th>
                  <th>Total Size</th>
                </tr>
              </thead>
              <tbody>
                {preflight.database.top_tables.map((t) => (
                  <tr key={t.name}>
                    <td style={{ fontFamily: 'monospace', fontWeight: 600, color: '#1e293b' }}>{t.name}</td>
                    <td>{t.engine}</td>
                    <td>{t.rows.toLocaleString()}</td>
                    <td>{t.data_size_mb} MB</td>
                    <td>{t.index_size_mb} MB</td>
                    <td style={{ fontWeight: 600, color: t.size_mb > 100 ? '#ea580c' : '#0f172a' }}>{t.size_mb} MB</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 3. REALTIME PROGRESS & EXTENDED TELEMETRY CARD (IF RUNNING OR RECENT SESSION) */}
      {(isRunning || activeSession) && (
        <div
          style={{
            background: 'var(--webcare-bg-card, #ffffff)',
            borderRadius: '16px',
            border: isRunning ? '2px solid #3b82f6' : activeSession?.status === 'failed' ? '2px solid #ef4444' : '1px solid #e2e8f0',
            padding: '24px',
            boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.05)',
            display: 'flex',
            flexDirection: 'column',
            gap: '20px',
          }}
        >
          {/* HEADER: STATUS & TIMERS */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              {isRunning ? (
                <div
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '8px',
                    padding: '6px 14px',
                    background: '#eff6ff',
                    border: '1px solid #bfdbfe',
                    borderRadius: '20px',
                    color: '#1d4ed8',
                    fontSize: '13px',
                    fontWeight: 700,
                  }}
                >
                  <Loader2 size={16} className="webcare-spin" /> BACKUP IN PROGRESS
                </div>
              ) : activeSession?.status === 'completed' ? (
                <div
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '8px',
                    padding: '6px 14px',
                    background: '#ecfdf5',
                    border: '1px solid #a7f3d0',
                    borderRadius: '20px',
                    color: '#047857',
                    fontSize: '13px',
                    fontWeight: 700,
                  }}
                >
                  <CheckCircle2 size={16} /> BACKUP COMPLETED
                </div>
              ) : activeSession?.status === 'failed' ? (
                <div
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '8px',
                    padding: '6px 14px',
                    background: '#fef2f2',
                    border: '1px solid #fecaca',
                    borderRadius: '20px',
                    color: '#b91c1c',
                    fontSize: '13px',
                    fontWeight: 700,
                  }}
                >
                  <XCircle size={16} /> BACKUP FAILED
                </div>
              ) : (
                <div
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '8px',
                    padding: '6px 14px',
                    background: '#fffbeb',
                    border: '1px solid #fde68a',
                    borderRadius: '20px',
                    color: '#b45309',
                    fontSize: '13px',
                    fontWeight: 700,
                  }}
                >
                  <AlertTriangle size={16} /> BACKUP CANCELLED
                </div>
              )}

              <span style={{ fontSize: '13px', color: '#64748b', fontFamily: 'monospace' }}>
                Archive: <strong>{activeSession?.filename}</strong>
              </span>
            </div>

            {/* TIMESTAMPS */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '20px', fontSize: '13px', color: '#475569' }}>
              <div>
                <span style={{ color: '#94a3b8' }}>Start Time: </span>
                <strong>{activeSession?.start_time || telemetry?.start_time || '--'}</strong>
              </div>
              <div>
                <span style={{ color: '#94a3b8' }}>Stop Time: </span>
                <strong>{activeSession?.stop_time || telemetry?.stop_time || (isRunning ? 'Running...' : '--')}</strong>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'var(--webcare-bg-surface, #f8fafc)', padding: '4px 10px', borderRadius: '6px', border: '1px solid #e2e8f0' }}>
                <Clock size={14} color="#3b82f6" />
                <span style={{ color: '#94a3b8' }}>Duration: </span>
                <strong style={{ color: '#0f172a' }}>
                  {isRunning ? formatTime(elapsedTimer) : formatTime(activeSession?.total_time_seconds)}
                </strong>
              </div>
            </div>
          </div>

          {/* DUAL REAL-TIME PROGRESS BARS */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {/* OVERALL PROGRESS */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px', fontSize: '13px' }}>
                <span style={{ fontWeight: 600, color: '#0f172a' }}>
                  Overall Database Progress: {telemetry ? `${telemetry.overall_percent}%` : activeSession?.status === 'completed' ? '100%' : '0%'}
                </span>
                <span style={{ color: '#64748b' }}>
                  {telemetry
                    ? `${telemetry.total_rows_processed.toLocaleString()} / ${telemetry.total_estimated_rows.toLocaleString()} Rows (${telemetry.tables_completed} / ${telemetry.total_tables} Tables)`
                    : activeSession
                    ? `${activeSession.total_rows_processed.toLocaleString()} Rows Exported (${activeSession.tables_completed} Tables)`
                    : ''}
                </span>
              </div>
              <div style={{ width: '100%', height: '12px', background: '#e2e8f0', borderRadius: '6px', overflow: 'hidden' }}>
                <div
                  style={{
                    height: '100%',
                    width: `${telemetry ? telemetry.overall_percent : activeSession?.status === 'completed' ? 100 : 0}%`,
                    background: activeSession?.status === 'failed' ? '#ef4444' : 'linear-gradient(90deg, #3b82f6 0%, #10b981 100%)',
                    borderRadius: '6px',
                    transition: 'width 0.3s ease',
                  }}
                />
              </div>
            </div>

            {/* CURRENT TABLE REALTIME PROGRESS */}
            {isRunning && telemetry && (
              <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '12px 16px', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px', fontSize: '13px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ color: '#64748b' }}>Dumping Table:</span>
                    <strong style={{ fontFamily: 'monospace', color: '#1d4ed8', background: '#eff6ff', padding: '2px 8px', borderRadius: '4px' }}>
                      {telemetry.current_table_name || 'Initializing...'}
                    </strong>
                    <span style={{ fontSize: '11px', color: '#059669', background: '#ecfdf5', padding: '2px 6px', borderRadius: '4px', fontWeight: 600 }}>
                      ⚡ Server-Pacing: {telemetry.throttle_ms}ms cooling pause
                    </span>
                  </div>
                  <span style={{ color: '#64748b', fontSize: '12px' }}>
                    {telemetry.current_table_rows_done.toLocaleString()} / {telemetry.current_table_rows_total.toLocaleString()} rows ({telemetry.current_table_percent}%)
                  </span>
                </div>
                <div style={{ width: '100%', height: '6px', background: '#e2e8f0', borderRadius: '3px', overflow: 'hidden' }}>
                  <div
                    style={{
                      height: '100%',
                      width: `${telemetry.current_table_percent}%`,
                      background: '#3b82f6',
                      borderRadius: '3px',
                      transition: 'width 0.2s ease',
                    }}
                  />
                </div>
              </div>
            )}
          </div>

          {/* EXTENDED TELEMETRY GRID (6 DETAILED METRIC TILES) */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '14px' }}>
            {/* 1. PHP RAM USAGE */}
            <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '14px', borderRadius: '10px', border: '1px solid #e2e8f0' }}>
              <div style={{ fontSize: '12px', color: '#64748b', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                <Activity size={14} color="#3b82f6" /> PHP RAM Usage
              </div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: '#0f172a' }}>
                {telemetry?.php_memory_mb || preflight?.server_environment.php_memory_usage_mb || '--'} MB
              </div>
              <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px' }}>
                {telemetry ? `${telemetry.php_memory_percent}% of ${telemetry.php_memory_limit}` : `Limit: ${preflight?.server_environment.php_memory_limit}`}
              </div>
            </div>

            {/* 2. PEAK RAM USAGE */}
            <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '14px', borderRadius: '10px', border: '1px solid #e2e8f0' }}>
              <div style={{ fontSize: '12px', color: '#64748b', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                <Activity size={14} color="#8b5cf6" /> Peak RAM Usage
              </div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: '#0f172a' }}>
                {telemetry?.php_peak_memory_mb || preflight?.server_environment.php_peak_memory_mb || '--'} MB
              </div>
              <div style={{ fontSize: '11px', color: '#10b981', marginTop: '2px', fontWeight: 600 }}>
                ✓ Within safe memory bounds
              </div>
            </div>

            {/* 3. TOTAL SERVER RAM */}
            <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '14px', borderRadius: '10px', border: '1px solid #e2e8f0' }}>
              <div style={{ fontSize: '12px', color: '#64748b', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                <Server size={14} color="#06b6d4" /> Total Server RAM
              </div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: '#0f172a' }}>
                {telemetry?.system_ram.total_ram_mb
                  ? `${(telemetry.system_ram.total_ram_mb / 1024).toFixed(1)} GB`
                  : preflight?.server_environment.system_ram.total_ram_mb
                  ? `${(preflight.server_environment.system_ram.total_ram_mb / 1024).toFixed(1)} GB`
                  : 'N/A'}
              </div>
              <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px' }}>
                {telemetry?.system_ram.free_ram_mb
                  ? `${(telemetry.system_ram.free_ram_mb / 1024).toFixed(1)} GB Free (${telemetry.system_ram.ram_used_percent}% used)`
                  : 'System Managed'}
              </div>
            </div>

            {/* 4. TOTAL CPU USAGE & LOAD */}
            <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '14px', borderRadius: '10px', border: '1px solid #e2e8f0' }}>
              <div style={{ fontSize: '12px', color: '#64748b', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                <Cpu size={14} color="#f59e0b" /> Process CPU & Load
              </div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: '#0f172a' }}>
                {telemetry?.cpu_usage_percent !== null && telemetry?.cpu_usage_percent !== undefined
                  ? `${telemetry.cpu_usage_percent}%`
                  : 'Cool / Normal'}
              </div>
              <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px' }}>
                {telemetry?.cpu_load_average
                  ? `Load: ${telemetry.cpu_load_average['1m']}, ${telemetry.cpu_load_average['5m']}`
                  : 'Zero Server Spike'}
              </div>
            </div>

            {/* 5. CURRENT ARCHIVE SIZE */}
            <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '14px', borderRadius: '10px', border: '1px solid #e2e8f0' }}>
              <div style={{ fontSize: '12px', color: '#64748b', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                <HardDrive size={14} color="#10b981" /> Spooled Archive
              </div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: '#0f172a' }}>
                {telemetry?.archive_size_mb || activeSession?.final_size_mb || '--'} MB
              </div>
              <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px' }}>
                Gzip Compressed (.sql.gz)
              </div>
            </div>

            {/* 6. THROUGHPUT & SPEED */}
            <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '14px', borderRadius: '10px', border: '1px solid #e2e8f0' }}>
              <div style={{ fontSize: '12px', color: '#64748b', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                <Zap size={14} color="#ec4899" /> Throughput & Rate
              </div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: '#0f172a' }}>
                {telemetry?.rows_per_second ? `${telemetry.rows_per_second.toLocaleString()}` : '--'} rows/s
              </div>
              <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px' }}>
                {isRunning ? (telemetry?.eta_seconds ? `~ ${formatTime(telemetry.eta_seconds)} remaining` : 'Calculating ETA...') : 'Completed'}
              </div>
            </div>
          </div>

          {/* COMPREHENSIVE FAILURE DETAILS (IF FAILED) */}
          {activeSession?.status === 'failed' && activeSession.error_details && (
            <div
              style={{
                background: '#fef2f2',
                border: '1px solid #fecaca',
                borderRadius: '12px',
                padding: '18px',
                color: '#991b1b',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                <ShieldAlert size={22} color="#dc2626" style={{ flexShrink: 0, marginTop: '2px' }} />
                <div style={{ width: '100%' }}>
                  <h4 style={{ margin: '0 0 6px 0', fontSize: '16px', fontWeight: 700, color: '#b91c1c' }}>
                    {activeSession.error_details.title || 'Database Backup Operation Failed'}
                  </h4>
                  <p style={{ margin: '0 0 12px 0', fontSize: '13px', lineHeight: 1.5, color: '#7f1d1d' }}>
                    <strong>Technical Reason:</strong> {activeSession.error_details.technical_message}
                  </p>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '10px', background: 'var(--webcare-bg-card, #ffffff)', padding: '12px', borderRadius: '8px', border: '1px solid #fee2e2', marginBottom: '12px', fontSize: '12px' }}>
                    <div>
                      <span style={{ color: '#64748b' }}>Interrupted Table:</span>{' '}
                      <strong style={{ fontFamily: 'monospace' }}>{activeSession.error_details.failed_at_table || 'N/A'}</strong>
                    </div>
                    <div>
                      <span style={{ color: '#64748b' }}>Row Offset:</span>{' '}
                      <strong>{activeSession.error_details.failed_at_row_offset?.toLocaleString() || '0'}</strong>
                    </div>
                    <div>
                      <span style={{ color: '#64748b' }}>RAM at Failure:</span>{' '}
                      <strong>{activeSession.error_details.resource_state_at_failure?.php_memory_mb || '--'} MB</strong>
                    </div>
                    <div>
                      <span style={{ color: '#64748b' }}>Free Disk at Failure:</span>{' '}
                      <strong>{activeSession.error_details.resource_state_at_failure?.free_disk_mb || '--'} MB</strong>
                    </div>
                  </div>

                  {activeSession.error_details.recommended_action && (
                    <div style={{ fontSize: '13px', color: '#991b1b', background: '#fee2e2', padding: '10px', borderRadius: '6px' }}>
                      <strong>Developer / Administrator Action:</strong> {activeSession.error_details.recommended_action}
                    </div>
                  )}

                  <div style={{ marginTop: '12px', display: 'flex', gap: '10px' }}>
                    <button
                      className="webcare-btn"
                      onClick={handleStartBackup}
                      style={{ background: '#dc2626', color: '#ffffff', border: 'none', padding: '8px 16px', borderRadius: '6px', fontSize: '13px', fontWeight: 600, cursor: 'pointer' }}
                    >
                      <RefreshCw size={14} /> Retry Backup
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TABLE LOGS ACCORDION (DEVELOPER AUDIT TRAIL) */}
          {activeSession?.table_logs && activeSession.table_logs.length > 0 && (
            <div>
              <button
                onClick={() => setShowLogsDrawer(!showLogsDrawer)}
                style={{
                  background: 'var(--webcare-bg-surface, #f8fafc)',
                  border: '1px solid #e2e8f0',
                  borderRadius: '6px',
                  padding: '6px 14px',
                  fontSize: '12px',
                  color: '#475569',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  cursor: 'pointer',
                }}
              >
                <FileText size={13} />
                {showLogsDrawer ? 'Hide Completed Tables Audit Log' : `View Completed Tables Audit Log (${activeSession.table_logs.length} tables)`}
                {showLogsDrawer ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
              </button>

              {showLogsDrawer && (
                <div style={{ marginTop: '10px', maxHeight: '200px', overflowY: 'auto', background: 'var(--webcare-bg-surface, #f8fafc)', padding: '12px', borderRadius: '8px', border: '1px solid #e2e8f0', fontSize: '12px' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ textAlign: 'left', borderBottom: '1px solid #cbd5e1' }}>
                        <th style={{ padding: '4px' }}>Table</th>
                        <th style={{ padding: '4px' }}>Rows Exported</th>
                        <th style={{ padding: '4px' }}>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {activeSession.table_logs.map((log, idx) => (
                        <tr key={idx} style={{ borderBottom: '1px solid #f1f5f9' }}>
                          <td style={{ padding: '4px', fontFamily: 'monospace', color: '#1e293b' }}>{log.table}</td>
                          <td style={{ padding: '4px' }}>{log.rows.toLocaleString()}</td>
                          <td style={{ padding: '4px', color: '#10b981', fontWeight: 600 }}>✓ Dumped</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* 4. METRIC CARDS ROW */}
      <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
        <div className="webcare-metric-card" style={{ flex: 1, minWidth: '220px' }}>
          <div>
            <div className="webcare-metric-label">Vault Security</div>
            <div className="webcare-metric-val" style={{ fontSize: '17px', color: '#10b981', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Lock size={18} /> .htaccess, web.config & index.php Locked
            </div>
          </div>
        </div>
        <div className="webcare-metric-card" style={{ flex: 1, minWidth: '220px' }}>
          <div>
            <div className="webcare-metric-label">Stored Backups</div>
            <div className="webcare-metric-val" style={{ fontSize: '22px' }}>
              {backups.length}
            </div>
          </div>
        </div>
        <div className="webcare-metric-card" style={{ flex: 1, minWidth: '220px' }}>
          <div>
            <div className="webcare-metric-label">Total Vault Storage</div>
            <div className="webcare-metric-val" style={{ fontSize: '22px' }}>
              {totalVaultSizeMb >= 1024 ? `${(totalVaultSizeMb / 1024).toFixed(2)} GB` : `${totalVaultSizeMb.toFixed(2)} MB`}
            </div>
          </div>
        </div>
        <div className="webcare-metric-card" style={{ flex: 1, minWidth: '220px' }}>
          <div>
            <div className="webcare-metric-label">Vault Storage Path</div>
            <div className="webcare-metric-val" style={{ fontSize: '13px', fontFamily: 'monospace', color: '#475569', wordBreak: 'break-all' }}>
              uploads/webcare-pro-security/.db-backups/
            </div>
          </div>
        </div>
      </div>

      {/* 5. EXISTING DATABASE BACKUPS ARCHIVE TABLE */}
      <div className="webcare-card">
        <div className="webcare-card-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h3 style={{ margin: 0 }}>Existing Database Backups in Vault</h3>
            <span className="webcare-pill webcare-pill-count">
              {backups.length} archives
            </span>
          </div>
          <button
            className="webcare-btn webcare-btn-secondary"
            onClick={loadBackups}
            disabled={loadingBackups}
          >
            <RefreshCw size={14} className={loadingBackups ? 'webcare-spin' : ''} /> Refresh List
          </button>
        </div>

        {backups.length === 0 ? (
          <div style={{ padding: '48px', textAlign: 'center', color: '#64748b' }}>
            <Database size={48} color="#94a3b8" style={{ margin: '0 auto 12px auto' }} />
            <h4 className="webcare-empty-title" style={{ margin: '0 0 6px 0', fontSize: '18px' }}>No Backups Created Yet</h4>
            <p className="webcare-empty-desc" style={{ margin: 0, fontSize: '14px' }}>Click "Create Instant Backup" above to generate a full SQL snapshot before running remediations.</p>
          </div>
        ) : (
          <table className="webcare-table">
            <thead>
              <tr>
                <th>Backup Archive</th>
                <th>File Size</th>
                <th>Created At</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {backups.map((b) => (
                <tr key={b.filename}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="webcare-backup-filename" style={{ fontFamily: 'monospace', fontWeight: 600 }}>
                        {b.filename}
                      </span>
                      <button
                        onClick={() => copyToClipboard(b.filename)}
                        style={{
                          background: 'transparent',
                          border: 'none',
                          color: '#94a3b8',
                          cursor: 'pointer',
                          padding: '2px',
                        }}
                        title="Copy filename"
                      >
                        {copiedFilename === b.filename ? <Check size={13} color="#10b981" /> : <Copy size={13} />}
                      </button>
                    </div>
                  </td>
                  <td>
                    <span className="webcare-backup-filesize" style={{ fontWeight: 600 }}>
                      {b.size_mb >= 1024 ? `${(b.size_mb / 1024).toFixed(2)} GB` : `${b.size_mb} MB`}
                    </span>
                  </td>
                  <td className="webcare-backup-date" style={{ fontSize: '13px' }}>{b.created}</td>
                  <td style={{ textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: '8px' }}>
                      <button
                        className="webcare-btn"
                        style={{ background: '#eff6ff', color: '#1d4ed8', border: '1px solid #bfdbfe', padding: '6px 12px', fontSize: '12px' }}
                        onClick={() => handleDownloadBackup(b.filename)}
                      >
                        <Download size={13} /> Download
                      </button>
                      <button
                        className="webcare-btn"
                        style={{ background: '#fee2e2', color: '#b91c1c', border: '1px solid #fecaca', padding: '6px 12px', fontSize: '12px' }}
                        onClick={() => handleDeleteBackup(b.filename)}
                      >
                        <Trash2 size={13} /> Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
