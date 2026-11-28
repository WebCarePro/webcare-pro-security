import { useState, useEffect, ReactNode } from '@wordpress/element';
import { 
  LayoutDashboard, 
  Radar, 
  Shield, 
  Users, 
  Server, 
  Settings as SettingsIcon,
  Grid,
  Sun, 
  Moon, 
  ShieldAlert, 
  ShieldCheck,
  Sparkles,
  SlidersHorizontal,
  Zap,
  Database,
  Loader2,
  Wrench,
  AlertTriangle,
  PlayCircle,
  Search,
  ChevronRight,
  FileText,
  XCircle
} from 'lucide-react';
import WebCareBrandLogo from './WebCareBrandLogo';
import MegaMenuModal from './MegaMenuModal';
import WelcomeModal from './WelcomeModal';
import { RescueAssistantModal } from './RescueAssistantModal';
import { QuickJumpModal } from './QuickJumpModal';
import { applyWebCareTheme, getWebCareTheme } from '../utils/theme';
import { apiRequest } from '../utils/api';
import { toast } from '../utils/dialog';
import { confirmAction, ConfirmModalHost } from './ui/ConfirmModal';
import { useWorkspaceMode } from '../hooks/useWorkspaceMode';
import { ToastProvider } from './ui/ToastProvider';
import { buildAdminUrl, navigateToRoute, parseCurrentRoute, PILLARS, PILLAR_MAP } from '../utils/routeRegistry';

interface WebCareShellProps {
  activeTab?: string;
  activePillarId?: string;
  children: ReactNode;
}

export const WebCareShell = ({ activeTab, activePillarId, children }: WebCareShellProps) => {
  const [themeMode, setThemeMode] = useState<'dark' | 'light'>(() => getWebCareTheme());
  const { mode: currentWorkspaceMode, isDeveloperMode, setMode } = useWorkspaceMode();
  const workspaceMode = isDeveloperMode ? 'advanced' : 'essential';

  const [routeState, setRouteState] = useState(() => parseCurrentRoute());

  // Listen to popstate and same-pillar custom route-change event
  useEffect(() => {
    const handleSync = () => {
      setRouteState(parseCurrentRoute());
    };
    window.addEventListener('popstate', handleSync);
    window.addEventListener('webcare:route-change', handleSync);
    return () => {
      window.removeEventListener('popstate', handleSync);
      window.removeEventListener('webcare:route-change', handleSync);
    };
  }, []);

  const [megaMenuOpen, setMegaMenuOpen] = useState(false);
  const [quickJumpOpen, setQuickJumpOpen] = useState(false);
  const [isWelcomeModalOpen, setIsWelcomeModalOpen] = useState(false);
  const [rescueModalOpen, setRescueModalOpen] = useState<boolean>(() => {
    try {
      return new URLSearchParams(window.location.search).get('rescue') === '1';
    } catch {
      return false;
    }
  });
  const [rescuePaused, setRescuePaused] = useState(false);
  const [safeModeSecondsLeft, setSafeModeSecondsLeft] = useState<number>(0);
  const [resumingSafeMode, setResumingSafeMode] = useState(false);
  const [activeBackupSession, setActiveBackupSession] = useState<{
    isRunning: boolean;
    tablesCompleted: number;
    totalTables: number;
    percent: number;
  } | null>(null);
  const [activeScanSession, setActiveScanSession] = useState<{
    scanId: number;
    scanTarget: string;
    triggerType: string;
    scannedFiles: number;
    totalFiles: number;
    remaining: number;
    phase: string;
    lastFile: string;
    elapsed: number;
    telemetry?: any;
    percent: number;
  } | null>(null);
  const [abortingScan, setAbortingScan] = useState(false);

  // Poll for active background or resumed security scan across all plugin pages
  useEffect(() => {
    let isMounted = true;
    const TARGETED_TARGETS = new Set([
      'core_integrity', 'database', 'users', 'vulnerabilities',
      'seo_spam', 'persistence', 'fim_only', 'filesystem_only'
    ]);

    const fetchActiveScan = async () => {
      if (document.hidden) return;
      try {
        const res: any = await apiRequest({ path: '/webcare-pro-security/v1/scan/active' });
        if (!isMounted) return;

        if (res?.is_running && res?.scan_id) {
          const total = Math.max(1, Number(res.total_files || 0));
          const scanned = Number(res.scanned_files || 0);
          const remaining = Number(res.remaining ?? Math.max(0, total - scanned));
          const phase = String(res.phase || 'batch');
          const target = String(res.scan_target || 'plugins_themes');
          let percent = 5;
          if (TARGETED_TARGETS.has(target)) {
            percent = phase === 'deep_audit' ? 75 : Math.min(85, Math.max(15, Math.round((scanned / total) * 85)));
          } else if (phase === 'deep_audit' || (total > 0 && remaining <= 0)) {
            percent = 90;
          } else if (res.total_files > 0) {
            percent = Math.min(85, Math.max(3, Math.round((scanned / total) * 85)));
          }

          setActiveScanSession({
            scanId: Number(res.scan_id),
            scanTarget: target,
            triggerType: String(res.trigger_type || 'manual'),
            scannedFiles: scanned,
            totalFiles: Number(res.total_files || 0),
            remaining,
            phase,
            lastFile: String(res.last_file || ''),
            elapsed: Number(res.elapsed || 0),
            telemetry: res.telemetry || null,
            percent,
          });
        } else {
          setActiveScanSession(null);
        }
      } catch (_) {}
    };

    fetchActiveScan();
    const interval = setInterval(fetchActiveScan, 3000);
    const handleScanVisibility = () => {
      if (!document.hidden) {
        fetchActiveScan();
      }
    };
    document.addEventListener('visibilitychange', handleScanVisibility);
    return () => {
      isMounted = false;
      clearInterval(interval);
      document.removeEventListener('visibilitychange', handleScanVisibility);
    };
  }, []);

  // Tick local elapsed seconds smoothly between 3s scan status polls
  useEffect(() => {
    if (!activeScanSession) return;
    const timer = setInterval(() => {
      if (!document.hidden) {
        setActiveScanSession((prev) => (prev ? { ...prev, elapsed: prev.elapsed + 1 } : null));
      }
    }, 1000);
    return () => clearInterval(timer);
  }, [Boolean(activeScanSession)]);

  const formatScanElapsed = (secs: number) => {
    const mins = Math.floor(Math.max(0, secs) / 60);
    const rem = Math.max(0, secs) % 60;
    return `${String(mins).padStart(2, '0')}:${String(rem).padStart(2, '0')}`;
  };

  const getScanTargetLabel = (target: string, triggerType: string) => {
    const targetedNames: Record<string, string> = {
      core_integrity: 'WordPress Core Integrity Audit',
      database: 'Database SQL & Content Injection Audit',
      users: 'User Privilege & Backdoor Audit',
      vulnerabilities: 'Plugin & Theme CVE Vulnerability Audit',
      seo_spam: 'SEO Spam & Malicious Redirect Audit',
      persistence: 'WP-Cron, MU-Plugin & Persistence Audit',
      fim_only: 'File Integrity Monitoring (FIM) Diff Audit',
      filesystem_only: 'Targeted Filesystem Malware Scan',
    };
    if (targetedNames[target]) return targetedNames[target];
    if (triggerType === 'scheduled') {
      return `Scheduled Auto Scan (${target === 'full' ? 'Full System' : 'Plugins & Themes'})`;
    }
    if (target === 'custom') return 'Custom Security Scan';
    if (target === 'full') return 'Complete Website Scan';
    return 'Quick Scan (Plugins & Themes)';
  };

  const handleAbortActiveScan = async () => {
    if (!activeScanSession || abortingScan) return;
    const confirmed = await confirmAction({
      title: 'Stop Active Security Scan',
      message: 'Are you sure you want to stop and cancel the currently running scan? In-progress checks will be aborted immediately.',
      confirmLabel: 'Stop Scan',
      variant: 'danger',
    });
    if (!confirmed) return;

    setAbortingScan(true);
    try {
      await apiRequest({
        path: '/webcare-pro-security/v1/scan/abort',
        method: 'POST',
        data: { scan_id: activeScanSession.scanId },
      });
      setActiveScanSession(null);
      toast.info('Active security scan was stopped and lock released.');
    } catch (err: any) {
      toast.error(err?.message || 'Failed to abort active scan.');
    } finally {
      setAbortingScan(false);
    }
  };

  // Poll for background database backup status
  useEffect(() => {
    let isMounted = true;
    const fetchActiveBackup = async () => {
      if (document.hidden) return;
      try {
        const root = (window as any).webcareScannerSettings?.root || '/wp-json/webcare-pro-security/v1';
        const nonce = (window as any).webcareScannerSettings?.nonce || '';
        const url = `${root}/backup/active`;
        const res = await fetch(url, {
          headers: {
            'X-WP-Nonce': nonce,
            'Content-Type': 'application/json',
          },
        });
        const data = await res.json();
        if (isMounted) {
          if (data?.success && data?.is_running && data?.session?.state) {
            const st = data.session.state;
            const tel = data.session.telemetry;
            setActiveBackupSession({
              isRunning: true,
              tablesCompleted: st.tables_completed || 0,
              totalTables: st.total_tables || 1,
              percent: tel?.overall_percent || 0,
            });
          } else {
            setActiveBackupSession(null);
          }
        }
      } catch (_) {}
    };

    fetchActiveBackup();
    const interval = setInterval(fetchActiveBackup, 3000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // Poll and sync 15-minute Safe Mode status (pauses when document is hidden)
  useEffect(() => {
    let isMounted = true;

    const checkSafeMode = async () => {
      if (document.hidden) return;
      try {
        const res = await apiRequest({ path: '/rescue/status?minutes=15', method: 'GET' });
        if (isMounted && res?.success) {
          const isPaused = Boolean(res?.pause_status?.paused);
          setRescuePaused(isPaused);
          setSafeModeSecondsLeft(res?.pause_status?.seconds_remaining || 0);
        }
      } catch (_) {}
    };

    checkSafeMode();
    const interval = setInterval(checkSafeMode, 5000);

    const handleVisibility = () => {
      if (!document.hidden) {
        checkSafeMode();
      }
    };
    document.addEventListener('visibilitychange', handleVisibility);

    return () => {
      isMounted = false;
      clearInterval(interval);
      document.removeEventListener('visibilitychange', handleVisibility);
    };
  }, []);

  // Safe Mode local countdown ticker
  useEffect(() => {
    if (!rescuePaused || safeModeSecondsLeft <= 0) return;

    const timer = setInterval(() => {
      if (!document.hidden) {
        setSafeModeSecondsLeft((prev) => (prev > 0 ? prev - 1 : 0));
      }
    }, 1000);

    return () => clearInterval(timer);
  }, [rescuePaused, safeModeSecondsLeft]);

  const handleResumeStrictFirewall = async () => {
    setResumingSafeMode(true);
    try {
      const res = await apiRequest({ path: '/rescue/resume', method: 'POST' });
      if (res?.success) {
        setRescuePaused(false);
        setSafeModeSecondsLeft(0);
        toast.success(res.message || 'Strict firewall resumed successfully.');
      } else {
        toast.error(res?.message || 'Failed to resume strict firewall.');
      }
    } catch (err: any) {
      toast.error(err?.message || 'Failed to resume strict firewall.');
    } finally {
      setResumingSafeMode(false);
    }
  };

  const formatSafeModeTime = (secs: number) => {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  };

  const toggleThemeMode = () => {
    const next = themeMode === 'dark' ? 'light' : 'dark';
    setThemeMode(next);
    applyWebCareTheme(next);
    try {
      window.dispatchEvent(new CustomEvent('webcare_theme_changed', { detail: next }));
    } catch {}
  };

  const toggleWorkspaceMode = () => {
    const next = currentWorkspaceMode === 'developer' ? 'simple' : 'developer';
    setMode(next);
  };

  useEffect(() => {
    applyWebCareTheme(themeMode);

    const handleStorage = (e: StorageEvent) => {
      if (e.key === 'webcare_theme_mode' && (e.newValue === 'light' || e.newValue === 'dark')) {
        setThemeMode(e.newValue);
        applyWebCareTheme(e.newValue);
      }
    };
    window.addEventListener('storage', handleStorage);
    return () => window.removeEventListener('storage', handleStorage);
  }, [themeMode]);

  // Keyboard shortcut: Ctrl+K or Cmd+K toggles the Quick-Jump Command Bar
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setQuickJumpOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const PAGE_MAP: Record<string, string> = {
    dashboard: 'webcare-pro-security',
    overview: 'webcare-pro-security',
    'webcare-pro-security': 'webcare-pro-security',
    scan: 'webcare-pro-scanner',
    scanner: 'webcare-pro-scanner',
    'webcare-pro-scanner': 'webcare-pro-scanner',
    'webcare-pro-scan': 'webcare-pro-scanner',
    firewall: 'webcare-pro-firewall',
    'webcare-pro-firewall': 'webcare-pro-firewall',
    logs: 'webcare-pro-logs',
    waf_logs: 'webcare-pro-logs',
    'webcare-pro-logs': 'webcare-pro-logs',
    'webcare-pro-waf-logs': 'webcare-pro-logs',
    auth: 'webcare-pro-login',
    login: 'webcare-pro-login',
    'webcare-pro-login': 'webcare-pro-login',
    'webcare-pro-auth': 'webcare-pro-login',
    vault: 'webcare-pro-backups',
    backup: 'webcare-pro-backups',
    backups: 'webcare-pro-backups',
    'webcare-pro-backups': 'webcare-pro-backups',
    'webcare-pro-vault': 'webcare-pro-backups',
    settings: 'webcare-pro-settings',
    'webcare-pro-settings': 'webcare-pro-settings',
    wizard: 'webcare-pro-setup',
    setup: 'webcare-pro-setup',
    'webcare-pro-setup': 'webcare-pro-setup',
    'webcare-pro-wizard': 'webcare-pro-setup',
  };

  const currentPillarId = activePillarId || (
    activeTab ? (PAGE_MAP[activeTab] || 'webcare-pro-security') : routeState.page
  );

  const navigateTo = (slug: string, tabParam?: string, sectionParam?: string) => {
    const targetPillar = PAGE_MAP[slug] || (slug.startsWith('webcare-pro-') ? slug : `webcare-pro-${slug}`);
    navigateToRoute(targetPillar, tabParam || '', sectionParam || '');
  };

  const handleMegaMenuNavigate = (tab: string, subTab?: string, nestedSubTab?: string) => {
    setMegaMenuOpen(false);
    const targetPillar = PAGE_MAP[tab] || (tab.startsWith('webcare-pro-') ? tab : `webcare-pro-${tab}`);
    navigateToRoute(targetPillar, subTab || '', nestedSubTab || '');
  };

  return (
    <div className={`webcare-container webcare-scanner-app ${themeMode === 'dark' ? 'webcare-theme-dark' : 'webcare-theme-light'}`} style={{ minHeight: '100vh' }}>
      <header className="header-bar webcare-two-tier-header webcare-header-hud">
        {/* TIER 1: BRAND IDENTITY, REASSURANCE & ACTIONS */}
        <div className="webcare-header-tier-top">
          <div className="brand-section">
            <div 
              style={{ cursor: 'pointer', display: 'flex', alignItems: 'center' }}
              onClick={() => navigateTo('dashboard')}
              title="Return to Executive Security Dashboard"
            >
              <WebCareBrandLogo size={36} />
            </div>
            <div>
              <div className="brand-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontFamily: 'var(--font-display, "Outfit", sans-serif)', fontSize: '18px', fontWeight: 800, color: 'var(--webcare-text-title)', letterSpacing: '-0.02em' }}>
                  WebCare <span className="highlight" style={{ color: '#0ea5e9' }}>Pro</span> Security
                </span>
              </div>
              <div className="brand-subtitle" style={{ marginTop: '2px', display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11.5px', color: 'var(--webcare-text-secondary)' }}>
                <span className="pulse-dot" style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#10b981', boxShadow: '0 0 0 3px rgba(16, 185, 129, 0.2)' }} />
                <span>Enterprise Protection Active</span>
                <span className="webcare-dot-bullet" />
                <span style={{ fontFamily: 'var(--font-mono, monospace)', fontWeight: 600, color: 'var(--webcare-text-secondary)' }}>v{((window as any).webcareScannerSettings?.version) || '2.5.0'}</span>
              </div>
            </div>
          </div>

          <div className="webcare-header-actions" style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
            {/* Quick-Jump Search Pill */}
            <button
              type="button"
              className="webcare-btn webcare-search-pill-btn"
              onClick={() => setQuickJumpOpen(true)}
              title="Search settings, logs & tools (Ctrl + K)"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                padding: '6px 12px',
                borderRadius: '8px',
                fontSize: '12px',
                fontWeight: 500,
                background: 'var(--webcare-bg-surface, #f8fafc)',
                color: 'var(--webcare-text-secondary, #475569)',
                border: '1px solid var(--webcare-border, #cbd5e1)',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <Search size={13} color="#6366f1" />
              <span>Search tools &amp; tasks...</span>
              <kbd style={{ fontSize: '10px', background: 'var(--webcare-bg-deep, #e2e8f0)', border: '1px solid var(--webcare-border, #cbd5e1)', padding: '1px 5px', borderRadius: '4px', fontWeight: 600 }}>
                ⌘K
              </kbd>
            </button>
            {/* Background Database Backup Live Indicator */}
            {activeBackupSession && activeBackupSession.isRunning && (
              <button
                type="button"
                className="webcare-btn"
                onClick={() => navigateTo('vault', 'backup')}
                title="Database backup is running in the background. Click to view live progress."
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '6px 12px',
                  borderRadius: '8px',
                  fontSize: '12px',
                  fontWeight: 700,
                  background: 'rgba(59, 130, 246, 0.1)',
                  color: '#2563eb',
                  border: '1px solid rgba(59, 130, 246, 0.3)',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  animation: 'pulse 2s infinite',
                }}
              >
                <Loader2 size={13} className="webcare-spin" />
                <span>DB Backup: {activeBackupSession.tablesCompleted}/{activeBackupSession.totalTables} ({activeBackupSession.percent}%)</span>
              </button>
            )}

            {/* Mode Switcher: Simple Mode vs. Developer Mode */}
            <button
              type="button"
              className={`webcare-mode-toggle-pill ${workspaceMode === 'advanced' ? 'is-advanced' : 'is-essential'}`}
              onClick={toggleWorkspaceMode}
              title={workspaceMode === 'essential'
                ? "Switch to Developer Mode (Reveals WireFilter Visual Rule Builder, webcare-policy.php status, Raw Regex/AST, MCP JSON-RPC, & WP-CLI)"
                : "Switch to Simple Mode (Plain-English security presets, 3-switch AI crawlers, 1-click unblock, and daily CVE alerts)"
              }
              aria-label="Toggle Simple Mode or Developer Mode"
            >
              <div className="webcare-mode-toggle-thumb">
                {workspaceMode === 'advanced' ? (
                  <SlidersHorizontal size={13} className="webcare-mode-icon" />
                ) : (
                  <ShieldCheck size={13} className="webcare-mode-icon" />
                )}
              </div>
              <div className="webcare-mode-toggle-label">
                <span className="webcare-mode-toggle-title">
                  {workspaceMode === 'advanced' ? 'Developer' : 'Simple'}
                </span>
                <span className={`webcare-mode-toggle-chip ${workspaceMode === 'advanced' ? 'chip-advanced' : 'chip-essential'}`}>
                  {workspaceMode === 'advanced' ? 'Pro Tools' : 'Owner'}
                </span>
              </div>
            </button>

            {/* Rescue Assistant Trigger ("Something Not Working?") */}
            <button
              type="button"
              className="webcare-btn"
              onClick={() => setRescueModalOpen(true)}
              title="Something Not Working? Click to Troubleshoot & 1-Click Fix My Site"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 12px',
                borderRadius: '8px',
                fontSize: '12px',
                fontWeight: 700,
                background: rescuePaused ? 'var(--webcare-status-warn-soft)' : 'var(--webcare-status-info-soft)',
                color: rescuePaused ? 'var(--webcare-status-warn)' : 'var(--webcare-status-info)',
                border: `1px solid ${rescuePaused ? 'var(--webcare-status-warn-border)' : 'var(--webcare-status-info-border)'}`,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              <Wrench size={13} />
              <span>{rescuePaused ? 'Test Mode Active' : 'Something Not Working?'}</span>
            </button>

            {/* Welcome Guide Trigger */}
            <button
              type="button"
              className="webcare-btn"
              onClick={() => setIsWelcomeModalOpen(true)}
              title="Open Welcome Guide & Pre-Flight Readiness"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 12px',
                borderRadius: '8px',
                fontSize: '12px',
                fontWeight: 700,
                background: 'rgba(6, 182, 212, 0.08)',
                color: '#0284c7',
                border: '1px solid rgba(6, 182, 212, 0.25)',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              <Sparkles size={13} color="#0284c7" />
              <span className="webcare-wizard-btn-text">Welcome Guide</span>
            </button>

            {/* Panic Button */}
            <button
              type="button"
              className="webcare-btn"
              onClick={() => navigateTo('settings', 'containment')}
              title="1-Click Emergency Incident Containment Protocol & Panic Lockdown"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 12px',
                borderRadius: '8px',
                fontSize: '12px',
                fontWeight: 700,
                background: 'rgba(239, 68, 68, 0.08)',
                color: '#dc2626',
                border: '1px solid rgba(239, 68, 68, 0.25)',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <ShieldAlert size={13} color="#dc2626" />
              <span className="webcare-panic-btn-text">Panic Button</span>
            </button>

            {/* Theme Toggle Button */}
            <button
              type="button"
              className="webcare-theme-toggle-btn"
              onClick={toggleThemeMode}
              title={`Switch to ${themeMode === 'dark' ? 'Light / White Mode' : 'Dark Mode'}`}
              aria-label={`Switch to ${themeMode === 'dark' ? 'Light / White Mode' : 'Dark Mode'}`}
            >
              {themeMode === 'dark' ? (
                <>
                  <Sun size={14} className="webcare-theme-toggle-icon" />
                  <span className="webcare-theme-toggle-text">White Mode</span>
                </>
              ) : (
                <>
                  <Moon size={14} className="webcare-theme-toggle-icon" />
                  <span className="webcare-theme-toggle-text">Dark Mode</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* TIER 2: PRIMARY NAVIGATION ROW (5-Tab Calm Mode vs Full 7-Pillar + All Modules in Developer Mode) */}
        <div className="webcare-header-tier-bottom">
          <nav className="nav-tabs" aria-label="Main Security Pillars">
            {/* Overview / Peace of Mind */}
            <button
              type="button"
              className={`nav-tab-btn ${currentPillarId === 'webcare-pro-security' ? 'active' : ''}`}
              id="tabBtnDashboard"
              onClick={() => navigateTo('webcare-pro-security')}
              aria-current={currentPillarId === 'webcare-pro-security' ? 'page' : undefined}
            >
              <LayoutDashboard size={15} />
              <span>{isDeveloperMode ? 'Dashboard' : 'Overview ("Peace of Mind")'}</span>
            </button>

            {/* Shield / Firewall */}
            <button
              type="button"
              className={`nav-tab-btn ${currentPillarId === 'webcare-pro-firewall' ? 'active' : ''}`}
              id="tabBtnFirewall"
              onClick={() => navigateTo('webcare-pro-firewall')}
              aria-current={currentPillarId === 'webcare-pro-firewall' ? 'page' : undefined}
            >
              <Shield size={15} />
              <span>{isDeveloperMode ? 'Firewall' : 'Shield'}</span>
            </button>

            {/* Developer Mode Only: Logs & Bans */}
            {isDeveloperMode && (
              <button
                type="button"
                className={`nav-tab-btn ${currentPillarId === 'webcare-pro-logs' ? 'active' : ''}`}
                id="tabBtnLogs"
                onClick={() => navigateTo('webcare-pro-logs')}
                aria-current={currentPillarId === 'webcare-pro-logs' ? 'page' : undefined}
              >
                <FileText size={15} />
                <span>Logs &amp; Bans</span>
              </button>
            )}

            {/* Site Scan / Malware Scanner */}
            <button
              type="button"
              className={`nav-tab-btn ${currentPillarId === 'webcare-pro-scanner' ? 'active' : ''}`}
              id="tabBtnScan"
              onClick={() => navigateTo('webcare-pro-scanner')}
              aria-current={currentPillarId === 'webcare-pro-scanner' ? 'page' : undefined}
            >
              <Radar size={15} />
              <span>{isDeveloperMode ? 'Malware & Scanner' : 'Site Scan'}</span>
            </button>

            {/* Login Safety / Login & Access */}
            <button
              type="button"
              className={`nav-tab-btn ${currentPillarId === 'webcare-pro-login' ? 'active' : ''}`}
              id="tabBtnIdentity"
              onClick={() => navigateTo('webcare-pro-login')}
              aria-current={currentPillarId === 'webcare-pro-login' ? 'page' : undefined}
            >
              <Users size={15} />
              <span>{isDeveloperMode ? 'Login & Access' : 'Login Safety'}</span>
            </button>

            {/* Developer Mode Only: Backups & Vault */}
            {isDeveloperMode && (
              <button
                type="button"
                className={`nav-tab-btn ${currentPillarId === 'webcare-pro-backups' ? 'active' : ''}`}
                id="tabBtnVault"
                onClick={() => navigateTo('webcare-pro-backups')}
                aria-current={currentPillarId === 'webcare-pro-backups' ? 'page' : undefined}
              >
                <Server size={15} />
                <span>Backups &amp; Vault</span>
              </button>
            )}

            {/* Settings */}
            <button
              type="button"
              className={`nav-tab-btn ${currentPillarId === 'webcare-pro-settings' ? 'active' : ''}`}
              id="tabBtnSettings"
              onClick={() => navigateTo('webcare-pro-settings')}
              aria-current={currentPillarId === 'webcare-pro-settings' ? 'page' : undefined}
            >
              <SettingsIcon size={15} />
              <span>{isDeveloperMode ? 'Settings & Doctor' : 'Settings'}</span>
            </button>

            {/* Quick-Jump Mega Menu Button (Available in Developer Mode or via All Modules button) */}
            <button
              type="button"
              className={`nav-tab-btn webcare-mega-menu-trigger ${megaMenuOpen ? 'active' : ''}`}
              id="tabBtnAllModules"
              onClick={() => setMegaMenuOpen(true)}
              title="Explore all modules, tools & settings"
            >
              <Grid size={15} />
              <span>All Modules</span>
            </button>
          </nav>
        </div>
      </header>

      {/* Dynamic Canonical Breadcrumb Trail from RouteRegistry */}
      {(() => {
        const activePillar = PILLAR_MAP[currentPillarId] || PILLAR_MAP['webcare-pro-security'];
        const currentTabId = routeState.tab || activePillar?.default_tab || '';
        const activeTabObj = activePillar?.tabs?.find((t) => t.id === currentTabId);
        const subLabel = activeTabObj?.label;
        const currentSecId = routeState.section || activeTabObj?.default_section || '';
        const activeSecObj = activeTabObj?.sections?.find((s) => s.id === currentSecId);
        const secLabel = activeSecObj?.label;

        return (
          <nav
            aria-label="Breadcrumb"
            className="webcare-breadcrumbs-bar"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '6px 20px',
              fontSize: '11.5px',
              fontWeight: 500,
              color: 'var(--webcare-text-muted, #64748b)',
              background: 'var(--webcare-bg-surface, #f8fafc)',
              borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
              lineHeight: 1,
            }}
          >
            <button
              type="button"
              onClick={() => navigateTo('webcare-pro-security')}
              style={{
                background: 'none',
                border: 'none',
                padding: 0,
                color: 'var(--webcare-text-muted, #64748b)',
                fontSize: '11.5px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
              onMouseEnter={(e) => { e.currentTarget.style.color = '#4f46e5'; }}
              onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--webcare-text-muted, #64748b)'; }}
            >
              WebCare Pro
            </button>

            <span style={{ opacity: 0.5 }}>›</span>

            <button
              type="button"
              onClick={() => navigateTo(activePillar?.id || 'webcare-pro-security')}
              style={{
                background: 'none',
                border: 'none',
                padding: 0,
                color: subLabel ? 'var(--webcare-text-muted, #64748b)' : 'var(--webcare-text-primary, #0f172a)',
                fontSize: '11.5px',
                fontWeight: subLabel ? 500 : 700,
                cursor: 'pointer',
              }}
              onMouseEnter={(e) => { e.currentTarget.style.color = '#4f46e5'; }}
              onMouseLeave={(e) => { e.currentTarget.style.color = subLabel ? 'var(--webcare-text-muted, #64748b)' : 'var(--webcare-text-primary, #0f172a)'; }}
              aria-current={!subLabel ? 'page' : undefined}
            >
              {activePillar?.menu_title || 'Overview'}
            </button>

            {subLabel && (
              <>
                <span style={{ opacity: 0.5 }}>›</span>
                <span 
                  style={{ 
                    color: secLabel ? 'var(--webcare-text-muted, #64748b)' : 'var(--webcare-text-primary, #0f172a)', 
                    fontWeight: secLabel ? 500 : 700 
                  }}
                  aria-current={!secLabel ? 'page' : undefined}
                >
                  {subLabel}
                </span>
              </>
            )}

            {secLabel && (
              <>
                <span style={{ opacity: 0.5 }}>›</span>
                <span style={{ color: 'var(--webcare-text-primary, #0f172a)', fontWeight: 700 }} aria-current="page">
                  {secLabel}
                </span>
              </>
            )}
          </nav>
        );
      })()}

      {/* Sticky Safe Mode Banner */}
      {rescuePaused && (
        <div
          role="alert"
          className="webcare-safe-mode-banner"
          style={{
            position: 'sticky',
            top: '0',
            zIndex: 999,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
            padding: '10px 20px',
            background: 'linear-gradient(90deg, #fffbeb 0%, #fef3c7 100%)',
            border: '1px solid #fde68a',
            borderTop: 'none',
            borderRadius: '0 0 10px 10px',
            boxShadow: '0 4px 6px -1px rgba(217, 119, 6, 0.1)',
            color: '#92400e',
            fontSize: '13px',
            fontWeight: 500,
            animation: 'webcare-fade-in 0.2s ease-out',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1 }}>
            <div
              style={{
                width: '26px',
                height: '26px',
                borderRadius: '6px',
                background: '#fef3c7',
                border: '1px solid #fde68a',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#d97706',
                flexShrink: 0,
              }}
            >
              <AlertTriangle size={15} />
            </div>
            <div>
              <strong style={{ fontWeight: 700, color: '#78350f' }}>Safe Mode Active</strong> — Heuristic blocking paused ({formatSafeModeTime(safeModeSecondsLeft)} remaining). Zero-tolerance RCE/SQLi protection remains active.
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button
              type="button"
              onClick={handleResumeStrictFirewall}
              disabled={resumingSafeMode}
              className="webcare-btn-amber-resume"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '5px 14px',
                borderRadius: '6px',
                fontSize: '12px',
                fontWeight: 700,
                background: '#d97706',
                color: '#ffffff',
                border: 'none',
                cursor: resumingSafeMode ? 'not-allowed' : 'pointer',
                boxShadow: '0 1px 2px rgba(0, 0, 0, 0.08)',
                transition: 'all 0.15s ease',
              }}
            >
              {resumingSafeMode ? (
                <>
                  <Loader2 size={12} className="webcare-spin" />
                  <span>Resuming...</span>
                </>
              ) : (
                <>
                  <PlayCircle size={13} />
                  <span>Resume Strict Firewall</span>
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {/* Global Persistent Active Scan Progress Bar Banner across all standalone plugin pages */}
      {activeScanSession && (
        <div className="webcare-active-scan-banner" style={{ marginTop: '14px' }}>
          <div className="webcare-active-scan-banner-info" style={{ flex: 1, minWidth: '260px' }}>
            <div className="webcare-active-scan-spinner-box">
              <Loader2 size={20} className="webcare-spin-icon" />
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="webcare-active-scan-title" style={{ flexWrap: 'wrap' }}>
                <span><strong>Scan in Progress:</strong> </span>
                <span>{getScanTargetLabel(activeScanSession.scanTarget, activeScanSession.triggerType)}</span>
                <span className="webcare-active-scan-percent">{activeScanSession.percent}%</span>
                <span className="webcare-active-scan-telemetry-chip">
                  <span>⏱️ {formatScanElapsed(activeScanSession.elapsed)}</span>
                  {activeScanSession.totalFiles > 0 && (
                    <span> • 📄 {activeScanSession.scannedFiles.toLocaleString()} / {activeScanSession.totalFiles.toLocaleString()}</span>
                  )}
                  {activeScanSession.telemetry?.memory_mb && <span> • 💾 {activeScanSession.telemetry.memory_mb} MB</span>}
                  {activeScanSession.telemetry?.cpu_percent !== null && activeScanSession.telemetry?.cpu_percent !== undefined && (
                    <span> • ⚡ {activeScanSession.telemetry.cpu_percent}% CPU</span>
                  )}
                </span>
              </div>
              <div className="webcare-active-scan-subtitle" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                <span>
                  {activeScanSession.lastFile
                    ? activeScanSession.lastFile
                    : activeScanSession.phase === 'deep_audit'
                    ? 'Executing deep engine correlation & database integrity inspection...'
                    : 'Background worker scanning site files...'}
                </span>
              </div>
              <div className="webcare-progress-bar-bg" style={{ height: '5px', marginTop: '8px', background: 'rgba(99, 102, 241, 0.16)' }}>
                <div
                  className="webcare-progress-fill"
                  style={{
                    width: `${Math.min(100, Math.max(3, activeScanSession.percent))}%`,
                    background: 'linear-gradient(90deg, #4f46e5 0%, #7c3aed 100%)',
                    borderRadius: '999px',
                  }}
                />
              </div>
            </div>
          </div>
          <div className="webcare-active-scan-actions">
            <button
              type="button"
              className="webcare-btn"
              onClick={() => {
                const isTargeted = [
                  'core_integrity', 'database', 'users', 'vulnerabilities',
                  'seo_spam', 'persistence', 'fim_only', 'filesystem_only'
                ].includes(activeScanSession.scanTarget);
                window.location.href = buildAdminUrl('webcare-pro-scanner', isTargeted ? 'targeted' : 'malware');
              }}
              style={{ fontSize: '12px', padding: '6px 14px', background: '#3b82f6', color: '#fff' }}
            >
              <span>View Active Scan</span>
            </button>
            <button
              type="button"
              className="webcare-btn"
              disabled={abortingScan}
              onClick={handleAbortActiveScan}
              style={{ fontSize: '12px', padding: '6px 14px', background: '#ef4444', color: '#fff', display: 'inline-flex', alignItems: 'center', gap: '6px', opacity: abortingScan ? 0.7 : 1 }}
            >
              <XCircle size={14} />
              <span>{abortingScan ? 'Stopping...' : 'Stop Scan'}</span>
            </button>
          </div>
        </div>
      )}

      {/* Main Content Area */}
      <main className="webcare-main-content" style={{ marginTop: '16px' }}>
        {children}
      </main>

      {/* Global Command Center / All Modules Mega-Menu */}
      <MegaMenuModal
        isOpen={megaMenuOpen}
        onClose={() => setMegaMenuOpen(false)}
        onNavigate={handleMegaMenuNavigate}
        currentTab={activeTab}
      />

      {/* Welcome Guide & Pre-Flight Readiness Modal */}
      <WelcomeModal
        isOpen={isWelcomeModalOpen}
        onClose={() => setIsWelcomeModalOpen(false)}
        onStartScan={() => navigateTo('scan')}
      />

      {/* 1-Click Fix My Site Rescue Assistant Modal */}
      <RescueAssistantModal
        isOpen={rescueModalOpen}
        onClose={() => setRescueModalOpen(false)}
        onPauseChange={(ps) => {
          setRescuePaused(Boolean(ps?.paused));
          setSafeModeSecondsLeft(ps?.seconds_remaining || 0);
        }}
      />

      {/* Quick-Jump Command Bar Modal (Ctrl+K / ⌘K) */}
      <QuickJumpModal
        isOpen={quickJumpOpen}
        onClose={() => setQuickJumpOpen(false)}
        onNavigate={(slug, tab, section) => {
          let target = PAGE_MAP[slug] || (slug.startsWith('webcare-pro-') ? slug : `webcare-pro-${slug}`);
          if (tab && !target.includes('&tab=')) {
            target += `&tab=${tab}`;
          }
          if (section && !target.includes('&section=')) {
            target += `&section=${section}`;
          }
          window.location.href = `admin.php?page=${target}`;
        }}
        onSwitchToAdvancedMode={() => {
          if (!isDeveloperMode) {
            setMode('developer');
            toast.info('Switched to Developer Mode for advanced rule configuration.');
          }
        }}
      />

      {/* Global In-Page Toast & Confirm Modal Providers */}
      <ToastProvider />
      <ConfirmModalHost />
    </div>
  );
};

export default WebCareShell;
