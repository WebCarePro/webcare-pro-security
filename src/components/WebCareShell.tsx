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
  PlayCircle
} from 'lucide-react';
import WebCareBrandLogo from './WebCareBrandLogo';
import MegaMenuModal from './MegaMenuModal';
import WelcomeModal from './WelcomeModal';
import { RescueAssistantModal } from './RescueAssistantModal';
import { applyWebCareTheme, getWebCareTheme } from '../utils/theme';
import { apiRequest } from '../utils/api';
import { toast } from '../utils/dialog';
import { useWorkspaceMode } from '../hooks/useWorkspaceMode';

interface WebCareShellProps {
  activeTab: 'dashboard' | 'scan' | 'firewall' | 'modular_waf' | 'waf_logs' | 'auth' | 'vault' | 'fim' | 'forensics' | 'settings' | 'notifications' | 'activity_logs' | 'cron_manager' | 'about' | 'wizard';
  children: ReactNode;
}

export const WebCareShell = ({ activeTab, children }: WebCareShellProps) => {
  const [themeMode, setThemeMode] = useState<'dark' | 'light'>(() => getWebCareTheme());
  const { mode: currentWorkspaceMode, isDeveloperMode, setMode } = useWorkspaceMode();
  const workspaceMode = isDeveloperMode ? 'advanced' : 'essential';

  const [megaMenuOpen, setMegaMenuOpen] = useState(false);
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

  // Keyboard shortcut: Ctrl+K or Cmd+K toggles the All Modules Mega Menu
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setMegaMenuOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const PAGE_MAP: Record<string, string> = {
    dashboard: 'webcare-pro-security',
    scan: 'webcare-pro-scan',
    targeted: 'webcare-pro-scan&tab=targeted',
    logs: 'webcare-pro-scan&tab=logs',
    fim: 'webcare-pro-fim',
    vulnerabilities: 'webcare-pro-scan&tab=vulnerabilities',
    firewall: 'webcare-pro-firewall',
    modular_waf: 'webcare-pro-modular-waf',
    waf_logs: 'webcare-pro-waf-logs',
    vpatch: 'webcare-pro-firewall&tab=vpatch',
    auth: 'webcare-pro-auth',
    vault: 'webcare-pro-vault',
    quarantine: 'webcare-pro-vault&tab=quarantine',
    backup: 'webcare-pro-vault&tab=backup',
    forensics: 'webcare-pro-forensics',
    server: 'webcare-pro-vault&tab=server',
    settings: 'webcare-pro-settings',
    notifications: 'webcare-pro-notifications',
    activity_logs: 'webcare-pro-activity-logs',
    cron_manager: 'webcare-pro-cron-manager',
    about: 'webcare-pro-settings&tab=about',
    wizard: 'webcare-pro-wizard',
  };

  const navigateTo = (slug: string, tabParam?: string) => {
    let target = PAGE_MAP[slug] || (slug.startsWith('webcare-pro-') ? slug : `webcare-pro-${slug}`);
    if (tabParam) {
      if (target.includes('&tab=')) {
        target += `&subtab=${tabParam}`;
      } else {
        target += `&tab=${tabParam}`;
      }
    }
    window.location.href = `admin.php?page=${target}`;
  };

  const handleMegaMenuNavigate = (tab: string, subTab?: string, nestedSubTab?: string) => {
    setMegaMenuOpen(false);
    let target = PAGE_MAP[tab] || (tab.startsWith('webcare-pro-') ? tab : `webcare-pro-${tab}`);
    if (subTab && !target.includes('&tab=')) {
      target += `&tab=${subTab}`;
    }
    if (nestedSubTab && !target.includes('&subtab=')) {
      target += `&subtab=${nestedSubTab}`;
    }
    window.location.href = `admin.php?page=${target}`;
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

        {/* TIER 2: PRIMARY NAVIGATION ROW (6 CORE PILLARS + ALL MODULES) */}
        <div className="webcare-header-tier-bottom">
          <nav className="nav-tabs">
            <button
              type="button"
              className={`nav-tab-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
              id="tabBtnDashboard"
              onClick={() => navigateTo('dashboard')}
            >
              <LayoutDashboard size={15} />
              <span>Dashboard</span>
            </button>

            <button
              type="button"
              className={`nav-tab-btn ${['scan', 'targeted', 'logs', 'fim', 'vulnerabilities'].includes(activeTab) ? 'active' : ''}`}
              id="tabBtnScan"
              onClick={() => navigateTo('scan')}
            >
              <Radar size={15} />
              <span>Scanner &amp; CVEs</span>
            </button>

            <button
              type="button"
              className={`nav-tab-btn ${['firewall', 'modular_waf', 'waf_logs', 'vpatch'].includes(activeTab) ? 'active' : ''}`}
              id="tabBtnFirewall"
              onClick={() => navigateTo('firewall')}
            >
              <Shield size={15} />
              <span>Firewall &amp; Logs</span>
            </button>

            <button
              type="button"
              className={`nav-tab-btn ${activeTab === 'auth' ? 'active' : ''}`}
              id="tabBtnIdentity"
              onClick={() => navigateTo('auth')}
            >
              <Users size={15} />
              <span>Login &amp; Access</span>
            </button>

            <button
              type="button"
              className={`nav-tab-btn ${['vault', 'quarantine', 'backup', 'forensics', 'server'].includes(activeTab) ? 'active' : ''}`}
              id="tabBtnVault"
              onClick={() => navigateTo('vault')}
            >
              <Server size={15} />
              <span>Vault &amp; Tools</span>
            </button>

            <button
              type="button"
              className={`nav-tab-btn ${['settings', 'notifications', 'activity_logs', 'cron_manager', 'about'].includes(activeTab) ? 'active' : ''}`}
              id="tabBtnSettings"
              onClick={() => navigateTo('settings')}
            >
              <SettingsIcon size={15} />
              <span>Settings &amp; Doctor</span>
            </button>

            {/* Quick-Jump Mega Menu Button */}
            <button
              type="button"
              className={`nav-tab-btn webcare-mega-menu-trigger ${megaMenuOpen ? 'active' : ''}`}
              id="tabBtnAllModules"
              onClick={() => setMegaMenuOpen(true)}
              title="Explore all modules, tools & settings (Ctrl + K)"
            >
              <Grid size={15} />
              <span>All Modules</span>
              <span className="webcare-kbd-shortcut">⌘K</span>
            </button>
          </nav>
        </div>
      </header>

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
    </div>
  );
};

export default WebCareShell;
