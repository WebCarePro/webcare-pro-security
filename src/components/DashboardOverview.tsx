import React, { useState, useEffect, useMemo } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Shield,
  Activity,
  Play,
  Pause,
  CheckCircle2,
  Database,
  ArrowRight,
  Lock,
  Server,
  Zap,
  Globe,
  RefreshCw,
  Search,
  Ban,
  Clock,
  Layers,
  Sparkles,
  Check,
  AlertTriangle,
  FolderArchive,
} from 'lucide-react';
import { apiRequest } from '../utils/api';
import { buildAdminUrl } from '../utils/routeRegistry';
import './DashboardOverview.css';

export interface DashboardOverviewProps {
  currentScan: any;
  uniqueIssues: any[];
  firewallStatus: any;
  firewallLogs: any[];
  serverInfo: any;
  vulnReport: any;
  quarantinedFiles: any[];
  backups?: any[];
  isScanning: boolean;
  onStartScan: () => void;
  onOpenRescueModal: () => void;
  isRescuePaused?: boolean;
  onNavigate: (tab: any, subTab?: string, nestedSubTab?: string) => void;
  formatRelativeTime: (dateStr: any) => string;
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  currentScan,
  uniqueIssues,
  firewallStatus,
  firewallLogs,
  serverInfo,
  vulnReport,
  quarantinedFiles,
  backups = [],
  isScanning,
  onStartScan,
  onOpenRescueModal,
  isRescuePaused = false,
  onNavigate,
  formatRelativeTime,
}) => {
  const [internalPaused, setInternalPaused] = useState<boolean>(isRescuePaused);
  const [pauseSecondsLeft, setPauseSecondsLeft] = useState<number>(0);
  const [isPausing, setIsPausing] = useState<boolean>(false);

  // Sync rescue pause status from backend or props
  useEffect(() => {
    setInternalPaused(isRescuePaused);
  }, [isRescuePaused]);

  // Load rescue pause timer if active
  useEffect(() => {
    let active = true;
    apiRequest({ path: '/rescue/status?minutes=15', method: 'GET' })
      .then((res: any) => {
        if (!active || !res?.success) return;
        if (res.pause_status?.paused) {
          setInternalPaused(true);
          setPauseSecondsLeft(res.pause_status.seconds_remaining || 0);
        } else {
          setInternalPaused(false);
          setPauseSecondsLeft(0);
        }
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, []);

  // Countdown timer for safe mode pause
  useEffect(() => {
    if (!internalPaused || pauseSecondsLeft <= 0) return;
    const interval = setInterval(() => {
      setPauseSecondsLeft((prev) => {
        if (prev <= 1) {
          setInternalPaused(false);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [internalPaused, pauseSecondsLeft]);

  // Handle 15-Min Safe Mode Quick Toggle
  const handleToggleSafeMode = async () => {
    if (internalPaused) {
      setIsPausing(true);
      try {
        const res = await apiRequest({ path: '/rescue/resume', method: 'POST' });
        if (res?.success) {
          setInternalPaused(false);
          setPauseSecondsLeft(0);
        }
      } catch {
        onOpenRescueModal();
      } finally {
        setIsPausing(false);
      }
    } else {
      setIsPausing(true);
      try {
        const res = await apiRequest({ path: '/rescue/pause-15m', method: 'POST' });
        if (res?.success) {
          setInternalPaused(true);
          setPauseSecondsLeft(res.pause_status?.seconds_remaining || 900);
        } else {
          onOpenRescueModal();
        }
      } catch {
        onOpenRescueModal();
      } finally {
        setIsPausing(false);
      }
    }
  };

  // Evaluate active threats and security score
  const openIssues = useMemo(
    () => (uniqueIssues || []).filter((i) => i.status === 'open'),
    [uniqueIssues]
  );
  const reviewItemsCount = openIssues.length;

  const { healthScore, protectionStatusLabel, protectionStatusColor } = useMemo(() => {
    let activeRaw = 0;
    for (const issue of openIssues) {
      const conf = issue.confidence && issue.confidence > 1 ? issue.confidence / 100 : issue.confidence || 1;
      if (issue.severity === 'critical') activeRaw += 40 * conf;
      else if (issue.severity === 'high') activeRaw += 15 * conf;
      else if (issue.severity === 'medium') activeRaw += 5 * conf;
      else if (issue.severity === 'low') activeRaw += 1 * conf;
    }
    const activeRiskScore = Math.min(100, Math.round(activeRaw));
    const score = Math.max(0, 100 - activeRiskScore);

    let label = 'Strong';
    let color = '#10b981';
    if (score < 60) {
      label = 'Needs Attention';
      color = '#ef4444';
    } else if (score < 85) {
      label = 'Good';
      color = '#f59e0b';
    }

    return { healthScore: score, protectionStatusLabel: label, protectionStatusColor: color };
  }, [openIssues]);

  // Threats blocked count
  const threatsBlockedCount = firewallStatus?.total_blocks ?? 0;

  // Latest backup info
  const latestBackup = backups && backups.length > 0 ? backups[0] : null;
  const latestBackupTime = latestBackup
    ? formatRelativeTime(latestBackup.created_at || latestBackup.timestamp || latestBackup.date)
    : null;

  // Overall State Evaluation for Peace-of-Mind Hero
  let heroState: 'protected' | 'review' | 'paused' | 'scanning' = 'protected';
  if (isScanning) {
    heroState = 'scanning';
  } else if (internalPaused) {
    heroState = 'paused';
  } else if (reviewItemsCount > 0) {
    heroState = 'review';
  }

  // Format pause timer display mm:ss
  const formatPauseTimer = (secs: number) => {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}:${s < 10 ? '0' : ''}${s}`;
  };

  // Circular score progress calculations (r = 18, circumference = 2 * PI * 18 ~ 113.1)
  const ringRadius = 18;
  const ringCircumference = 2 * Math.PI * ringRadius;
  const strokeDashoffset = ringCircumference - (healthScore / 100) * ringCircumference;

  // Vulnerability count for Plugin & Theme Risks tile
  const vulnTotal = (vulnReport?.plugins_vulnerable || 0) + (vulnReport?.themes_vulnerable || 0);

  // Extract exact runtime telemetry from serverInfo (supporting both structured serverInfo and flat fallbacks)
  const resolvedPhpVersion = useMemo(() => {
    return (
      serverInfo?.php?.version ||
      serverInfo?.php_version ||
      (window as any).webcareScannerSettings?.serverInfo?.php?.version ||
      '8.4+'
    );
  }, [serverInfo]);

  const resolvedWpVersion = useMemo(() => {
    return (
      serverInfo?.wordpress?.version ||
      serverInfo?.wp_version ||
      (window as any).webcareScannerSettings?.serverInfo?.wordpress?.version ||
      '7.0+'
    );
  }, [serverInfo]);

  const resolvedServerEngine = useMemo(() => {
    const rawSoftware =
      serverInfo?.server?.software ||
      serverInfo?.server_software ||
      (window as any).webcareScannerSettings?.serverInfo?.server?.software ||
      '';

    if (rawSoftware) {
      if (rawSoftware.toLowerCase().includes('apache')) return 'Apache';
      if (rawSoftware.toLowerCase().includes('litespeed')) return 'LiteSpeed';
      if (rawSoftware.toLowerCase().includes('nginx')) return 'Nginx';
      if (rawSoftware.toLowerCase().includes('caddy')) return 'Caddy';
      if (rawSoftware.toLowerCase().includes('iis')) return 'IIS';
      return rawSoftware.split('/')[0].split(' ')[0];
    }
    return 'Apache';
  }, [serverInfo]);

  return (
    <div className="wcp-dash-container">
      {/* =========================================================================
          1. Hero Sanctuary Card (.wcp-dash-hero)
         ========================================================================= */}
      <section className={`wcp-dash-hero is-${heroState}`}>
        <div className="wcp-dash-hero-glow" />

        <div className="wcp-dash-hero-content">
          {/* Animated Living Shield Emblem */}
          <div className="wcp-dash-emblem-wrap">
            <svg
              className="wcp-dash-emblem-svg"
              viewBox="0 0 84 84"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              {/* Outer Breathing Ring */}
              <circle
                className="wcp-dash-ring-outer"
                cx="42"
                cy="42"
                r="38"
                stroke={
                  heroState === 'scanning'
                    ? '#6366f1'
                    : heroState === 'review' || heroState === 'paused'
                    ? '#f59e0b'
                    : '#10b981'
                }
                strokeWidth="1.5"
              />

              {/* Inner Breathing Ring */}
              <circle
                className="wcp-dash-ring-inner"
                cx="42"
                cy="42"
                r="31"
                stroke={
                  heroState === 'scanning'
                    ? '#6366f1'
                    : heroState === 'review' || heroState === 'paused'
                    ? '#f59e0b'
                    : '#10b981'
                }
                strokeWidth="1.5"
              />

              {/* Rotating Dashed Orbital Ring */}
              <circle
                className="wcp-dash-ring-orbital"
                cx="42"
                cy="42"
                r="25"
                stroke={
                  heroState === 'scanning'
                    ? '#818cf8'
                    : heroState === 'review' || heroState === 'paused'
                    ? '#fbbf24'
                    : '#34d399'
                }
                strokeWidth="1.5"
              />
            </svg>

            {/* Emblem Core Center */}
            <div className="wcp-dash-emblem-core">
              {heroState === 'scanning' ? (
                <RefreshCw size={24} className="wcp-dash-spin" />
              ) : heroState === 'paused' ? (
                <Pause size={22} />
              ) : heroState === 'review' ? (
                <ShieldAlert size={24} />
              ) : (
                <ShieldCheck size={26} />
              )}
            </div>
          </div>

          {/* Calm Status Copy */}
          <div className="wcp-dash-hero-body">
            <div className="wcp-dash-status-pill-row">
              <span className="wcp-dash-status-pill">
                <span className="wcp-dash-pill-dot" />
                {heroState === 'scanning'
                  ? 'Security Scan Running'
                  : heroState === 'paused'
                  ? `Safe Mode Active • ${formatPauseTimer(pauseSecondsLeft)}`
                  : 'Real-Time Shield Active'}
              </span>

              <span className="wcp-dash-privacy-pill">
                <Lock size={12} />
                100% On-Premise Shield
              </span>
            </div>

            <h1 className="wcp-dash-hero-title">
              {heroState === 'scanning'
                ? 'Security scan is currently evaluating your files'
                : heroState === 'paused'
                ? 'Safe Mode is active — firewall paused temporarily'
                : reviewItemsCount > 0
                ? `Protection is active — ${reviewItemsCount} item${
                    reviewItemsCount === 1 ? '' : 's'
                  } ready for review`
                : 'Your site is protected and running smoothly'}
            </h1>

            <p className="wcp-dash-hero-desc">
              {heroState === 'scanning'
                ? 'Inspecting core files, plugin structures, and server configuration in non-blocking batches.'
                : heroState === 'paused'
                ? 'Firewall rules are temporarily paused for troubleshooting. All core exploit shields resume automatically.'
                : reviewItemsCount > 0
                ? 'Autonomous defenses are filtering malicious traffic. Recommended security advisories are prepared for your review.'
                : 'All sentinels are active. WebCare Pro is filtering traffic, monitoring filesystem integrity, and defending your perimeter.'}
            </p>
          </div>

          {/* Primary Actions (Right) */}
          <div className="wcp-dash-hero-actions">
            <button
              type="button"
              className="wcp-dash-btn-primary"
              onClick={onStartScan}
              disabled={isScanning}
            >
              {isScanning ? (
                <>
                  <RefreshCw size={14} className="wcp-dash-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <Play size={14} fill="currentColor" />
                  <span>Run Quick Scan</span>
                </>
              )}
            </button>

            <button
              type="button"
              className={`wcp-dash-btn-secondary ${internalPaused ? 'is-resuming' : ''}`}
              onClick={handleToggleSafeMode}
              disabled={isPausing}
              title={
                internalPaused
                  ? 'Resume firewall protection immediately'
                  : 'Temporarily pause strict heuristic checks for 15 minutes'
              }
            >
              {internalPaused ? (
                <>
                  <Play size={13} fill="currentColor" />
                  <span>Resume Protection</span>
                </>
              ) : (
                <>
                  <Clock size={13} />
                  <span>15-Min Safe Mode</span>
                </>
              )}
            </button>
          </div>
        </div>
      </section>

      {/* =========================================================================
          2. 4-Card Bento KPI Row (.wcp-dash-kpi-grid)
         ========================================================================= */}
      <section className="wcp-dash-kpi-grid">
        {/* KPI 1: Protection Score */}
        <div
          className="wcp-dash-kpi-card"
          onClick={() => handleTileNavigate('settings', 'doctor')}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') handleTileNavigate('settings', 'doctor');
          }}
        >
          <div className="wcp-dash-kpi-top">
            <span className="wcp-dash-kpi-label">Protection Score</span>
            <div className="wcp-dash-progress-ring-wrap">
              <svg className="wcp-dash-progress-ring-svg" viewBox="0 0 44 44">
                <circle
                  className="wcp-dash-progress-ring-bg"
                  cx="22"
                  cy="22"
                  r={ringRadius}
                  strokeWidth="3.5"
                  fill="none"
                />
                <circle
                  className="wcp-dash-progress-ring-fg"
                  cx="22"
                  cy="22"
                  r={ringRadius}
                  strokeWidth="3.5"
                  fill="none"
                  stroke={protectionStatusColor}
                  strokeDasharray={ringCircumference}
                  strokeDashoffset={strokeDashoffset}
                />
              </svg>
              <span className="wcp-dash-progress-ring-text wcp-dash-tabular">{healthScore}</span>
            </div>
          </div>

          <div className="wcp-dash-kpi-center">
            <span
              className="wcp-dash-kpi-val wcp-dash-tabular"
              style={{ color: protectionStatusColor }}
            >
              {healthScore}
              <span style={{ fontSize: '15px', color: 'var(--webcare-text-muted, #94a3b8)', fontWeight: 500 }}>
                /100
              </span>
            </span>
            <span
              style={{
                fontSize: '11px',
                fontWeight: 600,
                padding: '2px 8px',
                borderRadius: '6px',
                color: protectionStatusColor,
                backgroundColor: `${protectionStatusColor}16`,
                border: `1px solid ${protectionStatusColor}30`,
              }}
            >
              {protectionStatusLabel}
            </span>
          </div>

          <div className="wcp-dash-kpi-bottom">
            <span>Automated diagnostic health</span>
            <span className="wcp-dash-kpi-action-link">
              Site Doctor <ArrowRight size={12} />
            </span>
          </div>
        </div>

        {/* KPI 2: Threats Blocked */}
        <div
          className="wcp-dash-kpi-card"
          onClick={() => handleTileNavigate('logs', 'blocked')}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') handleTileNavigate('logs', 'blocked');
          }}
        >
          <div className="wcp-dash-kpi-top">
            <span className="wcp-dash-kpi-label">Threats Blocked</span>
            <div className="wcp-dash-kpi-icon-badge is-indigo">
              <Shield size={17} />
            </div>
          </div>

          <div className="wcp-dash-kpi-center">
            <span className="wcp-dash-kpi-val wcp-dash-tabular">
              {threatsBlockedCount.toLocaleString()}
            </span>
            {/* Decorative wave sparkline */}
            <svg
              className="wcp-dash-sparkline-svg"
              viewBox="0 0 72 28"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M2 24C12 24 16 8 26 14C36 20 42 4 52 10C60 15 64 6 70 2"
                stroke="#6366f1"
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M2 24C12 24 16 8 26 14C36 20 42 4 52 10C60 15 64 6 70 2V28H2V24Z"
                fill="url(#wcp-spark-grad)"
                opacity="0.18"
              />
              <defs>
                <linearGradient id="wcp-spark-grad" x1="36" y1="2" x2="36" y2="28" gradientUnits="userSpaceOnUse">
                  <stop stopColor="#6366f1" />
                  <stop offset="1" stopColor="#6366f1" stopOpacity="0" />
                </linearGradient>
              </defs>
            </svg>
          </div>

          <div className="wcp-dash-kpi-bottom">
            <span>Perimeter Layer 7 filter</span>
            <span className="wcp-dash-kpi-action-link">
              View Logs <ArrowRight size={12} />
            </span>
          </div>
        </div>

        {/* KPI 3: Items to Review */}
        <div
          className="wcp-dash-kpi-card"
          onClick={() => handleTileNavigate('scan')}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') handleTileNavigate('scan');
          }}
        >
          <div className="wcp-dash-kpi-top">
            <span className="wcp-dash-kpi-label">Items to Review</span>
            <div
              className={`wcp-dash-kpi-icon-badge ${
                reviewItemsCount === 0 ? 'is-emerald' : 'is-amber'
              }`}
            >
              {reviewItemsCount === 0 ? <CheckCircle2 size={17} /> : <AlertTriangle size={17} />}
            </div>
          </div>

          <div className="wcp-dash-kpi-center">
            {reviewItemsCount === 0 ? (
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  color: '#10b981',
                  fontWeight: 700,
                  fontSize: '18px',
                }}
              >
                <Check size={20} /> All Clear
              </span>
            ) : (
              <span className="wcp-dash-kpi-val wcp-dash-tabular" style={{ color: '#d97706' }}>
                {reviewItemsCount}
              </span>
            )}
          </div>

          <div className="wcp-dash-kpi-bottom">
            <span>
              {reviewItemsCount === 0 ? '0 unresolved security warnings' : 'Ready for 1-click inspection'}
            </span>
            <span className="wcp-dash-kpi-action-link">
              Open Scanner <ArrowRight size={12} />
            </span>
          </div>
        </div>

        {/* KPI 4: Latest Backup */}
        <div
          className="wcp-dash-kpi-card"
          onClick={() => handleTileNavigate('backup')}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') handleTileNavigate('backup');
          }}
        >
          <div className="wcp-dash-kpi-top">
            <span className="wcp-dash-kpi-label">Latest Backup</span>
            <div className="wcp-dash-kpi-icon-badge is-cyan">
              <Database size={17} />
            </div>
          </div>

          <div className="wcp-dash-kpi-center">
            {latestBackupTime ? (
              <span className="wcp-dash-kpi-val-text">{latestBackupTime}</span>
            ) : (
              <span className="wcp-dash-kpi-val-text is-muted">Create Backup</span>
            )}
          </div>

          <div className="wcp-dash-kpi-bottom">
            <span>
              {latestBackupTime ? 'Encrypted snapshot saved' : 'No recovery snapshots yet'}
            </span>
            <span className="wcp-dash-kpi-action-link">
              {latestBackupTime ? 'Manage' : 'Create First'} <ArrowRight size={12} />
            </span>
          </div>
        </div>
      </section>

      {/* =========================================================================
          3. Quick Actions Dock (.wcp-dash-actions-dock)
         ========================================================================= */}
      <section className="wcp-dash-actions-dock">
        {/* Action 1: Run Security Scan */}
        <button
          type="button"
          className="wcp-dash-dock-btn"
          onClick={onStartScan}
          disabled={isScanning}
        >
          <div className="wcp-dash-dock-icon is-indigo">
            <Search size={18} />
          </div>
          <div className="wcp-dash-dock-text">
            <span className="wcp-dash-dock-title">Run Security Scan</span>
            <span className="wcp-dash-dock-sub">Core files &amp; plugins</span>
          </div>
        </button>

        {/* Action 2: Blocked Traffic & Bans */}
        <button
          type="button"
          className="wcp-dash-dock-btn"
          onClick={() => handleTileNavigate('logs', 'blocked')}
        >
          <div className="wcp-dash-dock-icon is-cyan">
            <Ban size={18} />
          </div>
          <div className="wcp-dash-dock-text">
            <span className="wcp-dash-dock-title">Blocked Traffic &amp; Bans</span>
            <span className="wcp-dash-dock-sub">Inspect perimeter blocks</span>
          </div>
        </button>

        {/* Action 3: Create Database Backup */}
        <button
          type="button"
          className="wcp-dash-dock-btn"
          onClick={() => handleTileNavigate('backup')}
        >
          <div className="wcp-dash-dock-icon is-purple">
            <Database size={18} />
          </div>
          <div className="wcp-dash-dock-text">
            <span className="wcp-dash-dock-title">Create Database Backup</span>
            <span className="wcp-dash-dock-sub">Safe rollback snapshot</span>
          </div>
        </button>

        {/* Action 4: Site Health Check */}
        <button
          type="button"
          className="wcp-dash-dock-btn"
          onClick={() => handleTileNavigate('settings', 'doctor')}
        >
          <div className="wcp-dash-dock-icon is-emerald">
            <Activity size={18} />
          </div>
          <div className="wcp-dash-dock-text">
            <span className="wcp-dash-dock-title">Site Health Check</span>
            <span className="wcp-dash-dock-sub">Run deep diagnostics</span>
          </div>
        </button>
      </section>

      {/* =========================================================================
          4. Lower Bento 2-Column Grid (.wcp-dash-lower-grid)
         ========================================================================= */}
      <div className="wcp-dash-lower-grid">
        {/* Left Column: Protection Layers (2x3 Mini-Card Grid) */}
        <div className="wcp-dash-card">
          <div className="wcp-dash-card-header">
            <div className="wcp-dash-card-title-group">
              <Layers size={18} color="#10b981" />
              <h3 className="wcp-dash-card-title">Protection Layers</h3>
            </div>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
                fontSize: '11px',
                fontWeight: 600,
                color: '#059669',
                background: 'rgba(16, 185, 129, 0.12)',
                padding: '3px 9px',
                borderRadius: '6px',
              }}
            >
              <Check size={12} /> Active &amp; Guarded
            </span>
          </div>
          <p className="wcp-dash-card-subtitle">
            Autonomous sentinels defending runtime requests, authentications, and core files.
          </p>

          <div className="wcp-dash-layers-grid">
            {/* Tile 1: Web Firewall */}
            <div
              className="wcp-dash-layer-tile"
              onClick={() => handleTileNavigate('firewall', 'rules')}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') handleTileNavigate('firewall', 'rules');
              }}
            >
              <div className="wcp-dash-layer-left">
                <div className="wcp-dash-layer-icon">
                  <ShieldCheck size={16} />
                </div>
                <span className="wcp-dash-layer-name">Web Firewall</span>
              </div>
              <span className="wcp-dash-layer-badge is-active">Active</span>
            </div>

            {/* Tile 2: Login & 2FA */}
            <div
              className="wcp-dash-layer-tile"
              onClick={() => handleTileNavigate('auth', '2fa')}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') handleTileNavigate('auth', '2fa');
              }}
            >
              <div className="wcp-dash-layer-left">
                <div className="wcp-dash-layer-icon">
                  <Lock size={15} />
                </div>
                <span className="wcp-dash-layer-name">Login &amp; 2FA</span>
              </div>
              <span className="wcp-dash-layer-badge is-active">Active</span>
            </div>

            {/* Tile 3: Malware Scanner */}
            <div
              className="wcp-dash-layer-tile"
              onClick={() => handleTileNavigate('scan')}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') handleTileNavigate('scan');
              }}
            >
              <div className="wcp-dash-layer-left">
                <div className="wcp-dash-layer-icon">
                  <Search size={15} />
                </div>
                <span className="wcp-dash-layer-name">Malware Scanner</span>
              </div>
              <span className="wcp-dash-layer-badge is-active">Ready</span>
            </div>

            {/* Tile 4: Plugin & Theme Risks */}
            <div
              className="wcp-dash-layer-tile"
              onClick={() => handleTileNavigate('vulnerabilities')}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') handleTileNavigate('vulnerabilities');
              }}
            >
              <div className="wcp-dash-layer-left">
                <div className="wcp-dash-layer-icon">
                  <Zap size={15} />
                </div>
                <span className="wcp-dash-layer-name">Plugin &amp; Theme Risks</span>
              </div>
              {vulnTotal > 0 ? (
                <span className="wcp-dash-layer-badge is-warning">
                  {vulnTotal} to Review
                </span>
              ) : (
                <span className="wcp-dash-layer-badge is-active">Safe</span>
              )}
            </div>

            {/* Tile 5: Database Backups */}
            <div
              className="wcp-dash-layer-tile"
              onClick={() => handleTileNavigate('backup')}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') handleTileNavigate('backup');
              }}
            >
              <div className="wcp-dash-layer-left">
                <div className="wcp-dash-layer-icon">
                  <Database size={15} />
                </div>
                <span className="wcp-dash-layer-name">Database Backups</span>
              </div>
              <span className="wcp-dash-layer-badge is-active">
                {backups && backups.length > 0 ? `${backups.length} Saved` : 'Ready'}
              </span>
            </div>

            {/* Tile 6: Site Doctor */}
            <div
              className="wcp-dash-layer-tile"
              onClick={() => handleTileNavigate('settings', 'doctor')}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') handleTileNavigate('settings', 'doctor');
              }}
            >
              <div className="wcp-dash-layer-left">
                <div className="wcp-dash-layer-icon">
                  <Activity size={15} />
                </div>
                <span className="wcp-dash-layer-name">Site Doctor</span>
              </div>
              <span className="wcp-dash-layer-badge is-active">Ready</span>
            </div>
          </div>
        </div>

        {/* Right Column: Quiet Activity Pulse */}
        <div className="wcp-dash-card">
          <div className="wcp-dash-card-header">
            <div className="wcp-dash-card-title-group">
              <Activity size={18} color="#6366f1" />
              <h3 className="wcp-dash-card-title">Quiet Activity Pulse</h3>
            </div>
            <button
              type="button"
              className="wcp-dash-kpi-action-link"
              style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '12px' }}
              onClick={() => handleTileNavigate('logs')}
            >
              View all logs &rarr;
            </button>
          </div>
          <p className="wcp-dash-card-subtitle">
            Chronological ledger of recent security decisions and intercepted traffic.
          </p>

          <div className="wcp-dash-pulse-timeline">
            {firewallLogs && firewallLogs.length > 0 ? (
              firewallLogs.slice(0, 5).map((log: any, idx: number) => {
                const categoryClean = log.rule_category
                  ? log.rule_category.replace(/_/g, ' ')
                  : 'Malicious Incursion';
                return (
                  <div key={log.id || `pulse-log-${idx}`} className="wcp-dash-pulse-item">
                    <div className="wcp-dash-pulse-dot is-block" />
                    <div className="wcp-dash-pulse-body">
                      <div className="wcp-dash-pulse-header">
                        <span className="wcp-dash-pulse-rule">
                          Blocked {categoryClean}
                        </span>
                        <span className="wcp-dash-pulse-time">
                          {formatRelativeTime(log.created_at || log.timestamp)}
                        </span>
                      </div>
                      <p className="wcp-dash-pulse-desc">
                        {log.request_method || 'GET'} {log.request_uri || '/'}
                        <span className="wcp-dash-pulse-ip">
                          {log.ip_address || '127.0.0.1'}
                        </span>
                      </p>
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="wcp-dash-pulse-empty">
                All quiet — no threats intercepted recently.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* =========================================================================
          5. Subtle System Readiness Footer Strip (.wcp-dash-footer-strip)
         ========================================================================= */}
      <footer className="wcp-dash-footer-strip">
        <div className="wcp-dash-footer-item">
          <span className="wcp-dash-footer-dot" />
          <span>PHP:</span>
          <span className="wcp-dash-footer-val wcp-dash-tabular">
            {resolvedPhpVersion}
          </span>
        </div>

        <div className="wcp-dash-footer-item">
          <span>WordPress:</span>
          <span className="wcp-dash-footer-val wcp-dash-tabular">
            {resolvedWpVersion}
          </span>
        </div>

        <div className="wcp-dash-footer-item">
          <span>Server Engine:</span>
          <span className="wcp-dash-footer-val">
            {resolvedServerEngine}
          </span>
        </div>

        <div className="wcp-dash-footer-item">
          <span>Quarantined Files:</span>
          <span className="wcp-dash-footer-val wcp-dash-tabular">
            {quarantinedFiles?.length || 0}
          </span>
        </div>

        <div className="wcp-dash-footer-item">
          <span>Protection Mode:</span>
          <span className="wcp-dash-footer-val">Active / Fail-Closed</span>
        </div>
      </footer>
    </div>
  );
};

export default DashboardOverview;
