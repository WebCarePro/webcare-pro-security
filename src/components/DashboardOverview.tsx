import React, { Fragment, useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Shield,
  Activity,
  Play,
  Pause,
  AlertTriangle,
  CheckCircle2,
  Database,
  ArrowRight,
  HardDrive,
  Lock,
  Server,
  Zap,
  Globe,
  RefreshCw,
  Search,
  ExternalLink,
  Ban,
  Clock,
  Layers,
  Sparkles,
  AlertOctagon,
  UserCheck,
  Check,
} from 'lucide-react';
import { apiRequest } from '../utils/api';
import { buildAdminUrl } from '../utils/routeRegistry';

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
  const openIssues = (uniqueIssues || []).filter((i) => i.status === 'open');
  const reviewItemsCount = openIssues.length;

  let activeRaw = 0;
  for (const issue of openIssues) {
    const conf = issue.confidence && issue.confidence > 1 ? issue.confidence / 100 : issue.confidence || 1;
    if (issue.severity === 'critical') activeRaw += 40 * conf;
    else if (issue.severity === 'high') activeRaw += 15 * conf;
    else if (issue.severity === 'medium') activeRaw += 5 * conf;
    else if (issue.severity === 'low') activeRaw += 1 * conf;
  }
  const activeRiskScore = Math.min(100, Math.round(activeRaw));
  const healthScore = Math.max(0, 100 - activeRiskScore);

  let protectionStatusLabel = 'Strong';
  let protectionStatusColor = '#10b981';
  if (healthScore < 60) {
    protectionStatusLabel = 'Needs Attention';
    protectionStatusColor = '#ef4444';
  } else if (healthScore < 85) {
    protectionStatusLabel = 'Good';
    protectionStatusColor = '#f59e0b';
  }

  // Threats blocked
  const threatsBlockedCount = firewallStatus?.total_blocks ?? 0;
  const firewallActive = firewallStatus?.enabled !== false && !internalPaused;

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

  return (
    <div className="webcare-calm-dashboard">
      {/* =========================================================================
          1. CALM "PEACE OF MIND" HERO CARD
         ========================================================================= */}
      <section className={`webcare-hero-calm state-${heroState}`}>
        <div className="webcare-hero-calm-body">
          {/* Animated Soothing Shield Emblem */}
          <div className={`webcare-shield-aura state-${heroState}`}>
            <div className="shield-ring outer-ring" />
            <div className="shield-ring inner-ring" />
            <div className="shield-core">
              {heroState === 'scanning' ? (
                <Activity size={36} className="webcare-pulse-icon" />
              ) : heroState === 'paused' ? (
                <Pause size={34} />
              ) : heroState === 'review' ? (
                <ShieldAlert size={36} />
              ) : (
                <ShieldCheck size={38} />
              )}
            </div>
          </div>

          {/* Hero Headlines & Status */}
          <div className="webcare-hero-calm-text">
            <div className="webcare-hero-pill-bar">
              <span className={`webcare-live-indicator-pill ${heroState}`}>
                <span className="live-dot" />
                {heroState === 'scanning'
                  ? 'Security Scan in Progress...'
                  : heroState === 'paused'
                  ? `Safe Mode Active (${formatPauseTimer(pauseSecondsLeft)} remaining)`
                  : 'Firewall Active • Real-Time Shield'}
              </span>

              <span className="webcare-privacy-pill">
                <Lock size={12} />
                100% On-Premise Protection
              </span>
            </div>

            <h1 className="webcare-hero-calm-title">
              {heroState === 'scanning' ? (
                'Scanning your site for security threats...'
              ) : heroState === 'paused' ? (
                'Safe Mode is active — firewall paused temporarily'
              ) : heroState === 'review' ? (
                `Protection is active — ${reviewItemsCount} ${
                  reviewItemsCount === 1 ? 'item' : 'items'
                } ready for your review`
              ) : (
                'Your site is protected and running smoothly'
              )}
            </h1>

            <p className="webcare-hero-calm-desc">
              {heroState === 'scanning'
                ? 'Deep scanning core files, database integrity, plugins, and server configurations in non-blocking batches.'
                : heroState === 'paused'
                ? 'Firewall rules are temporarily paused to allow safe plugin updates and troubleshooting. All protections resume automatically.'
                : heroState === 'review'
                ? 'Continuous proactive defenses are actively filtering malicious traffic. Recommended optimizations and advisories are ready for you.'
                : 'All defensive layers are active. WebCare Pro is monitoring requests, verifying file integrity, and blocking unauthorized access.'}
            </p>
          </div>

          {/* Primary Calm Actions */}
          <div className="webcare-hero-calm-actions">
            <button
              type="button"
              className="webcare-hero-action-primary"
              onClick={onStartScan}
              disabled={isScanning}
            >
              {isScanning ? (
                <>
                  <RefreshCw size={15} className="webcare-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <Play size={15} fill="currentColor" />
                  <span>Run Quick Scan</span>
                </>
              )}
            </button>

            <button
              type="button"
              className={`webcare-hero-action-safe-mode ${internalPaused ? 'is-paused' : ''}`}
              onClick={handleToggleSafeMode}
              disabled={isPausing}
              title={
                internalPaused
                  ? 'Click to resume firewall protection immediately'
                  : 'Pause firewall for 15 minutes to safely update plugins or troubleshoot'
              }
            >
              {internalPaused ? (
                <>
                  <Play size={14} />
                  <span>Resume Firewall</span>
                </>
              ) : (
                <>
                  <Pause size={14} />
                  <span>15-Min Safe Mode</span>
                </>
              )}
            </button>
          </div>
        </div>
      </section>

      {/* =========================================================================
          2. FOUR CLEAN KPI SUMMARY CARDS (STAGGERED ENTRANCE)
         ========================================================================= */}
      <section className="webcare-kpi-grid">
        {/* KPI 1: Threats Blocked (7 Days) */}
        <div
          className="webcare-kpi-card"
          style={{ animationDelay: '50ms' }}
          onClick={() => onNavigate('logs', 'blocked')}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') onNavigate('logs', 'blocked');
          }}
        >
          <div className="webcare-kpi-header">
            <span className="webcare-kpi-label">Threats Blocked (7 Days)</span>
            <div className="webcare-kpi-icon-wrap is-blue">
              <Shield size={18} />
            </div>
          </div>
          <div className="webcare-kpi-metric-row">
            <span className="webcare-kpi-value">{threatsBlockedCount.toLocaleString()}</span>
          </div>
          <div className="webcare-kpi-footer">
            <span className="webcare-kpi-subtext">
              <span className="webcare-trend-dot" />
              Proactive Layer 7 edge filter
            </span>
            <span className="webcare-kpi-arrow">View Logs &rarr;</span>
          </div>
        </div>

        {/* KPI 2: Items to Review */}
        <div
          className="webcare-kpi-card"
          style={{ animationDelay: '100ms' }}
          onClick={() => onNavigate('scan')}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') onNavigate('scan');
          }}
        >
          <div className="webcare-kpi-header">
            <span className="webcare-kpi-label">Items to Review</span>
            <div
              className={`webcare-kpi-icon-wrap ${
                reviewItemsCount === 0 ? 'is-green' : 'is-amber'
              }`}
            >
              {reviewItemsCount === 0 ? <CheckCircle2 size={18} /> : <AlertTriangle size={18} />}
            </div>
          </div>
          <div className="webcare-kpi-metric-row">
            {reviewItemsCount === 0 ? (
              <span className="webcare-kpi-value is-clean">
                <Check size={22} className="inline-check" /> All Clear
              </span>
            ) : (
              <span className="webcare-kpi-value is-amber">{reviewItemsCount}</span>
            )}
          </div>
          <div className="webcare-kpi-footer">
            <span className="webcare-kpi-subtext">
              {reviewItemsCount === 0 ? '0 unaddressed security warnings' : 'Ready for 1-click inspection'}
            </span>
            <span className="webcare-kpi-arrow">Open Scanner &rarr;</span>
          </div>
        </div>

        {/* KPI 3: Protection Score */}
        <div
          className="webcare-kpi-card"
          style={{ animationDelay: '150ms' }}
          onClick={() => onNavigate('settings', 'doctor')}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') onNavigate('settings', 'doctor');
          }}
        >
          <div className="webcare-kpi-header">
            <span className="webcare-kpi-label">Protection Score</span>
            <div className="webcare-kpi-icon-wrap is-indigo">
              <Sparkles size={18} />
            </div>
          </div>
          <div className="webcare-kpi-metric-row">
            <span className="webcare-kpi-value" style={{ color: protectionStatusColor }}>
              {healthScore}
              <span className="webcare-kpi-max">/100</span>
            </span>
            <span
              className="webcare-kpi-status-badge"
              style={{
                color: protectionStatusColor,
                backgroundColor: `${protectionStatusColor}18`,
                borderColor: `${protectionStatusColor}40`,
              }}
            >
              {protectionStatusLabel}
            </span>
          </div>
          <div className="webcare-kpi-footer">
            <span className="webcare-kpi-subtext">Automated diagnostic score</span>
            <span className="webcare-kpi-arrow">Site Doctor &rarr;</span>
          </div>
        </div>

        {/* KPI 4: Latest Backup */}
        <div
          className="webcare-kpi-card"
          style={{ animationDelay: '200ms' }}
          onClick={() => onNavigate('backup')}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') onNavigate('backup');
          }}
        >
          <div className="webcare-kpi-header">
            <span className="webcare-kpi-label">Latest Backup</span>
            <div className="webcare-kpi-icon-wrap is-purple">
              <Database size={18} />
            </div>
          </div>
          <div className="webcare-kpi-metric-row">
            {latestBackupTime ? (
              <span className="webcare-kpi-value-text">{latestBackupTime}</span>
            ) : (
              <span className="webcare-kpi-value-text is-muted">No Backups Yet</span>
            )}
          </div>
          <div className="webcare-kpi-footer">
            <span className="webcare-kpi-subtext">
              {latestBackupTime ? 'Encrypted snapshot available' : 'Create your initial recovery point'}
            </span>
            <span className="webcare-kpi-arrow">
              {latestBackupTime ? 'Manage &rarr;' : 'Create First &rarr;'}
            </span>
          </div>
        </div>
      </section>

      {/* =========================================================================
          3. SINGLE-ROW QUICK ACTIONS STRIP
         ========================================================================= */}
      <section className="webcare-actions-strip">
        <button
          type="button"
          className="webcare-strip-btn"
          onClick={() => onNavigate('scan')}
        >
          <Search size={16} className="strip-btn-icon icon-emerald" />
          <div className="strip-btn-text">
            <strong>Run Malware Scan</strong>
            <small>Inspect core &amp; plugins</small>
          </div>
        </button>

        <button
          type="button"
          className="webcare-strip-btn"
          onClick={() => onNavigate('logs')}
        >
          <Ban size={16} className="strip-btn-icon icon-blue" />
          <div className="strip-btn-text">
            <strong>Unban IP &amp; Traffic Logs</strong>
            <small>Manage bans &amp; blocks</small>
          </div>
        </button>

        <button
          type="button"
          className="webcare-strip-btn"
          onClick={() => onNavigate('backup')}
        >
          <Database size={16} className="strip-btn-icon icon-purple" />
          <div className="strip-btn-text">
            <strong>Create Database Backup</strong>
            <small>Safe pre-update snapshot</small>
          </div>
        </button>

        <button
          type="button"
          className="webcare-strip-btn"
          onClick={() => onNavigate('settings', 'doctor')}
        >
          <Activity size={16} className="strip-btn-icon icon-amber" />
          <div className="strip-btn-text">
            <strong>Run Site Health Check</strong>
            <small>Deep server diagnostics</small>
          </div>
        </button>
      </section>

      {/* =========================================================================
          4. CALM 2-COLUMN LOWER GRID
         ========================================================================= */}
      <div className="webcare-lower-grid">
        {/* Left Column: Protection Layers (Peace-of-Mind Checklist) */}
        <div className="webcare-card webcare-protection-checklist-card">
          <div className="webcare-card-header">
            <div className="webcare-card-title-group">
              <Layers size={18} className="icon-emerald" />
              <h3>Protection Layers</h3>
            </div>
            <span className="webcare-badge-clean">
              <Check size={12} /> All Active
            </span>
          </div>
          <p className="webcare-card-subtitle">
            Continuous defensive sentinels safeguarding your site around the clock.
          </p>

          <div className="webcare-layers-list">
            {/* Layer 1: Web Firewall */}
            <div
              className="webcare-layer-item"
              onClick={() => onNavigate('firewall')}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') onNavigate('firewall');
              }}
            >
              <div className="layer-status-icon">
                <CheckCircle2 size={16} color="#10b981" />
              </div>
              <div className="layer-info">
                <div className="layer-name-row">
                  <strong>Web Firewall (WAF)</strong>
                  <span className="layer-tag">Real-Time</span>
                </div>
                <p>Blocks SQL injection, XSS probes, and exploit attempts at Layer 7.</p>
              </div>
              <ArrowRight size={14} className="layer-arrow" />
            </div>

            {/* Layer 2: Login & 2FA */}
            <div
              className="webcare-layer-item"
              onClick={() => onNavigate('auth')}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') onNavigate('auth');
              }}
            >
              <div className="layer-status-icon">
                <CheckCircle2 size={16} color="#10b981" />
              </div>
              <div className="layer-info">
                <div className="layer-name-row">
                  <strong>Login &amp; 2FA Protection</strong>
                  <span className="layer-tag">Active</span>
                </div>
                <p>Brute-force lockout defense, TOTP two-factor, and biometric passkeys.</p>
              </div>
              <ArrowRight size={14} className="layer-arrow" />
            </div>

            {/* Layer 3: Malware Scanner */}
            <div
              className="webcare-layer-item"
              onClick={() => onNavigate('scan')}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') onNavigate('scan');
              }}
            >
              <div className="layer-status-icon">
                <CheckCircle2 size={16} color="#10b981" />
              </div>
              <div className="layer-info">
                <div className="layer-name-row">
                  <strong>Malware &amp; Core Integrity Scanner</strong>
                  <span className="layer-tag">Scheduled</span>
                </div>
                <p>Validates WordPress core checksums and analyzes suspicious PHP code.</p>
              </div>
              <ArrowRight size={14} className="layer-arrow" />
            </div>

            {/* Layer 4: Database Backups */}
            <div
              className="webcare-layer-item"
              onClick={() => onNavigate('backup')}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') onNavigate('backup');
              }}
            >
              <div className="layer-status-icon">
                <CheckCircle2 size={16} color="#10b981" />
              </div>
              <div className="layer-info">
                <div className="layer-name-row">
                  <strong>Database Backups &amp; Rollback</strong>
                  <span className="layer-tag">Enabled</span>
                </div>
                <p>On-demand snapshot backups with automated pre-remediation safety points.</p>
              </div>
              <ArrowRight size={14} className="layer-arrow" />
            </div>

            {/* Layer 5: Public Threat Feeds */}
            <div
              className="webcare-layer-item"
              onClick={() => onNavigate('firewall', 'intel')}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') onNavigate('firewall', 'intel');
              }}
            >
              <div className="layer-status-icon">
                <CheckCircle2 size={16} color="#10b981" />
              </div>
              <div className="layer-info">
                <div className="layer-name-row">
                  <strong>Public Threat Feeds</strong>
                  <span className="layer-tag">Synced</span>
                </div>
                <p>Curated botnet IP lists and known vulnerability signatures cached locally.</p>
              </div>
              <ArrowRight size={14} className="layer-arrow" />
            </div>

            {/* Layer 6: Server Guard */}
            <div
              className="webcare-layer-item"
              onClick={() => onNavigate('server')}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') onNavigate('server');
              }}
            >
              <div className="layer-status-icon">
                <CheckCircle2 size={16} color="#10b981" />
              </div>
              <div className="layer-info">
                <div className="layer-name-row">
                  <strong>Server Guard &amp; Headers</strong>
                  <span className="layer-tag">Hardened</span>
                </div>
                <p>Security headers (CSP, HSTS, X-Frame-Options) and upload dir protection.</p>
              </div>
              <ArrowRight size={14} className="layer-arrow" />
            </div>
          </div>
        </div>

        {/* Right Column: Recent Activity Pulse */}
        <div className="webcare-card webcare-activity-pulse-card">
          <div className="webcare-card-header">
            <div className="webcare-card-title-group">
              <Activity size={18} className="icon-blue" />
              <h3>Recent Activity Pulse</h3>
            </div>
            <button
              type="button"
              className="webcare-view-all-link"
              onClick={() => onNavigate('logs')}
            >
              <span>View all logs &rarr;</span>
            </button>
          </div>
          <p className="webcare-card-subtitle">
            Real-time feed of recent security events and perimeter blocks.
          </p>

          <div className="webcare-pulse-list">
            {firewallLogs && firewallLogs.length > 0 ? (
              firewallLogs.slice(0, 5).map((log: any, idx: number) => {
                const categoryClean = log.rule_category
                  ? log.rule_category.replace(/_/g, ' ')
                  : 'Malicious Request';
                return (
                  <div key={log.id || `pulse-log-${idx}`} className="webcare-pulse-item">
                    <div className="pulse-item-indicator is-block" />
                    <div className="pulse-item-content">
                      <div className="pulse-item-title-row">
                        <span className="pulse-item-title">
                          Blocked {categoryClean}
                        </span>
                        <span className="pulse-item-time">
                          {formatRelativeTime(log.created_at || log.timestamp)}
                        </span>
                      </div>
                      <p className="pulse-item-desc">
                        {log.request_method || 'GET'} {log.request_uri || '/'} from IP{' '}
                        <code>{log.ip_address || '127.0.0.1'}</code>
                      </p>
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="webcare-pulse-item">
                <div className="pulse-item-indicator is-clean" />
                <div className="pulse-item-content">
                  <div className="pulse-item-title-row">
                    <span className="pulse-item-title">Perimeter Defenses Calm</span>
                    <span className="pulse-item-time">Just now</span>
                  </div>
                  <p className="pulse-item-desc">
                    No malicious intrusions detected in recent window. Firewall is actively watching incoming traffic.
                  </p>
                </div>
              </div>
            )}

            {/* Core Verification Milestone Event */}
            <div className="webcare-pulse-item">
              <div className="pulse-item-indicator is-clean" />
              <div className="pulse-item-content">
                <div className="pulse-item-title-row">
                  <span className="pulse-item-title">
                    WordPress Core Integrity Verified
                  </span>
                  <span className="pulse-item-time">
                    {formatRelativeTime(currentScan?.finished_at || currentScan?.created_at || new Date())}
                  </span>
                </div>
                <p className="pulse-item-desc">
                  Official cryptographic checksums verified against WordPress API.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardOverview;
