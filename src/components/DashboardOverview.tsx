import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Shield,
  Activity,
  Play,
  Pause,
  CheckCircle2,
  ArrowRight,
  Lock,
  Zap,
  Globe,
  RefreshCw,
  Clock,
  Layers,
  Check,
  AlertTriangle,
  Users,
  CalendarClock,
  Bell,
  ChevronDown,
  Target,
  FolderSearch,
  Image,
  FileCode2,
  KeyRound,
  FileCheck2,
  PackageCheck,
  Cloud,
  Stethoscope,
  Cpu,
  Bot,
  Sparkles,
  Radar,
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

interface AdminSessionsSummary {
  loaded: boolean;
  adminCount: number;
  sessionCount: number;
  usernames: string[];
}

interface CloudflareLiveStatus {
  loaded: boolean;
  configured: boolean;
  zoneName: string;
  autoSyncBans: boolean;
  error?: string;
}

interface ScheduleLiveStatus {
  loaded: boolean;
  enabled: boolean;
  frequency: string;
  nextScheduledHuman: string;
  alertsEnabled: boolean;
  alertEmail: string;
}

const TARGET_SCAN_CHOICES = [
  {
    id: 'plugins_themes',
    title: 'Quick Checkup (Plugins & Themes)',
    subtitle: 'Check installed plugins, themes & known risks',
    icon: Zap,
    isTargeted: false,
  },
  {
    id: 'full',
    title: 'Complete Website Scan',
    subtitle: 'Full audit of WordPress core, themes, plugins & files',
    icon: Shield,
    isTargeted: false,
  },
  {
    id: 'core_integrity',
    title: 'WordPress Core Files Only',
    subtitle: 'Verify official WordPress core file checksums',
    icon: FileCode2,
    isTargeted: true,
  },
  {
    id: 'suspicious_uploads',
    title: 'Uploads & Media Folder',
    subtitle: 'Check wp-content/uploads for hidden scripts',
    icon: Image,
    isTargeted: true,
  },
] as const;

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  currentScan,
  uniqueIssues,
  firewallStatus,
  firewallLogs,
  serverInfo,
  vulnReport,
  quarantinedFiles,
  isScanning,
  onStartScan,
  onOpenRescueModal,
  isRescuePaused = false,
  formatRelativeTime,
}) => {
  const [internalPaused, setInternalPaused] = useState<boolean>(isRescuePaused);
  const [pauseSecondsLeft, setPauseSecondsLeft] = useState<number>(0);
  const [isPausing, setIsPausing] = useState<boolean>(false);
  const [launchingScan, setLaunchingScan] = useState<boolean>(false);

  // Target scan dropdown state
  const [scanMenuOpen, setScanMenuOpen] = useState<boolean>(false);
  const scanMenuContainerRef = useRef<HTMLDivElement | null>(null);
  const scanCaretBtnRef = useRef<HTMLButtonElement | null>(null);

  // Expandable guard cards
  const [expandedLayerKey, setExpandedLayerKey] = useState<string | null>(null);

  // Real-time backend data for Dashboard widgets
  const [adminSummary, setAdminSummary] = useState<AdminSessionsSummary>({
    loaded: false,
    adminCount: 0,
    sessionCount: 0,
    usernames: [],
  });
  const [cfStatus, setCfStatus] = useState<CloudflareLiveStatus>({
    loaded: false,
    configured: false,
    zoneName: '',
    autoSyncBans: false,
  });
  const [scheduleInfo, setScheduleInfo] = useState<ScheduleLiveStatus>({
    loaded: false,
    enabled: false,
    frequency: 'daily',
    nextScheduledHuman: '',
    alertsEnabled: false,
    alertEmail: '',
  });

  useEffect(() => {
    setInternalPaused(isRescuePaused);
  }, [isRescuePaused]);

  // Close Target Scan dropdown on outside click or Escape
  useEffect(() => {
    if (!scanMenuOpen) return;
    const handleOutside = (e: MouseEvent) => {
      if (
        scanMenuContainerRef.current &&
        !scanMenuContainerRef.current.contains(e.target as Node)
      ) {
        setScanMenuOpen(false);
      }
    };
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setScanMenuOpen(false);
        scanCaretBtnRef.current?.focus();
      }
    };
    document.addEventListener('mousedown', handleOutside);
    document.addEventListener('keydown', handleKey);
    return () => {
      document.removeEventListener('mousedown', handleOutside);
      document.removeEventListener('keydown', handleKey);
    };
  }, [scanMenuOpen]);

  // Load real rescue pause, active admin sessions, Cloudflare status, schedule & notification status
  useEffect(() => {
    let active = true;

    apiRequest({ path: '/webcare-pro-security/v1/rescue/status?minutes=15', method: 'GET' })
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

    apiRequest({ path: '/webcare-pro-security/v1/auth/sessions/list', method: 'GET' })
      .then((res: any) => {
        if (!active) return;
        const rawSessions: any[] = Array.isArray(res?.sessions) ? res.sessions : [];
        const activeAdmins = rawSessions.filter(
          (s) => s && s.is_active === true && !s.is_revoked && s.status !== 'logged_out'
        );
        const names: string[] = [];
        const uniqueAdmins = new Set<string>();
        activeAdmins.forEach((s) => {
          const idKey = String(s.user_id || s.user_login || '');
          if (idKey) uniqueAdmins.add(idKey);
          const display = String(s.user_login || s.display_name || '').trim();
          if (display && !names.includes(display)) names.push(display);
        });
        setAdminSummary({
          loaded: true,
          adminCount: uniqueAdmins.size,
          sessionCount: activeAdmins.length,
          usernames: names,
        });
      })
      .catch(() => {
        if (active) {
          setAdminSummary((prev) => ({ ...prev, loaded: true }));
        }
      });

    apiRequest({ path: '/webcare-pro-security/v1/cloudflare/status', method: 'GET' })
      .then((res: any) => {
        if (!active) return;
        const st = res?.status || {};
        setCfStatus({
          loaded: true,
          configured: Boolean(st.configured),
          zoneName: String(st.zone_name || ''),
          autoSyncBans: Boolean(st.auto_sync_bans),
          error: st.error ? String(st.error) : undefined,
        });
      })
      .catch(() => {
        if (active) {
          setCfStatus((prev) => ({ ...prev, loaded: true }));
        }
      });

    apiRequest({ path: '/webcare-pro-security/v1/settings', method: 'GET' })
      .then((res: any) => {
        if (!active) return;
        const s = res?.settings || {};
        const ti = res?.schedule_time || {};
        let nextHuman = '';
        if (ti?.next_scheduled_wp) {
          const diffSec = Number(ti.diff_seconds || 0);
          if (diffSec > 0 && diffSec < 3600) {
            nextHuman = `Next checkup in ${Math.max(1, Math.round(diffSec / 60))} min`;
          } else if (diffSec >= 3600 && diffSec < 86400 * 7) {
            nextHuman = `Next checkup in ${Math.round(diffSec / 3600)}h`;
          } else {
            nextHuman = `Next: ${ti.next_scheduled_wp}`;
          }
        }
        setScheduleInfo({
          loaded: true,
          enabled: Boolean(s.schedule_enabled),
          frequency: String(s.schedule_frequency || 'daily'),
          nextScheduledHuman: nextHuman,
          alertsEnabled: Boolean(s.notification_master_enabled || s.email_alerts_enabled),
          alertEmail: String(s.alert_emails || ''),
        });
      })
      .catch(() => {
        if (active) {
          setScheduleInfo((prev) => ({ ...prev, loaded: true }));
        }
      });

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

  const handleToggleSafeMode = async () => {
    if (internalPaused) {
      setIsPausing(true);
      try {
        const res = await apiRequest({ path: '/webcare-pro-security/v1/rescue/resume', method: 'POST' });
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
        const res = await apiRequest({ path: '/webcare-pro-security/v1/rescue/pause-15m', method: 'POST' });
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

  // Launch chosen target scan cleanly on the backend before redirecting to Scanner page
  const handleTargetScanLaunch = async (targetId: string, isTargeted: boolean) => {
    setScanMenuOpen(false);
    if (isScanning || launchingScan) {
      window.location.href = buildAdminUrl('webcare-pro-scanner', isTargeted ? 'targeted' : 'malware');
      return;
    }

    setLaunchingScan(true);
    try {
      const startRes: any = await apiRequest({
        path: '/webcare-pro-security/v1/scan/start',
        method: 'POST',
        data: { target: targetId },
      });
      if (startRes?.success) {
        window.location.href = buildAdminUrl('webcare-pro-scanner', isTargeted ? 'targeted' : 'malware');
        return;
      }
    } catch {
      // Fall back to opening the scanner page / parent callback cleanly
    } finally {
      setLaunchingScan(false);
    }
    onStartScan();
  };

  // Evaluate active threats and security score from real issues
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

  const threatsBlockedCount = firewallStatus?.total_blocks ?? 0;
  const vulnTotal = (vulnReport?.plugins_vulnerable || 0) + (vulnReport?.themes_vulnerable || 0);

  let heroState: 'protected' | 'review' | 'paused' | 'scanning' = 'protected';
  if (isScanning || launchingScan) {
    heroState = 'scanning';
  } else if (internalPaused) {
    heroState = 'paused';
  } else if (reviewItemsCount > 0 || vulnTotal > 0) {
    heroState = 'review';
  }

  const formatPauseTimer = (secs: number) => {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}:${s < 10 ? '0' : ''}${s}`;
  };

  const ringRadius = 18;
  const ringCircumference = 2 * Math.PI * ringRadius;
  const strokeDashoffset = ringCircumference - (healthScore / 100) * ringCircumference;

  const resolvedSiteHost = useMemo(() => {
    const siteUrl =
      serverInfo?.wordpress?.site_url ||
      (window as any).webcareScannerSettings?.siteUrl ||
      window.location.origin;
    try {
      return new URL(siteUrl).hostname;
    } catch {
      return window.location.hostname;
    }
  }, [serverInfo]);

  const resolvedPhpVersion = useMemo(() => {
    return (
      serverInfo?.php?.version ||
      serverInfo?.php_version ||
      (window as any).webcareScannerSettings?.serverInfo?.php?.version ||
      '8.3+'
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
    return 'Web Server';
  }, [serverInfo]);

  const formatFrequencyLabel = (freq: string) => {
    switch (freq) {
      case 'hourly':
        return 'Hourly';
      case 'twicedaily':
        return 'Twice Daily';
      case 'weekly':
        return 'Weekly';
      default:
        return 'Daily';
    }
  };

  const lastScanText = currentScan?.finished_at
    ? formatRelativeTime(currentScan.finished_at)
    : null;

  // Canonical WordPress pillar links
  const urlScannerRisks = buildAdminUrl('webcare-pro-scanner', 'risks');
  const urlScannerTargeted = buildAdminUrl('webcare-pro-scanner', 'targeted');
  const urlScannerFiles = buildAdminUrl('webcare-pro-scanner', 'file-changes');
  const urlLoginSessions = buildAdminUrl('webcare-pro-login', 'sessions');
  const urlLogin2fa = buildAdminUrl('webcare-pro-login', '2fa');
  const urlCloudflare = buildAdminUrl('webcare-pro-firewall', 'cloudflare');
  const urlFirewallRules = buildAdminUrl('webcare-pro-firewall', 'rules');
  const urlFirewallLogs = buildAdminUrl('webcare-pro-logs', 'firewall');
  const urlAdminActivity = buildAdminUrl('webcare-pro-logs', 'activity');
  const urlSchedules = buildAdminUrl('webcare-pro-settings', 'schedules');
  const urlAlerts = buildAdminUrl('webcare-pro-settings', 'alerts');
  const urlDoctor = buildAdminUrl('webcare-pro-settings', 'doctor');
  const urlCafStackGuard = buildAdminUrl('webcare-pro-modular-waf', 'rules');
  const urlAiDefense = buildAdminUrl('webcare-pro-modular-waf', 'nextgen');
  const urlAiIntelligence = buildAdminUrl('webcare-pro-settings', 'ai');
  const urlThreatFeeds = buildAdminUrl('webcare-pro-firewall', 'threat-intel');

  const cafActive = firewallStatus?.caf_enabled !== false && firewallStatus?.is_enabled !== false;
  const aiDefenseActive = firewallStatus?.ai_defense_enabled !== false && firewallStatus?.is_enabled !== false;
  const aiIntelConfigured = Boolean(
    firewallStatus?.ai_provider_configured ||
    serverInfo?.ai_provider_configured ||
    (window as any).webcareScannerSettings?.ai_provider_configured
  );
  const threatFeedsActive = firewallStatus?.threat_intel_enabled !== false && firewallStatus?.is_enabled !== false;

  const careLayers = [
    {
      key: 'firewall',
      name: 'Perimeter Firewall',
      icon: Shield,
      iconColor: '#4f46e5',
      badge: firewallStatus?.is_enabled === false ? 'Paused' : 'Active',
      tone: firewallStatus?.is_enabled === false ? 'warning' : 'active',
      desc: 'Filters harmful bots and exploit payloads before WordPress even loads, keeping pages fast.',
      href: urlFirewallRules,
      linkText: 'Firewall Rules',
    },
    {
      key: 'login',
      name: 'Friendly Login & 2FA',
      icon: KeyRound,
      iconColor: '#059669',
      badge: 'Active',
      tone: 'active',
      desc: 'Supports WebAuthn passkeys and 2FA while slowing down password guessers automatically.',
      href: urlLogin2fa,
      linkText: 'Login & 2FA',
    },
    {
      key: 'integrity',
      name: 'Core File Integrity',
      icon: FileCheck2,
      iconColor: '#0284c7',
      badge: reviewItemsCount > 0 ? `${reviewItemsCount} Notice` : 'Clean',
      tone: reviewItemsCount > 0 ? 'warning' : 'active',
      desc: 'Compares WordPress core files against official releases to confirm nothing unexpected changed.',
      href: urlScannerFiles,
      linkText: 'File Verification',
    },
    {
      key: 'risks',
      name: 'Plugin & Theme Risks',
      icon: PackageCheck,
      iconColor: '#d97706',
      badge: vulnTotal > 0 ? `${vulnTotal} to Review` : '0 Risks',
      tone: vulnTotal > 0 ? 'warning' : 'active',
      desc: 'Monitors active plugins and themes for known vulnerabilities and guides safe updates.',
      href: urlScannerRisks,
      linkText: 'Check Risks',
    },
    {
      key: 'cloudflare',
      name: 'Cloudflare Edge Sync',
      icon: Cloud,
      iconColor: '#f97316',
      badge: !cfStatus.loaded ? 'Checking' : cfStatus.configured ? 'Synced' : 'Optional',
      tone: cfStatus.configured ? 'active' : 'neutral',
      desc: 'Aligns real visitor IP detection and optional edge firewall filtering cleanly with your origin.',
      href: urlCloudflare,
      linkText: 'Cloudflare Setup',
    },
    {
      key: 'doctor',
      name: 'Site Health Doctor',
      icon: Stethoscope,
      iconColor: '#0d9488',
      badge: 'Ready',
      tone: 'active',
      desc: 'Monitors PHP, InnoDB settings locks, cron health, and safe server configuration automatically.',
      href: urlDoctor,
      linkText: 'Open Site Doctor',
    },
    {
      key: 'caf_stackguard',
      name: '(CAF) & StackGuard Engine',
      icon: Cpu,
      iconColor: '#7c3aed',
      badge: cafActive ? 'Active' : 'Paused',
      tone: cafActive ? 'active' : 'warning',
      desc: 'Automatically profiles your active WordPress stack and compiles tailored, zero-bloat firewall rules.',
      href: urlCafStackGuard,
      linkText: 'Open CAF & StackGuard',
    },
    {
      key: 'ai_defense',
      name: 'AI Defense',
      icon: Bot,
      iconColor: '#6366f1',
      badge: aiDefenseActive ? 'Guarded' : 'Paused',
      tone: aiDefenseActive ? 'active' : 'warning',
      desc: 'Protects forms, comments, and MCP endpoints against 2026–2027 prompt injection and AI scraping bots.',
      href: urlAiDefense,
      linkText: 'AI Defense Rules',
    },
    {
      key: 'ai_cyber_intel',
      name: 'AI Cybersecurity Intelligence Engine',
      icon: Sparkles,
      iconColor: '#8b5cf6',
      badge: aiIntelConfigured ? 'Connected' : 'Ready',
      tone: aiIntelConfigured ? 'active' : 'neutral',
      desc: 'Optional on-demand AI forensic assistant that explains suspicious code in plain English when you ask.',
      href: urlAiIntelligence,
      linkText: 'AI Engine Settings',
    },
    {
      key: 'threat_feeds',
      name: 'Public Threat Intelligence Feeds',
      icon: Radar,
      iconColor: '#0891b2',
      badge: threatFeedsActive ? 'Active' : 'Off',
      tone: threatFeedsActive ? 'active' : 'neutral',
      desc: 'Blocks known botnet IPs and abusive scanner networks locally on your server with zero telemetry.',
      href: urlThreatFeeds,
      linkText: 'Threat Feeds',
    },
  ];

  const totalAlertsText =
    vulnTotal > 0
      ? `${vulnTotal} plugin or theme risk${vulnTotal === 1 ? '' : 's'} ready for review`
      : reviewItemsCount > 0
      ? `${reviewItemsCount} item${reviewItemsCount === 1 ? '' : 's'} ready for your calm review`
      : '';

  return (
    <div className="wcp-dash-container">
      {/* Top Utility Header Bar + Notifications Link (#6) */}
      <div className="wcp-dash-topbar">
        <div className="wcp-dash-topbar-left">
          <span className="wcp-dash-topbar-brand">WebCare Pro Security &amp; Firewall</span>
          <span aria-hidden="true">&rsaquo;</span>
          <span className="wcp-dash-topbar-crumb">Peace of Mind Overview</span>
        </div>

        <div className="wcp-dash-topbar-right">
          <span>{resolvedSiteHost} &bull; On-Premise Shield</span>
          <a href={urlAlerts} className="wcp-dash-notify-pill">
            <Bell size={13} />
            <span>Email &amp; Alert Settings</span>
            <ArrowRight size={12} />
          </a>
        </div>
      </div>

      {/* =========================================================================
          1. Serene Sanctuary Hero Card (.wcp-dash-hero)
         ========================================================================= */}
      <section className={`wcp-dash-hero is-${heroState}${scanMenuOpen ? ' has-menu-open' : ''}`}>
        <div className="wcp-dash-hero-content">
          {/* Animated Living Botanical Shield */}
          <div className="wcp-dash-emblem-wrap">
            <div className="wcp-dash-aura-outer" />
            <div className="wcp-dash-aura-inner" />
            <svg
              className="wcp-dash-emblem-svg"
              viewBox="0 0 80 80"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
              aria-hidden="true"
            >
              <circle
                className="wcp-dash-ring-orbital"
                cx="40"
                cy="40"
                r="35"
                stroke={
                  heroState === 'scanning'
                    ? '#6366f1'
                    : heroState === 'review' || heroState === 'paused'
                    ? '#f59e0b'
                    : '#10b981'
                }
                strokeWidth="1.5"
              />
            </svg>

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

          {/* Calm Human Copy */}
          <div className="wcp-dash-hero-body">
            <div className="wcp-dash-status-pill-row">
              <span className="wcp-dash-status-pill">
                <span className="wcp-dash-pill-dot" />
                {heroState === 'scanning'
                  ? 'Calm Background Checkup Running'
                  : heroState === 'paused'
                  ? `Safe Mode Active • ${formatPauseTimer(pauseSecondsLeft)}`
                  : heroState === 'review'
                  ? 'Shield Active • 1 Quick Suggestion'
                  : 'Everything is Protected'}
              </span>

              <span className="wcp-dash-privacy-pill">
                <Lock size={12} />
                Runs quietly on your server
              </span>

              {lastScanText && (
                <span className="wcp-dash-privacy-pill">
                  <Clock size={12} />
                  Last checked {lastScanText}
                </span>
              )}
            </div>

            <h1 className="wcp-dash-hero-title">
              {heroState === 'scanning'
                ? 'Checking your website files gently in the background…'
                : heroState === 'paused'
                ? 'Safe Mode is active — strict firewall checks are paused temporarily.'
                : heroState === 'review'
                ? `Your site is guarded — ${totalAlertsText}.`
                : 'Rest easy — your website is safe and running smoothly.'}
            </h1>

            <p className="wcp-dash-hero-desc">
              {heroState === 'scanning'
                ? 'Inspecting WordPress core files and plugins in non-blocking batches so visitors notice zero slowdown.'
                : heroState === 'paused'
                ? 'Work freely while editing layouts or updating plugins. Core exploit defenses automatically turn back on when the timer ends.'
                : heroState === 'review'
                ? 'Autonomous defenses are actively filtering malicious traffic. Follow the guided links below whenever you have a minute.'
                : `WebCare Pro has quietly filtered ${threatsBlockedCount.toLocaleString()} suspicious request${
                    threatsBlockedCount === 1 ? '' : 's'
                  } without slowing down genuine visitors. No action is needed right now.`}
            </p>
          </div>

          {/* #1 Target Scan Dropdown Menu + Safe Mode Button */}
          <div className="wcp-dash-hero-actions">
            <div className="wcp-dash-split-wrap" ref={scanMenuContainerRef}>
              <button
                type="button"
                className="wcp-dash-split-main"
                onClick={() => handleTargetScanLaunch('plugins_themes', false)}
                disabled={isScanning || launchingScan}
              >
                {isScanning || launchingScan ? (
                  <>
                    <RefreshCw size={14} className="wcp-dash-spin" />
                    <span>Scanning…</span>
                  </>
                ) : (
                  <>
                    <Play size={14} fill="currentColor" />
                    <span>Run Quick Scan</span>
                  </>
                )}
              </button>

              <button
                ref={scanCaretBtnRef}
                type="button"
                className="wcp-dash-split-caret"
                aria-haspopup="menu"
                aria-expanded={scanMenuOpen ? 'true' : 'false'}
                aria-label="Choose target scan type"
                onClick={() => setScanMenuOpen((prev) => !prev)}
              >
                <ChevronDown size={15} />
              </button>

              {scanMenuOpen && (
                <div className="wcp-dash-scan-menu" role="menu" aria-label="Target scan choices">
                  <div className="wcp-dash-scan-menu-header">Choose Scan Target</div>
                  {TARGET_SCAN_CHOICES.map((choice) => {
                    const IconComp = choice.icon;
                    return (
                      <button
                        key={choice.id}
                        type="button"
                        role="menuitem"
                        className="wcp-dash-scan-menu-item"
                        onClick={() => handleTargetScanLaunch(choice.id, choice.isTargeted)}
                      >
                        <IconComp size={15} className="wcp-dash-scan-menu-icon" />
                        <div>
                          <div className="wcp-dash-scan-menu-title">{choice.title}</div>
                          <div className="wcp-dash-scan-menu-sub">{choice.subtitle}</div>
                        </div>
                      </button>
                    );
                  })}
                  <hr className="wcp-dash-scan-menu-sep" />
                  <a
                    href={urlScannerTargeted}
                    role="menuitem"
                    className="wcp-dash-scan-menu-item"
                    onClick={() => setScanMenuOpen(false)}
                  >
                    <Target size={15} className="wcp-dash-scan-menu-icon" />
                    <div>
                      <div className="wcp-dash-scan-menu-title">Custom &amp; Targeted Checks &rarr;</div>
                      <div className="wcp-dash-scan-menu-sub">Open full targeted directory &amp; database tools</div>
                    </div>
                  </a>
                </div>
              )}
            </div>

            <button
              type="button"
              className={`wcp-dash-btn-secondary ${internalPaused ? 'is-resuming' : ''}`}
              onClick={handleToggleSafeMode}
              disabled={isPausing}
              title={
                internalPaused
                  ? 'Resume strict firewall protection immediately'
                  : 'Pause strict heuristic checks for 15 minutes while editing'
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
          2. 4 Calm Reassurance KPI Cards (Safety Net Snapshot replaced cleanly)
         ========================================================================= */}
      <section className="wcp-dash-kpi-grid">
        {/* KPI 1: Site Wellness Score */}
        <div className="wcp-dash-kpi-card">
          <div className="wcp-dash-kpi-top">
            <span className="wcp-dash-kpi-label">Site Wellness Score</span>
            <div className="wcp-dash-progress-ring-wrap">
              <svg className="wcp-dash-progress-ring-svg" viewBox="0 0 44 44" aria-hidden="true">
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
              <span style={{ fontSize: '14px', color: 'var(--webcare-text-muted, #94a3b8)', fontWeight: 500 }}>
                /100
              </span>
            </span>
            <span className={`wcp-dash-layer-badge ${healthScore >= 85 ? 'is-active' : 'is-warning'}`}>
              {protectionStatusLabel}
            </span>
          </div>

          <div className="wcp-dash-kpi-bottom">
            <span>Automated diagnostic health</span>
            <a href={urlDoctor} className="wcp-dash-kpi-link">
              Site Doctor <ArrowRight size={12} />
            </a>
          </div>
        </div>

        {/* KPI 2: Distractions Kept Out */}
        <div className="wcp-dash-kpi-card">
          <div className="wcp-dash-kpi-top">
            <span className="wcp-dash-kpi-label">Distractions Kept Out</span>
            <div className="wcp-dash-kpi-icon-badge is-indigo">
              <Shield size={17} />
            </div>
          </div>

          <div className="wcp-dash-kpi-center">
            <span className="wcp-dash-kpi-val wcp-dash-tabular">
              {threatsBlockedCount.toLocaleString()}
            </span>
            <svg
              className="wcp-dash-sparkline-svg"
              viewBox="0 0 72 28"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
              aria-hidden="true"
            >
              <path
                d="M2 24C12 24 16 8 26 14C36 20 42 4 52 10C60 15 64 6 70 2"
                stroke="#6366f1"
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </div>

          <div className="wcp-dash-kpi-bottom">
            <span>Filtered automatically</span>
            <a href={urlFirewallLogs} className="wcp-dash-kpi-link">
              View Logs <ArrowRight size={12} />
            </a>
          </div>
        </div>

        {/* KPI 3 (#3): Plugin & Theme Risks Button */}
        <div className="wcp-dash-kpi-card">
          <div className="wcp-dash-kpi-top">
            <span className="wcp-dash-kpi-label">Plugin &amp; Theme Health</span>
            <div className={`wcp-dash-kpi-icon-badge ${vulnTotal === 0 ? 'is-emerald' : 'is-amber'}`}>
              {vulnTotal === 0 ? <CheckCircle2 size={17} /> : <AlertTriangle size={17} />}
            </div>
          </div>

          <div className="wcp-dash-kpi-center">
            <span
              className="wcp-dash-kpi-val wcp-dash-tabular"
              style={{ color: vulnTotal === 0 ? '#10b981' : '#d97706', fontSize: '20px' }}
            >
              {vulnTotal === 0
                ? '0 Known Risks'
                : `${vulnTotal} Risk${vulnTotal === 1 ? '' : 's'} Found`}
            </span>
          </div>

          <div className="wcp-dash-kpi-bottom">
            <span>{vulnTotal === 0 ? 'All extensions clean' : 'Update check ready'}</span>
            <a
              href={urlScannerRisks}
              className={`wcp-dash-risk-btn ${vulnTotal > 0 ? 'is-warning' : ''}`}
            >
              <span>Check Risks</span>
              <ArrowRight size={12} />
            </a>
          </div>
        </div>

        {/* KPI 4 (#4): Logged-In Administrator Counter -> page=webcare-pro-login&tab=sessions */}
        <div className="wcp-dash-kpi-card">
          <div className="wcp-dash-kpi-top">
            <span className="wcp-dash-kpi-label">Logged-In Administrators</span>
            <div className="wcp-dash-kpi-icon-badge is-cyan">
              <Users size={17} />
            </div>
          </div>

          <div className="wcp-dash-kpi-center">
            {!adminSummary.loaded ? (
              <span className="wcp-dash-kpi-val" style={{ fontSize: '17px' }}>Checking…</span>
            ) : (
              <>
                <span className="wcp-dash-kpi-val wcp-dash-tabular">
                  {adminSummary.adminCount}{' '}
                  <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--webcare-text-muted, #64748b)' }}>
                    {adminSummary.adminCount === 1 ? 'Admin' : 'Admins'}
                  </span>
                </span>
                <span className="wcp-dash-layer-badge is-active">
                  {adminSummary.sessionCount === 1
                    ? '1 Session'
                    : `${adminSummary.sessionCount} Sessions`}
                </span>
              </>
            )}
          </div>

          <div className="wcp-dash-kpi-bottom">
            <span>
              {!adminSummary.loaded
                ? 'Inspecting active logins'
                : adminSummary.usernames.length > 0
                ? `Active: ${adminSummary.usernames.slice(0, 2).join(', ')}`
                : 'No active admin tokens'}
            </span>
            <a href={urlLoginSessions} className="wcp-dash-kpi-link">
              Sessions <ArrowRight size={12} />
            </a>
          </div>
        </div>
      </section>

      {/* =========================================================================
          3. Connected Status Strip: #2 Cloudflare · #5 Scheduled Scan · #6 Alerts
         ========================================================================= */}
      <section className="wcp-dash-status-strip">
        {/* #2 Cloudflare Connect Status */}
        <a href={urlCloudflare} className="wcp-dash-status-link-card">
          <div className="wcp-dash-status-link-left">
            <div className="wcp-dash-status-link-icon is-sky">
              <Globe size={18} />
            </div>
            <div style={{ minWidth: 0 }}>
              <div className="wcp-dash-status-link-kicker">Cloudflare Edge Status</div>
              <div className={`wcp-dash-status-link-val ${cfStatus.configured ? 'is-active' : ''}`}>
                {!cfStatus.loaded ? (
                  'Checking connection…'
                ) : cfStatus.configured ? (
                  <>
                    <Check size={14} />
                    <span>Connected{cfStatus.zoneName ? ` • ${cfStatus.zoneName}` : ''}</span>
                  </>
                ) : (
                  <span>Not Connected</span>
                )}
              </div>
              <div className="wcp-dash-status-link-sub">
                {!cfStatus.loaded
                  ? 'Inspecting edge configuration'
                  : cfStatus.configured
                  ? cfStatus.autoSyncBans
                    ? 'Auto ban sync & real visitor IP active'
                    : 'Zone linked & edge controls ready'
                  : cfStatus.error
                  ? 'Needs verification in Cloudflare settings'
                  : 'Optional — connect free edge shield anytime'}
              </div>
            </div>
          </div>
          <span className="wcp-dash-status-link-cta">Configure &rarr;</span>
        </a>

        {/* #5 Scheduled Scanning Status */}
        <a href={urlSchedules} className="wcp-dash-status-link-card">
          <div className="wcp-dash-status-link-left">
            <div className="wcp-dash-status-link-icon is-sage">
              <CalendarClock size={18} />
            </div>
            <div style={{ minWidth: 0 }}>
              <div className="wcp-dash-status-link-kicker">Scheduled Scanning</div>
              <div className={`wcp-dash-status-link-val ${scheduleInfo.enabled ? 'is-active' : ''}`}>
                {!scheduleInfo.loaded ? (
                  'Loading schedule…'
                ) : scheduleInfo.enabled ? (
                  <>
                    <Check size={14} />
                    <span>Active &bull; {formatFrequencyLabel(scheduleInfo.frequency)}</span>
                  </>
                ) : (
                  <span>Manual Scans Only</span>
                )}
              </div>
              <div className="wcp-dash-status-link-sub">
                {!scheduleInfo.loaded
                  ? 'Checking background cron schedule'
                  : scheduleInfo.enabled
                  ? scheduleInfo.nextScheduledHuman || 'Automated checkups enabled'
                  : 'Turn on automatic daily or weekly scans'}
              </div>
            </div>
          </div>
          <span className="wcp-dash-status-link-cta">Schedule &rarr;</span>
        </a>

        {/* #6 Notification Settings Link */}
        <a href={urlAlerts} className="wcp-dash-status-link-card">
          <div className="wcp-dash-status-link-left">
            <div className="wcp-dash-status-link-icon is-indigo">
              <Bell size={18} />
            </div>
            <div style={{ minWidth: 0 }}>
              <div className="wcp-dash-status-link-kicker">Security Notifications</div>
              <div className={`wcp-dash-status-link-val ${scheduleInfo.alertsEnabled ? 'is-active' : ''}`}>
                {!scheduleInfo.loaded
                  ? 'Checking alert channels…'
                  : scheduleInfo.alertsEnabled
                  ? 'Email Alerts Active'
                  : 'Alerts Standby'}
              </div>
              <div className="wcp-dash-status-link-sub">
                {!scheduleInfo.loaded
                  ? 'Checking email preferences'
                  : scheduleInfo.alertsEnabled && scheduleInfo.alertEmail
                  ? `Sending to ${scheduleInfo.alertEmail}`
                  : 'Choose when WebCare Pro notifies you'}
              </div>
            </div>
          </div>
          <span className="wcp-dash-status-link-cta">Alerts &rarr;</span>
        </a>
      </section>

      {/* =========================================================================
          4. Lower Sanctuary Bento Grid: Always-On Site Care + Quiet Activity Journal
         ========================================================================= */}
      <div className="wcp-dash-lower-grid">
        {/* Left Column: Expandable Always-On Guards */}
        <div className="wcp-dash-card">
          <div className="wcp-dash-card-header">
            <div className="wcp-dash-card-title-group">
              <Layers size={18} color="#10b981" />
              <h3 className="wcp-dash-card-title">Always-On Site Care</h3>
            </div>
            <span className="wcp-dash-layer-badge is-active">
              <Check size={11} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
              Active &amp; Guarded
            </span>
          </div>
          <p className="wcp-dash-card-subtitle">
            Click any guard below to read in plain English what it quietly takes care of for you.
          </p>

          <div className="wcp-dash-layers-grid">
            {careLayers.map((layer) => {
              const isOpen = expandedLayerKey === layer.key;
              const LayerIcon = layer.icon;
              return (
                <div key={layer.key} className="wcp-dash-layer-tile">
                  <button
                    type="button"
                    className="wcp-dash-layer-trigger"
                    aria-expanded={isOpen ? 'true' : 'false'}
                    onClick={() => setExpandedLayerKey(isOpen ? null : layer.key)}
                  >
                    <div className="wcp-dash-layer-left" style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                      <LayerIcon size={15} style={{ color: layer.iconColor, flexShrink: 0 }} />
                      <span className="wcp-dash-layer-name">{layer.name}</span>
                    </div>
                    <span className={`wcp-dash-layer-badge is-${layer.tone}`}>
                      {layer.badge}
                    </span>
                  </button>

                  <div className="wcp-dash-layer-details" data-open={isOpen ? 'true' : 'false'}>
                    <div className="wcp-dash-layer-details-inner">
                      <p className="wcp-dash-layer-desc">{layer.desc}</p>
                      <a href={layer.href} className="wcp-dash-kpi-link">
                        {layer.linkText} <ArrowRight size={12} />
                      </a>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Quiet Activity Journal */}
        <div className="wcp-dash-card">
          <div className="wcp-dash-card-header">
            <div className="wcp-dash-card-title-group">
              <Activity size={18} color="#6366f1" />
              <h3 className="wcp-dash-card-title">Quiet Activity Journal</h3>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <a href={urlAdminActivity} className="wcp-dash-kpi-link">
                Admin Activity
              </a>
              <a href={urlFirewallLogs} className="wcp-dash-kpi-link">
                All Logs <ArrowRight size={12} />
              </a>
            </div>
          </div>
          <p className="wcp-dash-card-subtitle">
            Recent automated protections handled calmly without interrupting your visitors.
          </p>

          <div className="wcp-dash-pulse-timeline">
            {firewallLogs && firewallLogs.length > 0 ? (
              firewallLogs.slice(0, 4).map((log: any, idx: number) => {
                const categoryClean = log.rule_category
                  ? String(log.rule_category).replace(/_/g, ' ')
                  : 'Suspicious Request';
                return (
                  <div key={log.id || `pulse-log-${idx}`} className="wcp-dash-pulse-item">
                    <div className="wcp-dash-pulse-dot" />
                    <div className="wcp-dash-pulse-body">
                      <div className="wcp-dash-pulse-header">
                        <span className="wcp-dash-pulse-rule">
                          Quietly filtered {categoryClean}
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
                All quiet — no suspicious traffic has needed filtering recently.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* =========================================================================
          5. Subtle System Readiness Footer Strip (.wcp-dash-footer-strip)
         ========================================================================= */}
      <footer className="wcp-dash-footer-strip">
        <div className="wcp-dash-footer-items">
          <div className="wcp-dash-footer-item">
            <span className="wcp-dash-footer-dot" />
            <span>PHP:</span>
            <span className="wcp-dash-footer-val wcp-dash-tabular">{resolvedPhpVersion}</span>
          </div>

          <div className="wcp-dash-footer-item">
            <span>WordPress:</span>
            <span className="wcp-dash-footer-val wcp-dash-tabular">{resolvedWpVersion}</span>
          </div>

          <div className="wcp-dash-footer-item">
            <span>Server:</span>
            <span className="wcp-dash-footer-val">{resolvedServerEngine}</span>
          </div>

          <div className="wcp-dash-footer-item">
            <span>Quarantined Files:</span>
            <span className="wcp-dash-footer-val wcp-dash-tabular">
              {quarantinedFiles?.length || 0}
            </span>
          </div>
        </div>

        <div className="wcp-dash-footer-item">
          <FolderSearch size={13} />
          <span>Protection Mode:</span>
          <span className="wcp-dash-footer-val">Active / Fail-Closed</span>
        </div>
      </footer>
    </div>
  );
};

export default DashboardOverview;
