import { useState, useEffect, useMemo } from '@wordpress/element';
import { CronManagerPage } from './CronManager/CronManagerPage';
import { NotificationsPage } from './NotificationsPage';
import {
  Settings,
  Calendar,
  Mail,
  Cpu,
  Download,
  Upload,
  RotateCcw,
  Save,
  CheckCircle2,
  AlertTriangle,
  Info,
  Clock,
  Key,
  ShieldAlert,
  Sparkles,
  Sliders,
  Check,
  Copy,
  Loader2,
  Zap,
  Lock,
  Eye,
  EyeOff,
  Filter,
  FileCode,
  CheckCircle,
  HelpCircle,
  RefreshCw,
  Trash2,
  Database,
  Shield,
  ShieldCheck,
  MessageSquare,
  Activity,
  Send,
  Share2,
  LifeBuoy,
  ExternalLink,
  Globe,
  Phone,
  Star,
  Users,
  ArrowUpRight,
  X,
  Bot,
  Cloud,
  Stethoscope
} from 'lucide-react';
import { MCPAgentServiceCard } from './components/MCPAgentServiceCard';
import { EmergencyContainmentCard } from './components/EmergencyContainmentCard';
import { DoctorRescueCenter } from './components/DoctorRescueCenter';
import { PluginConflictCheckerCard } from './components/PluginConflictCheckerCard';
import { ConfirmDialog } from './components/ConfirmDialog';
import { UnsavedChangesBar } from './components/ui/UnsavedChangesBar';
import { useWorkspaceMode } from './hooks/useWorkspaceMode';
import { toast } from './utils/dialog';

interface ScannerSettings {
  confidence_threshold_filesystem?: number;
  confidence_threshold_lotl?: number;
  confidence_threshold_ai?: number;
  confidence_threshold_db?: number;
  auto_suppress_whitelisted?: boolean;
  mcp_enabled?: boolean;
  mcp_token?: string;
  schedule_enabled: boolean;
  schedule_frequency: string;
  schedule_time: string;
  schedule_scan_type: string;

  email_alerts_enabled: boolean;
  alert_emails: string;
  alert_min_severity: string;
  email_digest_enabled: boolean;
  email_on_scan_completed: boolean;
  notify_on_cve_detected: boolean;
  threat_intel_enabled?: boolean;
  threat_intel_cisa_kev_enabled?: boolean;
  threat_intel_nvd_cve_enabled?: boolean;
  threat_intel_public_cidr_enabled?: boolean;
  email_report_items_limit?: number;

  slack_enabled?: boolean;
  slack_webhook_url?: string;
  discord_enabled?: boolean;
  discord_webhook_url?: string;
  clickup_enabled?: boolean;
  clickup_webhook_url?: string;
  asana_enabled?: boolean;
  asana_webhook_url?: string;
  generic_webhook_enabled?: boolean;
  generic_webhook_url?: string;
  webhook_notify_on_critical?: boolean;
  webhook_notify_on_fim?: boolean;
  webhook_notify_on_waf_block?: boolean;
  webhook_notify_on_scan_finish?: boolean;

  ai_enabled: boolean;
  ai_provider: 'openai' | 'gemini' | 'claude' | 'wp_ai_connect';
  openai_api_key?: string;
  openai_model?: string;
  gemini_api_key?: string;
  gemini_model?: string;
  claude_api_key?: string;
  claude_model?: string;
  ai_temperature?: number;
  ai_auto_analyze_critical?: boolean;
    ai_connect_status?: {
    is_available: boolean;
    engine_name: string;
    engine_slug: string;
    detected_via?: string;
    connectors_url?: string;
    has_connectors_page?: boolean;
    active_connectors?: string[];
    details: string;
    recommended_plugin?: {
      name: string;
      slug: string;
      author: string;
      install_url: string;
      description: string;
    };
  };

  has_openai_key?: boolean;
  has_gemini_key?: boolean;
  has_claude_key?: boolean;
  has_slack_webhook?: boolean;
  has_discord_webhook?: boolean;
  has_clickup_webhook?: boolean;
  has_asana_webhook?: boolean;
  has_generic_webhook?: boolean;

  scan_batch_size: number;
  scan_batch_delay_ms?: number;
  scan_execution_strategy?: 'ajax_client' | 'wp_cli_cron' | 'background_worker';
  scan_uploads_mode?: 'smart_executable' | 'deep_raster';
  scan_symlink_policy?: 'ignore' | 'follow_intree' | 'follow_all';
  scan_skip_vcs?: boolean;
  scan_skip_vendor?: boolean;
  scan_skip_cache?: boolean;
  scan_db_batch_size?: number;
  scan_excluded_tables?: string;
  scan_profiling_enabled?: boolean;
  scan_dry_run_mode?: boolean;
  memory_limit_override: string;
  max_file_size_kb: number;
  auto_quarantine_critical: boolean;

  excluded_paths: string;
  custom_extensions: string;

  disable_file_editing: boolean;
  hide_wp_version: boolean;
  block_sensitive_files: boolean;
  block_user_enumeration?: boolean;
  delete_data_on_uninstall?: boolean;
  waf_log_retention_days?: number;

  // HTTP Security Headers
  header_hsts?: boolean;
  header_hsts_preload?: boolean;
  header_x_frame_options?: boolean;
  header_x_frame_options_mode?: 'SAMEORIGIN' | 'DENY';
  header_nosniff?: boolean;
  header_referrer_policy?: boolean;
  header_referrer_policy_value?: string;
  header_permissions_policy?: boolean;
  header_permissions_policy_value?: string;
  header_xss_protection?: boolean;
  header_csp_enabled?: boolean;
  header_csp_custom?: string;
}

export type SettingsSubTab =
  | 'containment'
  | 'troubleshooter'
  | 'schedule'
  | 'cron'
  | 'email'
  | 'alerts'
  | 'webhooks'
  | 'cloudflare'
  | 'headers'
  | 'ai'
  | 'mcp'
  | 'performance'
  | 'import_export'
  | 'cleanup'
  | 'activity_logs'
  | 'support';


interface SettingsPageProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  onNavigateToDashboard?: () => void;
  onNavigateToNotifications?: () => void;
  onNavigateToActivityLogs?: () => void;
  onNavigateToCronManager?: () => void;
  initialSubTab?: SettingsSubTab;
}

// Reusable Modern Toggle Switch Component
const ToggleSwitch = ({
  checked,
  onChange,
  disabled = false,
  label,
  description,
  badge,
  activeColor = '#10b981',
}: {
  checked: boolean;
  onChange: (val: boolean) => void;
  disabled?: boolean;
  label?: React.ReactNode;
  description?: React.ReactNode;
  badge?: React.ReactNode;
  activeColor?: string;
}) => {
  return (
    <div
      onClick={() => !disabled && onChange(!checked)}
      className={`webcare-settings-toggle-row ${checked ? 'is-checked' : 'is-unchecked'}`}
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'space-between',
        gap: '16px',
        cursor: disabled ? 'not-allowed' : 'pointer',
        userSelect: 'none',
        opacity: disabled ? 0.6 : 1,
        padding: '12px 16px',
        borderRadius: '10px',
        transition: 'all 0.15s ease',
      }}
    >
      <div style={{ flex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <span className="webcare-settings-toggle-label" style={{ fontSize: '14px', fontWeight: 600 }}>{label}</span>
          {badge && <span className="webcare-settings-toggle-badge-wrap">{badge}</span>}
        </div>
        {description && (
          <div className="webcare-settings-toggle-desc" style={{ margin: '4px 0 0 0', fontSize: '13px', lineHeight: 1.5 }}>
            {description}
          </div>
        )}
      </div>
      <div
        className={`webcare-settings-toggle-track ${checked ? 'is-on' : 'is-off'}`}
        style={{
          width: '42px',
          height: '24px',
          borderRadius: '12px',
          background: checked ? (activeColor || '#10b981') : 'var(--webcare-toggle-off-bg, #cbd5e1)',
          position: 'relative',
          transition: 'all 0.2s ease',
          flexShrink: 0,
          marginTop: '2px',
          boxShadow: checked
            ? '0 0 10px rgba(16, 185, 129, 0.4), inset 0 1px 2px rgba(0,0,0,0.1)'
            : 'inset 0 1px 2px rgba(0,0,0,0.1)',
        }}
      >
        <div
          className="webcare-settings-toggle-thumb"
          style={{
            width: '18px',
            height: '18px',
            borderRadius: '50%',
            position: 'absolute',
            top: '3px',
            left: checked ? '21px' : '3px',
            transition: 'left 0.2s ease',
            boxShadow: '0 1px 3px rgba(0,0,0,0.25)',
          }}
        />
      </div>
    </div>
  );
};

interface SettingsTabMeta {
  id: SettingsSubTab;
  label: string;
  shortDesc: string;
  icon: any;
  isNew?: boolean;
  getBadge: (s: ScannerSettings | null, audit?: any, cfStatus?: any) => { text: string; bg: string; color: string } | null;
}

interface SettingsCategoryGroup {
  id: string;
  name: string;
  tagline: string;
  badge: string;
  accent: string;
  accentLight: string;
  accentBorder: string;
  tabs: SettingsTabMeta[];
}

const SETTINGS_CATEGORIES: SettingsCategoryGroup[] = [
  {
    id: 'health_rescue',
    name: 'Health & Rescue',
    tagline: 'Live runtime diagnostics, 15m Safe Mode & emergency containment',
    badge: 'Rescue',
    accent: '#dc2626',
    accentLight: '#fef2f2',
    accentBorder: '#fecaca',
    tabs: [
      {
        id: 'troubleshooter',
        label: 'Doctor & Rescue Center',
        shortDesc: 'Live runtime diagnostics, 15m Safe Mode & telemetry export',
        icon: Stethoscope,
        isNew: true,
        getBadge: () => ({ text: 'Doctor AI', bg: '#ecfdf5', color: '#047857' })
      },
      {
        id: 'containment',
        label: 'Emergency Containment',
        shortDesc: 'Freeze blast radius, lock filesystem & terminate sessions',
        icon: ShieldAlert,
        getBadge: () => ({ text: 'Incident Shield', bg: '#fee2e2', color: '#991b1b' })
      }
    ]
  },
  {
    id: 'alerts_schedules',
    name: 'Alerts & Schedules',
    tagline: 'Scan schedules, email delivery & DevSecOps webhooks',
    badge: 'Pipelines',
    accent: '#0284c7',
    accentLight: '#f0f9ff',
    accentBorder: '#bae6fd',
    tabs: [
      {
        id: 'schedule',
        label: 'Schedule Scans',
        shortDesc: 'Automated background cron runs',
        icon: Calendar,
        getBadge: (s) => (s?.schedule_enabled ? { text: 'Active Cron', bg: '#ecfdf5', color: '#059669' } : { text: 'Manual Only', bg: '#f1f5f9', color: '#64748b' })
      },
      {
        id: 'cron',
        label: 'Scheduled Tasks (Cron)',
        shortDesc: '15 Background WP-Cron tasks & logs',
        icon: Clock,
        getBadge: () => ({ text: '15 Tasks', bg: '#e0f2fe', color: '#0284c7' })
      },
      {
        id: 'email',
        label: 'Email Alerts',
        shortDesc: 'Instant threat & digest notices',
        icon: Mail,
        getBadge: (s) => (s?.email_alerts_enabled ? { text: 'Alerts On', bg: '#ecfdf5', color: '#059669' } : { text: 'Off', bg: '#f1f5f9', color: '#64748b' })
      },
      {
        id: 'alerts',
        label: 'Security Notifications',
        shortDesc: '60+ event notification matrix',
        icon: ShieldAlert,
        getBadge: () => ({ text: '60+ Events', bg: '#fef3c7', color: '#b45309' })
      },
      {
        id: 'webhooks',
        label: 'DevSecOps Webhooks',
        shortDesc: 'Slack, Discord, ClickUp & Asana',
        icon: MessageSquare,
        getBadge: (s) => {
          const activeCount = [s?.slack_enabled, s?.discord_enabled, s?.clickup_enabled, s?.asana_enabled, s?.generic_webhook_enabled].filter(Boolean).length;
          return activeCount > 0 ? { text: `${activeCount} Webhook(s)`, bg: '#dcfce7', color: '#15803d' } : { text: 'Slack/Discord', bg: '#f1f5f9', color: '#64748b' };
        }
      },
      {
        id: 'threat_intel',
        label: 'Threat Intel & NIST Sync',
        shortDesc: 'Public feeds & NIST NVD API key',
        icon: Shield,
        getBadge: () => ({ text: 'NIST / Feeds', bg: '#e0f2fe', color: '#0284c7' })
      }
    ]
  },
  {
    id: 'hardening_ai',
    name: 'Hardening & AI',
    tagline: 'HTTP hardening, Cloudflare edge status & AI heuristics',
    badge: 'Defense Core',
    accent: '#7c3aed',
    accentLight: '#f5f3ff',
    accentBorder: '#ddd6fe',
    tabs: [
      {
        id: 'headers',
        label: 'Headers & Hardening',
        shortDesc: '1-Click A+ HTTP security presets',
        icon: ShieldCheck,
        getBadge: (_s, audit) => (audit?.grade ? { text: `Grade ${audit.grade}`, bg: '#ecfdf5', color: '#047857' } : { text: 'A+ Preset', bg: '#ecfdf5', color: '#047857' })
      },
      {
        id: 'cloudflare',
        label: 'Cloudflare Edge Status',
        shortDesc: 'Edge synchronization status & jump to WAF',
        icon: Cloud,
        getBadge: (_s, _audit, cfStatus) => {
          const isConnected = !!(cfStatus?.configured || (cfStatus?.zone_id && cfStatus?.zone_name));
          return isConnected
            ? { text: 'Edge Connected', bg: '#ecfdf5', color: '#047857' }
            : { text: 'Edge Setup', bg: '#ffedd5', color: '#c2410c' };
        }
      },
      {
        id: 'ai',
        label: 'AI Code Forensics',
        shortDesc: 'ChatGPT, Gemini & Claude heuristics',
        icon: Sparkles,
        getBadge: (s) => (s?.ai_enabled ? { text: s.ai_provider === 'wp_ai_connect' ? 'Native AI Active' : `${(s.ai_provider || 'AI').toUpperCase()} Active`, bg: '#e0f2fe', color: '#0369a1' } : { text: 'Heuristics Off', bg: '#f1f5f9', color: '#64748b' })
      },
      {
        id: 'mcp',
        label: 'Model Context Protocol (MCP)',
        shortDesc: 'Claude Desktop, Cursor & Agentic tools',
        icon: Bot,
        isNew: true,
        getBadge: (s) => (s?.mcp_enabled ? { text: 'Agent Live', bg: '#cffafe', color: '#0891b2' } : { text: 'Agent Ready', bg: '#f0fdf4', color: '#16a34a' })
      }
    ]
  },
  {
    id: 'logs_activity',
    name: 'Logs & Activity',
    tagline: 'Cryptographic audit ledger & forensic event trail',
    badge: 'Forensics',
    accent: '#0284c7',
    accentLight: '#f0f9ff',
    accentBorder: '#bae6fd',
    tabs: [
      {
        id: 'activity_logs',
        label: 'Plugin Activity & Audit Logs',
        shortDesc: 'Cryptographic audit ledger & tamper defense',
        icon: Activity,
        isNew: true,
        getBadge: () => ({ text: 'Forensic Ledger', bg: '#e0f2fe', color: '#0284c7' })
      }
    ]
  },
  {
    id: 'system_updates',
    name: 'System & Maintenance',
    tagline: 'Resource limits, configuration backup, cleanup & direct support',
    badge: 'System',
    accent: '#0f766e',
    accentLight: '#f0fdfa',
    accentBorder: '#99f6e4',
    tabs: [
      {
        id: 'performance',
        label: 'Engine & Performance',
        shortDesc: 'Batch limits & memory overrides',
        icon: Sliders,
        getBadge: () => ({ text: 'Tuning', bg: '#f1f5f9', color: '#475569' })
      },
      {
        id: 'import_export',
        label: 'Import & Export',
        shortDesc: 'Portable JSON config backup',
        icon: Download,
        getBadge: () => ({ text: 'Backup/Sync', bg: '#f1f5f9', color: '#475569' })
      },
      {
        id: 'cleanup',
        label: 'Data & Purge',
        shortDesc: 'Database tables & uninstall behavior',
        icon: Trash2,
        getBadge: (s) => (s?.delete_data_on_uninstall ? { text: 'Auto-Purge', bg: '#fee2e2', color: '#991b1b' } : { text: 'Retain', bg: '#f1f5f9', color: '#64748b' })
      },
      {
        id: 'support',
        label: 'Support & Services',
        shortDesc: 'Direct 1-on-1 engineer assistance',
        icon: LifeBuoy,
        getBadge: () => ({ text: '1-on-1 Direct', bg: '#dbeafe', color: '#1e40af' })
      }
    ]
  }
];

export const SettingsPage = ({ apiRequest, onNavigateToDashboard, onNavigateToNotifications, onNavigateToActivityLogs, onNavigateToCronManager, initialSubTab }: SettingsPageProps) => {
  const { isSimpleMode, setMode } = useWorkspaceMode();
  const normalizeSubTab = (tab: string | null): SettingsSubTab | null => {
    if (!tab) return null;
    const tabMap: Record<string, SettingsSubTab> = {
      health: 'troubleshooter',
      troubleshooter: 'troubleshooter',
      doctor: 'troubleshooter',
      emergency: 'containment',
      containment: 'containment',
      cron: 'cron',
      'cron-manager': 'cron',
      schedules: 'schedule',
      schedule: 'schedule',
      alerts: 'alerts',
      notifications: 'alerts',
      email: 'email',
      webhooks: 'webhooks',
      cloudflare: 'cloudflare',
      headers: 'headers',
      ai: 'ai',
      mcp: 'mcp',
      performance: 'performance',
      'import-export': 'import_export',
      import_export: 'import_export',
      data: 'cleanup',
      cleanup: 'cleanup',
      activity_logs: 'activity_logs',
      about: 'support',
      support: 'support',
    };
    return tabMap[tab] || null;
  };

  const getStartingSubTab = (): SettingsSubTab => {
    if (initialSubTab) {
      const normalized = normalizeSubTab(initialSubTab);
      if (normalized) return normalized;
    }
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const sub = urlParams.get('tab') || urlParams.get('subtab');
      const normalized = normalizeSubTab(sub);
      if (normalized) return normalized;
    } catch (e) {}
    return 'schedule';
  };

  const [activeSubTab, setActiveSubTab] = useState<SettingsSubTab>(getStartingSubTab);
  const [copiedQuery, setCopiedQuery] = useState<boolean>(false);
  const [settings, setSettings] = useState<ScannerSettings | null>(null);
  const [initialSettingsSnapshot, setInitialSettingsSnapshot] = useState<string | null>(null);

  // In-App Confirm Dialog State
  const [settingsConfirmDialog, setSettingsConfirmDialog] = useState<{
    isOpen: boolean;
    title: string;
    message: string | React.ReactNode;
    targetItem?: string;
    confirmLabel?: string;
    variant?: 'danger' | 'warning' | 'info';
    isLoading?: boolean;
    onConfirm?: () => void | Promise<void>;
  }>({
    isOpen: false,
    title: '',
    message: '',
  });

  const requestSettingsConfirm = ({
    title,
    message,
    targetItem,
    confirmLabel = 'Confirm Action',
    variant = 'danger',
    onConfirm,
  }: {
    title: string;
    message: string | React.ReactNode;
    targetItem?: string;
    confirmLabel?: string;
    variant?: 'danger' | 'warning' | 'info';
    onConfirm: () => void | Promise<void>;
  }) => {
    setSettingsConfirmDialog({
      isOpen: true,
      title,
      message,
      targetItem,
      confirmLabel,
      variant,
      isLoading: false,
      onConfirm: async () => {
        try {
          setSettingsConfirmDialog((prev) => ({ ...prev, isLoading: true }));
          await onConfirm();
          setSettingsConfirmDialog((prev) => ({ ...prev, isOpen: false, isLoading: false }));
        } catch (err: any) {
          console.error(err);
          setSettingsConfirmDialog((prev) => ({ ...prev, isLoading: false }));
        }
      },
    });
  };

  const isDirty = useMemo(() => {
    if (!settings || !initialSettingsSnapshot) return false;
    try {
      return JSON.stringify(settings) !== initialSettingsSnapshot;
    } catch {
      return false;
    }
  }, [settings, initialSettingsSnapshot]);

  const handleDiscardChanges = () => {
    if (!initialSettingsSnapshot) return;
    try {
      setSettings(JSON.parse(initialSettingsSnapshot));
      toast.info('Unsaved changes discarded.');
    } catch {}
  };

  const toCanonicalTabSlug = (tab: SettingsSubTab): string => {
    switch (tab) {
      case 'troubleshooter': return 'doctor';
      case 'containment': return 'lockdown';
      case 'schedule': return 'schedules';
      case 'import_export': return 'import-export';
      case 'cleanup': return 'data';
      default: return tab;
    }
  };

  const handleTabChange = (newTab: SettingsSubTab) => {
    if (isDirty) {
      requestSettingsConfirm({
        title: 'Discard unsaved changes?',
        message: 'You have unsaved configuration changes in this tab. If you switch tabs now, your edits will be discarded.',
        confirmLabel: 'Discard & Switch',
        variant: 'warning',
        onConfirm: () => {
          handleDiscardChanges();
          setActiveSubTab(newTab);
          try {
            const url = new URL(window.location.href);
            const canonical = toCanonicalTabSlug(newTab);
            url.searchParams.set('tab', canonical);
            url.searchParams.delete('subtab');
            url.searchParams.delete('section');
            window.history.pushState({ tab: canonical }, '', url.toString());
          } catch (e) {}
        },
      });
      return;
    }

    setActiveSubTab(newTab);
    try {
      const url = new URL(window.location.href);
      const canonical = toCanonicalTabSlug(newTab);
      url.searchParams.set('tab', canonical);
      url.searchParams.delete('subtab');
      url.searchParams.delete('section');
      window.history.pushState({ tab: canonical }, '', url.toString());
    } catch (e) {}
  };

  // Auto-switch to Developer Mode on explicit deep link to an engineer tab, or fallback to 'troubleshooter' if switched manually to Simple Mode
  useEffect(() => {
    const engineerTabs: SettingsSubTab[] = [
      'containment',
      'webhooks',
      'headers',
      'ai',
      'mcp',
      'performance',
      'import_export',
      'activity_logs',
    ];
    if (isSimpleMode && engineerTabs.includes(activeSubTab)) {
      try {
        const urlParams = new URLSearchParams(window.location.search);
        const requestedTab = (urlParams.get('tab') || urlParams.get('subtab')) as SettingsSubTab | null;
        if (requestedTab && engineerTabs.includes(requestedTab)) {
          setMode('developer');
          toast.info(`Switched to Developer Mode for ${requestedTab.replace('_', ' ')}.`);
          return;
        }
      } catch (e) {}
      handleTabChange('troubleshooter');
    }
  }, [isSimpleMode, activeSubTab]);

  const handleCopyDirectLink = () => {
    try {
      const url = new URL(window.location.href);
      url.searchParams.set('tab', activeSubTab);
      url.searchParams.delete('subtab');
      navigator.clipboard.writeText(url.toString());
      setCopiedQuery(true);
      setTimeout(() => setCopiedQuery(false), 2500);
    } catch (e) {}
  };

  useEffect(() => {
    if (initialSubTab) {
      const normalized = normalizeSubTab(initialSubTab);
      if (normalized && normalized !== activeSubTab) {
        setActiveSubTab(normalized);
      }
    }
  }, [initialSubTab]);

  useEffect(() => {
    const handleSync = () => {
      try {
        const urlParams = new URLSearchParams(window.location.search);
        const sub = urlParams.get('tab') || urlParams.get('subtab');
        const normalized = normalizeSubTab(sub);
        if (normalized) {
          setActiveSubTab(normalized);
        }
      } catch (e) {}
    };
    window.addEventListener('popstate', handleSync);
    window.addEventListener('webcare:route-change', handleSync);
    return () => {
      window.removeEventListener('popstate', handleSync);
      window.removeEventListener('webcare:route-change', handleSync);
    };
  }, []);
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [saveSuccess, setSaveSuccess] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [nextScheduled, setNextScheduled] = useState<string | null>(null);
  const [scheduleTimeInfo, setScheduleTimeInfo] = useState<{
    next_run_timestamp?: number | null;
    next_scheduled_wp?: string | null;
    next_scheduled_gmt?: string | null;
    diff_seconds?: number;
    current_wp_time?: string;
    current_gmt_time?: string;
    timezone?: string;
    gmt_offset?: number;
  } | null>(null);
  const [countdownSeconds, setCountdownSeconds] = useState<number | null>(null);

  // Hardening & Security Headers audit state
  const [hardeningAudit, setHardeningAudit] = useState<any>(null);
  const [loadingAudit, setLoadingAudit] = useState<boolean>(false);
  const [applyingPreset, setApplyingPreset] = useState<boolean>(false);

  // AI Connection Test state
  const [testingAi, setTestingAi] = useState<boolean>(false);
  const [aiTestResult, setAiTestResult] = useState<{ success: boolean; message?: string; error?: string } | null>(null);

  // Reset Defaults Confirmation Modal State
  const [resetModalOpen, setResetModalOpen] = useState<boolean>(false);
  const [resetConfirmText, setResetConfirmText] = useState<string>('');
  const [resetting, setResetting] = useState<boolean>(false);

  // Temporary Support Access restriction state
  const [isTemporarySupport, setIsTemporarySupport] = useState<boolean>(() => {
    return Boolean((window as any).webcareScannerSettings?.isTemporarySupport);
  });

  // Helper function to partially mask sensitive webhooks/keys (keeps prefix & tail, masks middle token)
  const getMaskedSecret = (val?: string): string => {
    if (!val) return '';
    const trimmed = val.trim();
    if (trimmed.length <= 16) return '••••••••••••••••';
    // If it's a URL, preserve protocol & host / prefix up to last segment, and mask sensitive token
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
      try {
        const url = new URL(trimmed);
        const prefix = `${url.origin}${url.pathname.substring(0, Math.min(24, Math.floor(url.pathname.length * 0.4)))}`;
        const suffix = trimmed.slice(-4);
        return `${prefix}...••••••••...${suffix}`;
      } catch (e) {
        // Fallback for non-standard URLs
        return `${trimmed.substring(0, 16)}...••••••••...${trimmed.slice(-4)}`;
      }
    }
    // Generic API keys (e.g. sk-..., AIzaSy...)
    const head = trimmed.substring(0, 6);
    const tail = trimmed.slice(-4);
    return `${head}...••••••••...${tail}`;
  };

  // Show/hide API keys
  const [showKey, setShowKey] = useState<Record<string, boolean>>({});

  // Import JSON file ref
  const [importing, setImporting] = useState<boolean>(false);
  const [importStatus, setImportStatus] = useState<string | null>(null);

  // AI Models Catalog and Auto-update state
  const [modelCatalog, setModelCatalog] = useState<any>(null);
  const [updatingModels, setUpdatingModels] = useState<boolean>(false);
  const [modelUpdateMsg, setModelUpdateMsg] = useState<{ success: boolean; text: string } | null>(null);

  // Webhook Test & Save/Remove State
  const [testingWebhook, setTestingWebhook] = useState<{
    slack: boolean;
    discord: boolean;
    clickup: boolean;
    asana: boolean;
    generic: boolean;
  }>({ slack: false, discord: false, clickup: false, asana: false, generic: false });
  const [savingWebhook, setSavingWebhook] = useState<{
    slack: boolean;
    discord: boolean;
    clickup: boolean;
    asana: boolean;
    generic: boolean;
  }>({ slack: false, discord: false, clickup: false, asana: false, generic: false });
  const [webhookSavedFeedback, setWebhookSavedFeedback] = useState<{ [platform: string]: boolean }>({});
  const [webhookTestResult, setWebhookTestResult] = useState<{ platform: string; success: boolean; message: string } | null>(null);

  const handleSaveWebhook = async (platform: 'slack' | 'discord' | 'clickup' | 'asana' | 'generic') => {
    if (!settings) return;
    try {
      setSavingWebhook((prev) => ({ ...prev, [platform]: true }));
      const fieldMap: Record<string, string> = {
        slack: 'slack_webhook_url',
        discord: 'discord_webhook_url',
        clickup: 'clickup_webhook_url',
        asana: 'asana_webhook_url',
        generic: 'generic_webhook_url',
      };
      const enabledMap: Record<string, string> = {
        slack: 'slack_enabled',
        discord: 'discord_enabled',
        clickup: 'clickup_enabled',
        asana: 'asana_enabled',
        generic: 'generic_webhook_enabled',
      };
      const fieldName = fieldMap[platform];
      const enabledName = enabledMap[platform];
      const urlValue = (settings as any)[fieldName] || '';

      const payload: any = {
        [fieldName]: urlValue,
      };
      // Auto-enable if URL is provided
      if (urlValue.trim() !== '') {
        payload[enabledName] = true;
      }

      const res = await apiRequest({
        path: '/settings',
        method: 'POST',
        data: payload,
      });

      if (res && res.success) {
        setSettings((prev: any) => ({
          ...prev,
          ...res.settings,
        }));
        setShowKey((prev) => ({ ...prev, [platform]: false }));
        setWebhookSavedFeedback((prev) => ({ ...prev, [platform]: true }));
        setTimeout(() => {
          setWebhookSavedFeedback((prev) => ({ ...prev, [platform]: false }));
        }, 2500);
      }
    } catch (err: any) {
      console.error('Failed to save webhook', err);
      setSaveError(err?.message || 'Failed to save webhook URL.');
    } finally {
      setSavingWebhook((prev) => ({ ...prev, [platform]: false }));
    }
  };

  const handleRemoveWebhook = async (platform: 'slack' | 'discord' | 'clickup' | 'asana' | 'generic') => {
    if (!settings) return;
    const platformNames: Record<string, string> = {
      slack: 'Slack',
      discord: 'Discord',
      clickup: 'ClickUp',
      asana: 'Asana',
      generic: 'Automation',
    };
    const name = platformNames[platform] || 'Webhook';

    requestSettingsConfirm({
      title: `Remove ${name} Webhook`,
      message: `Are you sure you want to remove the ${name} webhook integration? Alerts will no longer be forwarded to this endpoint.`,
      confirmLabel: `Remove ${name} Webhook`,
      variant: 'danger',
      onConfirm: async () => {
        try {
          setSavingWebhook((prev) => ({ ...prev, [platform]: true }));
          const fieldMap: Record<string, string> = {
            slack: 'slack_webhook_url',
            discord: 'discord_webhook_url',
            clickup: 'clickup_webhook_url',
            asana: 'asana_webhook_url',
            generic: 'generic_webhook_url',
          };
          const enabledMap: Record<string, string> = {
            slack: 'slack_enabled',
            discord: 'discord_enabled',
            clickup: 'clickup_enabled',
            asana: 'asana_enabled',
            generic: 'generic_webhook_enabled',
          };
          const fieldName = fieldMap[platform];
          const enabledName = enabledMap[platform];

          const payload = {
            [fieldName]: '',
            [enabledName]: false,
          };

          const res = await apiRequest({
            path: '/settings',
            method: 'POST',
            data: payload,
          });

          if (res && res.success) {
            setSettings((prev: any) => ({
              ...prev,
              ...res.settings,
              [fieldName]: '',
              [`has_${platform}_webhook`]: false,
              [enabledName]: false,
            }));
            setShowKey((prev) => ({ ...prev, [platform]: false }));
          }
        } catch (err: any) {
          console.error('Failed to remove webhook', err);
          setSaveError(err?.message || 'Failed to remove webhook.');
        } finally {
          setSavingWebhook((prev) => ({ ...prev, [platform]: false }));
        }
      },
    });
  };

  const handleTestWebhook = async (platform: 'slack' | 'discord' | 'clickup' | 'asana' | 'generic') => {
    try {
      setTestingWebhook((prev) => ({ ...prev, [platform]: true }));
      setWebhookTestResult(null);

      let url = '';
      if (platform === 'slack') url = settings?.slack_webhook_url || '';
      else if (platform === 'discord') url = settings?.discord_webhook_url || '';
      else if (platform === 'clickup') url = settings?.clickup_webhook_url || '';
      else if (platform === 'asana') url = settings?.asana_webhook_url || '';
      else if (platform === 'generic') url = settings?.generic_webhook_url || '';

      const res = await apiRequest({
        path: '/notifications/test-webhook',
        method: 'POST',
        data: {
          platform,
          webhook_url: url,
        },
      });

      if (res) {
        setWebhookTestResult({
          platform,
          success: !!res.success,
          message: res.message || (res.success ? 'Test webhook alert sent successfully!' : 'Delivery failed.'),
        });
      }
    } catch (err: any) {
      setWebhookTestResult({
        platform,
        success: false,
        message: err?.message || 'Error occurred while contacting webhook endpoint.',
      });
    } finally {
      setTestingWebhook((prev) => ({ ...prev, [platform]: false }));
    }
  };

  // ==========================================
  // Cloudflare API & Edge State
  // ==========================================
  const [cfStatus, setCfStatus] = useState<any>(null);
  const [loadingCf, setLoadingCf] = useState<boolean>(false);
  const [cfToken, setCfToken] = useState<string>('');
  const [cfZoneId, setCfZoneId] = useState<string>('');
  const [showCfToken, setShowCfToken] = useState<boolean>(false);
  const [showCfZone, setShowCfZone] = useState<boolean>(false);
  const [cfAutoSyncBans, setCfAutoSyncBans] = useState<boolean>(true);
  const [cfVerifying, setCfVerifying] = useState<boolean>(false);
  const [cfVerifyResult, setCfVerifyResult] = useState<any>(null);
  const [disconnectingCf, setDisconnectingCf] = useState<boolean>(false);

  const loadCloudflareData = async () => {
    try {
      setLoadingCf(true);
      const res = await apiRequest({ path: '/cloudflare/status', method: 'GET' });
      if (res && res.status) {
        setCfStatus(res.status);
        if (res.status.configured) {
          setCfAutoSyncBans(!!res.status.auto_sync_bans);
        }
      }
    } catch (err) {
      console.error('Failed to load Cloudflare status', err);
    } finally {
      setLoadingCf(false);
    }
  };

  const handleToggleAutoSyncBans = async (val: boolean) => {
    setCfAutoSyncBans(val);
    if (cfStatus?.configured) {
      try {
        await apiRequest({
          path: '/settings',
          method: 'POST',
          data: { cloudflare_auto_sync_bans: val }
        });
        await loadCloudflareData();
      } catch (err) {
        console.error('Failed to update Cloudflare auto-sync bans', err);
      }
    }
  };

  const handleVerifyCloudflare = async () => {
    try {
      setCfVerifying(true);
      setCfVerifyResult(null);
      const res = await apiRequest({
        path: '/cloudflare/verify',
        method: 'POST',
        data: {
          token: cfToken.trim() || undefined,
          zone_id: cfZoneId.trim() || undefined,
        }
      });
      setCfVerifyResult(res);
      if (res && res.success) {
        const resolvedZoneId = (res.zone_id || cfZoneId).trim();
        if (resolvedZoneId) {
          setCfZoneId(resolvedZoneId);
        }
        setCfAutoSyncBans(true);
        await apiRequest({
          path: '/settings',
          method: 'POST',
          data: {
            cloudflare_enabled: true,
            cloudflare_api_token: cfToken.trim() || undefined,
            cloudflare_zone_id: resolvedZoneId,
            cloudflare_auto_sync_bans: true,
          }
        });
        await loadCloudflareData();
      }
    } catch (err: any) {
      setCfVerifyResult({
        success: false,
        message: err?.message || 'Verification request failed'
      });
    } finally {
      setCfVerifying(false);
    }
  };

  const handleDisconnectCloudflare = async () => {
    requestSettingsConfirm({
      title: 'Disconnect Cloudflare Integration',
      message: 'Are you sure you want to disconnect Cloudflare? This will completely remove your Cloudflare API Token and Zone ID from the website database.',
      confirmLabel: 'Disconnect Cloudflare',
      variant: 'danger',
      onConfirm: async () => {
        try {
          setDisconnectingCf(true);
          const res = await apiRequest({
            path: '/cloudflare/disconnect',
            method: 'POST'
          });
          if (res && res.success) {
            setCfToken('');
            setCfZoneId('');
            setCfStatus(null);
            setCfVerifyResult(null);
            loadCloudflareData();
            toast.success('Cloudflare disconnected successfully.');
          } else {
            toast.error(res?.message || 'Failed to disconnect Cloudflare.');
          }
        } catch (err: any) {
          toast.error('Error disconnecting: ' + (err?.message || 'Network error'));
        } finally {
          setDisconnectingCf(false);
        }
      },
    });
  };

  // Load models catalog
  const loadModelsCatalog = async () => {
    try {
      const res = await apiRequest({ path: '/ai/models', method: 'GET' });
      if (res && res.catalog) {
        setModelCatalog(res.catalog);
      }
    } catch (err) {
      console.warn('Failed to fetch AI models catalog', err);
    }
  };

  // Load current settings from backend
  const loadSettings = async () => {
    try {
      setLoading(true);
      const res = await apiRequest({ path: '/settings', method: 'GET' });
      if (res && res.settings) {
        if (typeof res.is_temporary_support === 'boolean') {
          setIsTemporarySupport(res.is_temporary_support);
        }
        const loadedSettings = {
          ...res.settings,
          ai_connect_status: res.ai_connect_status,
        };
        setSettings(loadedSettings);
        setInitialSettingsSnapshot(JSON.stringify(loadedSettings));
        setNextScheduled(res.next_scheduled || null);
        if (res.schedule_time) {
          setScheduleTimeInfo(res.schedule_time);
          if (typeof res.schedule_time.diff_seconds === 'number') {
            setCountdownSeconds(res.schedule_time.diff_seconds);
          }
        }
      }
    } catch (err: any) {
      console.error('Failed to load settings', err);
      setSaveError(err?.message || 'Could not load settings from server.');
    } finally {
      setLoading(false);
    }
  };

  // Load hardening and HTTP headers audit
  const loadHardeningAudit = async () => {
    try {
      setLoadingAudit(true);
      const res = await apiRequest({ path: '/hardening/audit', method: 'GET' });
      if (res && res.audit) {
        setHardeningAudit(res.audit);
      }
    } catch (err) {
      console.warn('Failed to load hardening audit', err);
    } finally {
      setLoadingAudit(false);
    }
  };

  // Apply Recommended A+ Hardening Preset
  const handleApplyHardeningPreset = async () => {
    try {
      setApplyingPreset(true);
      const res = await apiRequest({ path: '/hardening/apply-preset', method: 'POST' });
      if (res && res.success) {
        if (res.settings) {
          setSettings(res.settings);
        }
        if (res.audit) {
          setHardeningAudit(res.audit);
        }
        setSaveSuccess('Recommended A+ Security Hardening & Headers preset applied successfully!');
        toast.success('Recommended A+ Security Hardening & Headers preset applied successfully!');
        setTimeout(() => setSaveSuccess(null), 4000);
      }
    } catch (err: any) {
      toast.error('Failed to apply preset: ' + (err?.message || 'Unknown error'));
    } finally {
      setApplyingPreset(false);
    }
  };

  useEffect(() => {
    loadSettings();
    loadModelsCatalog();
    loadHardeningAudit();
    loadCloudflareData();
  }, []);

  useEffect(() => {
    if (activeSubTab === 'cloudflare') {
      loadCloudflareData();
    }
  }, [activeSubTab]);

  // Live countdown timer ticking every second
  useEffect(() => {
    if (countdownSeconds === null || countdownSeconds <= 0) return;
    const timer = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return;
      setCountdownSeconds((prev) => (prev !== null && prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(timer);
  }, [countdownSeconds]);

  // Format seconds into "X hours, Y min and Zs"
  const formatCountdown = (totalSec: number | null): string => {
    if (totalSec === null) return 'Calculating...';
    if (totalSec <= 0) return 'Executing momentarily...';

    const days = Math.floor(totalSec / 86400);
    const hours = Math.floor((totalSec % 86400) / 3600);
    const minutes = Math.floor((totalSec % 3600) / 60);
    const seconds = totalSec % 60;

    const parts: string[] = [];
    if (days > 0) parts.push(`${days} day${days > 1 ? 's' : ''}`);
    if (hours > 0) parts.push(`${hours} hour${hours > 1 ? 's' : ''}`);
    if (minutes > 0) parts.push(`${minutes} min`);
    parts.push(`${seconds}s`);

    return parts.join(' and ') + ' later from now';
  };

  // Check and auto-update AI agent version
  const handleUpdateAiModels = async () => {
    try {
      setUpdatingModels(true);
      setModelUpdateMsg(null);
      const res = await apiRequest({
        path: '/ai/models/update',
        method: 'POST',
        data: { auto_upgrade: true },
      });

      if (res && res.success) {
        if (res.catalog) {
          setModelCatalog(res.catalog);
        }
        if (res.settings) {
          setSettings(res.settings);
        }
        const discoveredItems = res.discovered ? Object.entries(res.discovered).map(([k, v]) => `${k.toUpperCase()}: ${v}`).join(', ') : '';
        const msg = discoveredItems 
          ? `Discovered and updated to latest releases (${discoveredItems})!`
          : (res.message || 'AI agent catalog checked and synchronized with latest available releases.');
        setModelUpdateMsg({ success: true, text: msg });
        setSaveSuccess('AI models verified and synchronized with latest releases.');
        setTimeout(() => setSaveSuccess(null), 4000);
      } else {
        setModelUpdateMsg({ success: false, text: res?.error || 'Could not check for model updates.' });
      }
    } catch (err: any) {
      console.error('Failed to update AI models', err);
      setModelUpdateMsg({ success: false, text: err?.message || 'Failed to check online AI model updates.' });
    } finally {
      setUpdatingModels(false);
    }
  };

  const handleSave = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!settings) return;

    if (isTemporarySupport) {
      setSaveError('Access Restricted: Temporary Support technicians have read-only access to plugin settings under Zero-Trust policies.');
      return;
    }

    try {
      setSaving(true);
      setSaveSuccess(null);
      setSaveError(null);

      const res = await apiRequest({
        path: '/settings',
        method: 'POST',
        data: settings,
      });

      if (res && res.success) {
        setShowKey({});
        const savedSettings = {
          ...res.settings,
          ai_connect_status: res.ai_connect_status || settings.ai_connect_status,
        };
        setSettings(savedSettings);
        setInitialSettingsSnapshot(JSON.stringify(savedSettings));
        setNextScheduled(res.next_scheduled || null);
        if (res.schedule_time) {
          setScheduleTimeInfo(res.schedule_time);
          if (typeof res.schedule_time.diff_seconds === 'number') {
            setCountdownSeconds(res.schedule_time.diff_seconds);
          }
        }
        setSaveSuccess(res.message || 'Settings saved successfully.');
        setTimeout(() => setSaveSuccess(null), 4000);
      }
    } catch (err: any) {
      console.error('Failed to save settings', err);
      setSaveError(err?.message || 'Failed to save settings.');
    } finally {
      setSaving(false);
    }
  };

  const handleTestAi = async () => {
    if (!settings) return;
    try {
      setTestingAi(true);
      setAiTestResult(null);

      const provider = settings.ai_provider;
      let apiKey = '';
      let model = '';

      if (provider === 'gemini') {
        apiKey = settings.gemini_api_key || '';
        model = settings.gemini_model || 'gemini-3.8-flash';
      } else if (provider === 'claude') {
        apiKey = settings.claude_api_key || '';
        model = settings.claude_model || 'claude-sonnet-5-5';
      } else if (provider === 'deepseek') {
        apiKey = settings.deepseek_api_key || '';
        model = settings.deepseek_model || 'deepseek-chat';
      } else if (provider === 'openrouter') {
        apiKey = settings.openrouter_api_key || '';
        model = settings.openrouter_model || 'auto';
      } else if (provider === 'wp_ai_connect') {
        apiKey = '';
        model = settings.ai_connect_status?.engine_slug || 'wp_native_ai';
      } else {
        apiKey = settings.openai_api_key || '';
        model = settings.openai_model || 'gpt-6.1-sol';
      }

      const res = await apiRequest({
        path: '/ai/test',
        method: 'POST',
        data: {
          provider,
          api_key: apiKey,
          model,
        },
      });

      if (res && res.success) {
        setAiTestResult({ success: true, message: res.message || 'AI Connection verified successfully!' });
      } else {
        setAiTestResult({ success: false, error: res?.error || 'Test ping failed.' });
      }
    } catch (err: any) {
      setAiTestResult({ success: false, error: err?.message || 'Connection test failed.' });
    } finally {
      setTestingAi(false);
    }
  };

  const handleExport = async () => {
    try {
      const res = await apiRequest({ path: '/settings/export', method: 'GET' });
      if (res && res.export) {
        const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(res.export, null, 2));
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute('href', dataStr);
        downloadAnchor.setAttribute('download', `webcare-security-settings-${new Date().toISOString().slice(0, 10)}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
        toast.success('Settings configuration exported successfully.');
      }
    } catch (err: any) {
      toast.error('Export failed: ' + (err?.message || 'Error'));
    }
  };

  const handleImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (isTemporarySupport) {
      toast.warning('Access Restricted: Temporary Support technicians are not permitted to import settings.');
      return;
    }

    const file = e.target.files?.[0];
    if (!file) return;

    try {
      setImporting(true);
      setImportStatus(null);
      const reader = new FileReader();
      reader.onload = async (event) => {
        try {
          const json = JSON.parse(event.target?.result as string);
          const res = await apiRequest({
            path: '/settings/import',
            method: 'POST',
            data: json,
          });
          if (res && res.success) {
            setShowKey({});
            setSettings(res.settings);
            setImportStatus('Settings imported successfully!');
            toast.success('Settings imported successfully!');
            setTimeout(() => setImportStatus(null), 4000);
          }
        } catch (parseErr: any) {
          toast.error('Import failed: ' + (parseErr?.message || 'Invalid JSON'));
        } finally {
          setImporting(false);
        }
      };
      reader.readAsText(file);
    } catch (err: any) {
      setImporting(false);
      toast.error('Import failed: ' + (err?.message || 'Error'));
    }
  };

  const handleResetDefaults = () => {
    if (isTemporarySupport) {
      toast.warning('Access Restricted: Temporary Support technicians are not permitted to reset plugin defaults.');
      return;
    }
    setResetConfirmText('');
    setResetModalOpen(true);
  };

  const handleConfirmReset = async () => {
    if (isTemporarySupport) {
      toast.warning('Access Restricted: Temporary Support technicians are not permitted to reset plugin defaults.');
      return;
    }
    if (resetConfirmText.trim().toLowerCase() !== 'reset') {
      return;
    }

    try {
      setResetting(true);
      const res = await apiRequest({ path: '/settings/reset', method: 'POST' });
      if (res && res.success) {
        setShowKey({});
        setSettings(res.settings);
        setResetModalOpen(false);
        setResetConfirmText('');
        setSaveSuccess('All plugin settings have been successfully reset to factory defaults.');
        toast.success('All plugin settings have been successfully reset to factory defaults.');
        setTimeout(() => setSaveSuccess(null), 5000);
      }
    } catch (err: any) {
      toast.error('Reset failed: ' + (err?.message || 'Error'));
    } finally {
      setResetting(false);
    }
  };

  const [triggeringCron, setTriggeringCron] = useState<boolean>(false);
  const [cronTriggerNotice, setCronTriggerNotice] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const handleTriggerCronNow = async () => {
    try {
      setTriggeringCron(true);
      setCronTriggerNotice(null);
      const res: any = await apiRequest({
        path: '/settings/trigger-cron',
        method: 'POST',
      });
      if (res?.success) {
        setCronTriggerNotice({
          type: 'success',
          message: 'Scheduled security scan triggered successfully! Check Dashboard & Scanner to observe progress.',
        });
        await loadSettings();
      } else {
        setCronTriggerNotice({
          type: 'error',
          message: res?.message || 'Could not trigger scheduled scan.',
        });
      }
    } catch (err: any) {
      setCronTriggerNotice({
        type: 'error',
        message: err?.message || 'Failed to trigger scan.',
      });
    } finally {
      setTriggeringCron(false);
      setTimeout(() => setCronTriggerNotice(null), 8000);
    }
  };

  if (loading) {
    return (
      <div className="webcare-page-container" style={{ padding: '60px 20px', textAlign: 'center', color: '#64748b' }}>
        <Loader2 size={36} className="webcare-spin-icon" style={{ margin: '0 auto 16px auto', color: '#0284c7' }} />
        <h3 style={{ fontSize: '18px', color: 'var(--webcare-text-primary, #1e293b)', margin: 0 }}>Loading Security Scanner Settings...</h3>
      </div>
    );
  }

  if (!settings) return null;

  return (
    <div className="webcare-page-container webcare-settings-page" style={{ width: '100%', maxWidth: '100%', margin: '0' }}>
      {/* Settings Top Header */}
      <div className="webcare-page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px', marginBottom: '24px' }}>
        <div>
          {onNavigateToDashboard && (
            <button
              type="button"
              className="webcare-btn"
              style={{ background: 'var(--webcare-bg-surface, #f8fafc)', color: '#64748b', fontSize: '12px', padding: '4px 10px', border: '1px solid var(--webcare-border, #e2e8f0)', borderRadius: '6px', marginBottom: '8px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
              onClick={onNavigateToDashboard}
            >
              ← Back to Scanner Dashboard
            </button>
          )}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{ background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)', color: '#ffffff', padding: '10px', borderRadius: '12px', display: 'flex', boxShadow: '0 2px 6px rgba(2, 132, 199, 0.25)' }}>
              <Settings size={24} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <h1 className="webcare-settings-title" style={{ margin: 0, fontSize: '22px', fontWeight: 700 }}>Scanner Settings &amp; Automation</h1>
                <span className={`webcare-settings-status-badge ${settings.schedule_enabled ? 'is-active' : 'is-inactive'}`} style={{
                  fontSize: '11px',
                  fontWeight: 600,
                  padding: '3px 8px',
                  borderRadius: '12px',
                }}>
                  {settings.schedule_enabled ? '● Automated Scans Active' : '○ Scans Manual'}
                </span>
                <span
                  onClick={() => handleTabChange('cleanup')}
                  className={`webcare-settings-status-badge ${settings.delete_data_on_uninstall ? 'is-warning' : 'is-inactive'}`}
                  style={{
                    fontSize: '11px',
                    fontWeight: 600,
                    padding: '3px 8px',
                    borderRadius: '12px',
                    cursor: 'pointer',
                  }}
                  title="Click to manage plugin uninstall data retention"
                >
                  <Trash2 size={11} style={{ display: 'inline', marginRight: '4px', verticalAlign: '-1px' }} />
                  Uninstall: {settings.delete_data_on_uninstall ? 'Auto-Purge' : 'Retain Data'}
                </span>
              </div>
              <p className="webcare-settings-subtitle" style={{ margin: '4px 0 0 0', fontSize: '13px' }}>
                Configure automated background scans, email alert thresholds, DevSecOps webhooks, AI threat forensics, and developer options.
              </p>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="webcare-btn"
            style={{
              background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
              color: '#ffffff',
              fontSize: '13px',
              padding: '8px 16px',
              borderRadius: '8px',
              border: 'none',
              fontWeight: 600,
              boxShadow: '0 2px 8px rgba(2, 132, 199, 0.35)',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              cursor: 'pointer'
            }}
            onClick={() => {
              if (onNavigateToActivityLogs) {
                onNavigateToActivityLogs();
              } else {
                window.location.href = 'admin.php?page=webcare-pro-logs&tab=activity';
              }
            }}
            title="Open Cryptographic Activity & Audit Log Stream"
          >
            <Activity size={14} />
            <span>Plugin Activity &amp; Audit Logs</span>
            <span style={{ fontSize: '10px', padding: '1px 6px', borderRadius: '10px', background: 'rgba(255, 255, 255, 0.22)', fontWeight: 800 }}>
              FORENSIC
            </span>
            <span style={{ fontSize: '12px' }}>→</span>
          </button>
          <button
            type="button"
            className="webcare-btn"
            style={{
              background: 'linear-gradient(135deg, #4f46e5 0%, #4338ca 100%)',
              color: '#ffffff',
              fontSize: '13px',
              padding: '8px 16px',
              borderRadius: '8px',
              border: 'none',
              fontWeight: 600,
              boxShadow: '0 2px 8px rgba(79, 70, 229, 0.35)',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              cursor: 'pointer'
            }}
            onClick={() => {
              if (onNavigateToNotifications) {
                onNavigateToNotifications();
              } else {
                window.location.href = 'admin.php?page=webcare-pro-settings&tab=alerts';
              }
            }}
            title="Open Dedicated 60+ Event Notification Center"
          >
            <MessageSquare size={14} />
            <span>Notification Center</span>
            <span style={{ fontSize: '10px', padding: '1px 6px', borderRadius: '10px', background: 'rgba(255, 255, 255, 0.22)', fontWeight: 800 }}>
              60+ EVENTS
            </span>
            <span style={{ fontSize: '12px' }}>→</span>
          </button>
          {isTemporarySupport ? (
            <button
              type="button"
              className="webcare-btn"
              disabled
              title="Temporary support accounts cannot reset plugin defaults."
              style={{ fontSize: '13px', borderRadius: '8px', opacity: 0.6, cursor: 'not-allowed', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Lock size={14} /> Reset Defaults (Locked)
            </button>
          ) : (
            <button
              type="button"
              className="webcare-btn webcare-settings-reset-defaults-btn"
              style={{ fontSize: '13px', borderRadius: '8px' }}
              onClick={handleResetDefaults}
            >
              <RotateCcw size={14} /> Reset Defaults
            </button>
          )}
          <button
            type="button"
            className="webcare-btn webcare-btn-primary"
            style={{
              background: isTemporarySupport ? '#64748b' : '#0284c7',
              color: '#fff',
              fontSize: '13px',
              padding: '9px 22px',
              borderRadius: '8px',
              boxShadow: isTemporarySupport ? 'none' : '0 2px 4px rgba(2, 132, 199, 0.2)',
              cursor: (saving || isTemporarySupport) ? 'not-allowed' : 'pointer',
              opacity: isTemporarySupport ? 0.7 : 1
            }}
            onClick={() => handleSave()}
            disabled={saving || isTemporarySupport}
            title={isTemporarySupport ? 'Settings modification is locked for temporary support accounts.' : undefined}
          >
            {saving ? <Loader2 size={15} className="webcare-spin-icon" /> : isTemporarySupport ? <Lock size={15} /> : <Save size={15} />}
            {saving ? 'Saving Changes...' : isTemporarySupport ? 'Settings Locked (Read Only)' : 'Save Settings'}
          </button>
        </div>
      </div>

      {/* Zero-Trust Support Notice */}
      {isTemporarySupport && (
        <div style={{ padding: '14px 18px', background: 'rgba(2, 132, 199, 0.08)', color: '#0284c7', border: '1px solid rgba(2, 132, 199, 0.25)', borderRadius: '10px', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <ShieldAlert size={20} />
          <div style={{ flex: 1, fontSize: '13px', lineHeight: 1.5 }}>
            <strong style={{ display: 'block', fontSize: '14px', marginBottom: '2px', color: '#0369a1' }}>Zero-Trust Temporary Support Session Active</strong>
            You are authenticated via an auto-expiring magic login session. To safeguard the host environment, settings changes, factory resets, core options modification, and credentials export are locked in read-only mode.
          </div>
        </div>
      )}

      {/* Save Alerts */}
      {saveSuccess && (
        <div style={{ padding: '12px 18px', background: '#ecfdf5', color: '#065f46', border: '1px solid #a7f3d0', borderRadius: '8px', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <CheckCircle2 size={18} color="#10b981" />
          <span style={{ fontSize: '14px', fontWeight: 500 }}>{saveSuccess}</span>
        </div>
      )}

      {saveError && (
        <div style={{ padding: '12px 18px', background: '#fef2f2', color: '#991b1b', border: '1px solid #fecaca', borderRadius: '8px', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <AlertTriangle size={18} color="#ef4444" />
          <span style={{ fontSize: '14px', fontWeight: 500 }}>{saveError}</span>
        </div>
      )}

      {/* =========================================================================
          REBUILT MODERN CATEGORIZED SETTINGS NAVIGATION (3-PILLAR COMMAND HUB)
          ========================================================================= */}
      <div className="webcare-settings-hub-card">
        {/* 3 Group Columns Grid */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(310px, 1fr))',
          gap: '16px',
          marginBottom: '14px'
        }}>
          {(() => {
            const ownerEssentialTabIds: SettingsSubTab[] = [
              'troubleshooter',
              'email',
              'alerts',
              'schedule',
              'cron',
              'cloudflare',
              'cleanup',
              'support',
            ];

            const categoriesToRender = SETTINGS_CATEGORIES.map(cat => {
              if (!isSimpleMode) return cat;
              return {
                ...cat,
                tabs: cat.tabs.filter(t => ownerEssentialTabIds.includes(t.id)),
              };
            }).filter(cat => cat.tabs.length > 0);

            return categoriesToRender.map((cat) => {
              const hasActive = cat.tabs.some((t) => t.id === activeSubTab);
              return (
              <div
                key={cat.id}
                className={`webcare-settings-cat-col ${hasActive ? 'active-col' : ''}`}
              >
                {/* Category Header */}
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  paddingBottom: '8px',
                  borderBottom: '1px solid var(--webcare-border)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div style={{
                      width: '8px',
                      height: '8px',
                      borderRadius: '50%',
                      background: hasActive ? cat.accent : '#94a3b8',
                      boxShadow: hasActive ? `0 0 8px ${cat.accent}` : 'none',
                    }} />
                    <span
                      className="webcare-settings-cat-title"
                      style={{
                        fontSize: '11px',
                        fontWeight: 700,
                        letterSpacing: '0.6px',
                        textTransform: 'uppercase',
                        color: hasActive ? cat.accent : 'inherit',
                      }}
                    >
                      {cat.name}
                    </span>
                  </div>
                  <span
                    className="webcare-settings-cat-count"
                    style={{
                      fontSize: '10px',
                      fontWeight: 600,
                      padding: '2px 7px',
                      borderRadius: '10px',
                      background: 'var(--webcare-surface-elevated)',
                      color: hasActive ? cat.accent : 'var(--webcare-text-muted)',
                    }}
                  >
                    {cat.tabs.length} tabs
                  </span>
                </div>

                {/* Tab Items in Category */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {cat.tabs.map((tab) => {
                    const Icon = tab.icon;
                    const isActive = activeSubTab === tab.id;
                    const badge = tab.getBadge(settings, hardeningAudit, cfStatus);
                    return (
                      <button
                        key={tab.id}
                        type="button"
                        className={`webcare-settings-subtab-btn ${isActive ? 'active' : ''}`}
                        onClick={() => handleTabChange(tab.id)}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0, flex: 1 }}>
                          <div
                            className={`webcare-settings-icon-wrap ${isActive ? 'active' : ''}`}
                            style={{
                              width: '28px',
                              height: '28px',
                              borderRadius: '6px',
                              background: isActive ? cat.accent : (hasActive ? '#ffffff' : '#f1f5f9'),
                              color: isActive ? '#ffffff' : (hasActive ? cat.accent : '#64748b'),
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              flexShrink: 0,
                              transition: 'all 0.15s ease',
                            }}
                          >
                            <Icon size={14} color={isActive ? '#ffffff' : (hasActive ? cat.accent : '#64748b')} />
                          </div>
                          <div style={{ minWidth: 0, flex: 1 }}>
                            <div
                              className={`webcare-settings-subtab-title ${isActive ? 'active' : ''}`}
                              style={{
                                fontSize: '13px',
                                fontWeight: isActive ? 700 : 500,
                                color: isActive ? 'var(--webcare-text-title, #0f172a)' : 'var(--webcare-text-secondary, #475569)',
                                whiteSpace: 'nowrap',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '6px'
                              }}
                            >
                              <span>{tab.label}</span>
                              {(tab as any).isNew && (
                                <span style={{
                                  fontSize: '9px',
                                  fontWeight: 700,
                                  padding: '1px 5px',
                                  borderRadius: '4px',
                                  background: 'linear-gradient(135deg, #06b6d4, #3b82f6)',
                                  color: '#ffffff',
                                  letterSpacing: '0.4px',
                                  textTransform: 'uppercase'
                                }}>
                                  MCP
                                </span>
                              )}
                            </div>
                            <div
                              className={`webcare-settings-subtab-desc ${isActive ? 'active' : ''}`}
                              style={{
                                fontSize: '11px',
                                color: isActive ? '#64748b' : '#94a3b8',
                                whiteSpace: 'nowrap',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                marginTop: '1px'
                              }}
                            >
                              {tab.shortDesc}
                            </div>
                          </div>
                        </div>

                        {/* Status Badge */}
                        {badge && (
                          <span
                            className="webcare-settings-subtab-badge"
                            style={{
                              fontSize: '10px',
                              fontWeight: 600,
                              padding: '2px 7px',
                              borderRadius: '6px',
                              background: badge.bg,
                              color: badge.color,
                              flexShrink: 0,
                              lineHeight: '14px',
                              border: `1px solid ${badge.color}22`
                            }}
                          >
                            {badge.text}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>
            );
            });
          })()}
        </div>

        {/* Bottom Breadcrumb & Direct Query Toolbar */}
        <div
          className="webcare-card-elevated"
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '12px',
            padding: '10px 14px',
            fontSize: '12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            <span style={{ fontWeight: 600 }}>Active Module:</span>
            <span className="webcare-badge-neutral">
              {SETTINGS_CATEGORIES.find(c => c.tabs.some(t => t.id === activeSubTab))?.name}
            </span>
            <span style={{ opacity: 0.5 }}>›</span>
            <span style={{ fontWeight: 600 }}>
              {SETTINGS_CATEGORIES.flatMap(c => c.tabs).find(t => t.id === activeSubTab)?.label}
            </span>
            <span style={{ opacity: 0.5 }}>&bull;</span>
            <span style={{ opacity: 0.75 }}>
              {SETTINGS_CATEGORIES.flatMap(c => c.tabs).find(t => t.id === activeSubTab)?.shortDesc}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {isSimpleMode && (
              <button
                type="button"
                onClick={() => {
                  setMode('developer');
                  toast.info('Switched to Developer Mode.');
                }}
                className="webcare-btn-micro"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '5px',
                  padding: '5px 12px',
                  fontSize: '11.5px',
                  background: 'var(--webcare-surface, #ffffff)',
                  color: 'var(--webcare-primary, #6366f1)',
                  border: '1px solid var(--webcare-primary, #6366f1)',
                  borderRadius: '6px',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                + Show 8 Pro Tabs
              </button>
            )}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '4px 10px',
                background: 'var(--webcare-surface)',
                border: '1px solid var(--webcare-border)',
                borderRadius: '6px',
                fontFamily: 'monospace',
                fontSize: '11px',
              }}
            >
              <span style={{ opacity: 0.6 }}>Query:</span>
              <span style={{ color: '#6366f1', fontWeight: 600 }}>?tab={activeSubTab}</span>
            </div>
            <button
              type="button"
              onClick={() => {
                if (onNavigateToCronManager) {
                  onNavigateToCronManager();
                } else {
                  window.location.href = 'admin.php?page=webcare-pro-settings&tab=cron';
                }
              }}
              title="Open Centralized Cron & Scheduled Tasks Control Center"
              className="webcare-btn"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
                padding: '5px 12px',
                fontSize: '11.5px',
                background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              <Clock size={12} />
              <span>Cron Manager</span>
              <span style={{ fontSize: '9px', padding: '1px 5px', borderRadius: '4px', background: 'rgba(255, 255, 255, 0.25)', fontWeight: 800 }}>
                15 TASKS
              </span>
              <span>→</span>
            </button>
            <button
              type="button"
              onClick={() => {
                if (onNavigateToActivityLogs) {
                  onNavigateToActivityLogs();
                } else {
                  window.location.href = 'admin.php?page=webcare-pro-logs&tab=activity';
                }
              }}
              title="Open Plugin Activity & Audit Logs"
              className="webcare-btn"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
                padding: '5px 12px',
                fontSize: '11.5px',
                background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              <Activity size={12} />
              <span>Activity Logs</span>
              <span style={{ fontSize: '9px', padding: '1px 5px', borderRadius: '4px', background: 'rgba(255, 255, 255, 0.25)', fontWeight: 800 }}>
                FORENSIC
              </span>
              <span>→</span>
            </button>
            <button
              type="button"
              onClick={() => {
                if (onNavigateToNotifications) {
                  onNavigateToNotifications();
                } else {
                  window.location.href = 'admin.php?page=webcare-pro-settings&tab=alerts';
                }
              }}
              title="Open Dedicated 60+ Event Notification Center"
              className="webcare-btn"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
                padding: '5px 12px',
                fontSize: '11.5px',
                background: 'linear-gradient(135deg, #4f46e5 0%, #4338ca 100%)',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              <MessageSquare size={12} />
              <span>Notification Center</span>
              <span style={{ fontSize: '9px', padding: '1px 5px', borderRadius: '4px', background: 'rgba(255, 255, 255, 0.25)', fontWeight: 800 }}>
                60+ EVENTS
              </span>
              <span>→</span>
            </button>
            <button
              type="button"
              onClick={handleCopyDirectLink}
              title="Copy direct shareable URL with query parameter"
              className={copiedQuery ? 'webcare-badge-clean' : 'webcare-btn-secondary'}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
                padding: '5px 12px',
                fontSize: '11.5px',
                cursor: 'pointer',
              }}
            >
              {copiedQuery ? <Check size={12} /> : <Copy size={12} />}
              <span>{copiedQuery ? 'URL Copied!' : 'Copy Direct Link'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* =========================================================================
          TAB 0: EMERGENCY INCIDENT CONTAINMENT PROTOCOL
          ========================================================================= */}
      {/* =========================================================================
          TAB 0: DOCTOR & RESCUE CENTER
          ========================================================================= */}
      {activeSubTab === 'troubleshooter' && (
        <>
          <DoctorRescueCenter apiRequest={apiRequest} />
          <PluginConflictCheckerCard apiRequest={apiRequest} />
        </>
      )}

      {/* =========================================================================
          TAB 0B: EMERGENCY CONTAINMENT
          ========================================================================= */}
      {activeSubTab === 'containment' && (
        <EmergencyContainmentCard apiRequest={apiRequest} />
      )}

      {/* =========================================================================
          TAB 1: SCHEDULE SCAN OPTIONS
          ========================================================================= */}
      {activeSubTab === 'schedule' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: '24px' }}>
          <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '14px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px' }}>
              <div style={{ background: '#eff6ff', color: '#2563eb', padding: '10px', borderRadius: '10px', display: 'flex' }}>
                <Clock size={22} />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>Automated Scheduled Scanning</h3>
                <p style={{ margin: 0, fontSize: '13px', color: '#64748b' }}>Run recurring security audits in the background via WordPress Cron</p>
              </div>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <ToggleSwitch
                checked={settings.schedule_enabled}
                onChange={(val) => setSettings({ ...settings, schedule_enabled: val })}
                label="Enable Background Scheduled Scans"
                description="When enabled, the scanner executes automatically at your configured frequency without requiring manual admin interaction."
                badge={settings.schedule_enabled ? (
                  <span style={{ fontSize: '11px', background: '#ecfdf5', color: '#059669', padding: '2px 8px', borderRadius: '10px', fontWeight: 600 }}>Active</span>
                ) : (
                  <span style={{ fontSize: '11px', background: '#f1f5f9', color: '#64748b', padding: '2px 8px', borderRadius: '10px', fontWeight: 500 }}>Disabled</span>
                )}
              />
            </div>

            {settings.schedule_enabled && (
              <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '20px', borderRadius: '10px', border: '1px solid var(--webcare-border, #e2e8f0)', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
                    Scan Frequency
                  </label>
                  <select
                    value={settings.schedule_frequency}
                    onChange={(e) => setSettings({ ...settings, schedule_frequency: e.target.value })}
                    style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px', background: 'var(--webcare-bg-card, #ffffff)' }}
                  >
                    <option value="hourly">Hourly (Intensive Security Watch)</option>
                    <option value="twicedaily">Twice Daily (Every 12 hours)</option>
                    <option value="daily">Daily (Recommended for Most Sites)</option>
                    <option value="weekly">Once Weekly</option>
                  </select>
                </div>

                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <label style={{ fontSize: '13px', fontWeight: 600, color: '#334155' }}>
                      Scheduled Execution Time ({scheduleTimeInfo?.timezone || 'WordPress Time'})
                    </label>
                    <span style={{ fontSize: '12px', color: '#64748b' }}>
                      Now: <strong>{scheduleTimeInfo?.current_wp_time?.split(' ')[1] || 'Current Time'}</strong>
                    </span>
                  </div>
                  <input
                    type="time"
                    value={settings.schedule_time}
                    onChange={(e) => setSettings({ ...settings, schedule_time: e.target.value })}
                    style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px', background: 'var(--webcare-bg-card, #ffffff)' }}
                  />
                  <span style={{ fontSize: '12px', color: '#64748b', marginTop: '4px', display: 'block', lineHeight: 1.45 }}>
                    {settings.schedule_frequency === 'hourly'
                      ? `Anchored execution minute: Runs each hour at :${settings.schedule_time ? settings.schedule_time.split(':')[1] || '00' : '00'} past the hour (e.g. at ${settings.schedule_time || '01:10'}, the next run starts at the upcoming ${settings.schedule_time.split(':')[1] || '10'} min mark).`
                      : settings.schedule_frequency === 'twicedaily'
                      ? `Runs every 12 hours anchored to ${settings.schedule_time || '02:00'} (in site timezone).`
                      : `Runs recurringly at ${settings.schedule_time || '02:00'} in your site's local WordPress timezone (${scheduleTimeInfo?.timezone || 'WordPress Time'}).`}
                  </span>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
                    Audit Scope
                  </label>
                  <select
                    value={settings.schedule_scan_type}
                    onChange={(e) => setSettings({ ...settings, schedule_scan_type: e.target.value })}
                    style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px', background: 'var(--webcare-bg-card, #ffffff)' }}
                  >
                    <option value="plugins_themes">Plugins & Themes (Fast, Recommended)</option>
                    <option value="full">Full WordPress Installation (Deep Full-Tree Audit)</option>
                    <option value="core_integrity">WordPress Core Integrity & Checksums Only</option>
                    <option value="suspicious_uploads">Uploads Folder Executables Only</option>
                  </select>
                </div>
              </div>
            )}
          </div>

          {/* Schedule Status & Tips */}
          <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '14px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px' }}>
              <div style={{ background: '#f0fdf4', color: '#16a34a', padding: '10px', borderRadius: '10px', display: 'flex' }}>
                <Zap size={22} />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>Cron Engine &amp; Diagnostics</h3>
                <p style={{ margin: 0, fontSize: '13px', color: '#64748b' }}>Background execution status and scheduler health</p>
              </div>
            </div>

            <div style={{
              padding: '18px 20px',
              background: settings.schedule_enabled ? '#f0fdf4' : '#f8fafc',
              border: settings.schedule_enabled ? '1px solid #bbf7d0' : '1px solid #e2e8f0',
              borderRadius: '12px',
              marginBottom: '20px'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: settings.schedule_enabled ? '#166534' : '#475569', fontWeight: 700, fontSize: '15px' }}>
                {settings.schedule_enabled ? <CheckCircle size={19} color="#16a34a" /> : <Clock size={19} color="#64748b" />}
                <span>{settings.schedule_enabled ? 'WP-Cron Scheduler Active' : 'Scheduler Engine Ready (Standby)'}</span>
              </div>

              {settings.schedule_enabled ? (
                <div style={{ marginTop: '14px' }}>
                  <div style={{
                    background: '#ffffff',
                    border: '1px solid #dcfce7',
                    borderRadius: '8px',
                    padding: '12px 14px',
                    marginBottom: '12px'
                  }}>
                    <div style={{ fontSize: '12px', fontWeight: 700, color: '#15803d', textTransform: 'uppercase', letterSpacing: '0.4px', marginBottom: '4px' }}>
                      Exact Time Until Next Scheduled Scan
                    </div>
                    <div style={{ fontSize: '15px', fontWeight: 800, color: '#14532d', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Clock size={16} color="#16a34a" />
                      <span>{formatCountdown(countdownSeconds)}</span>
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '13px', color: '#166534' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px dashed #bbf7d0', paddingBottom: '6px' }}>
                      <span style={{ color: '#15803d' }}>Next Run (WordPress Time):</span>
                      <strong style={{ color: 'var(--webcare-text-primary, #0f172a)', fontFamily: 'monospace', fontSize: '13px' }}>
                        {scheduleTimeInfo?.next_scheduled_wp || nextScheduled || 'Calculating...'}
                      </strong>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px dashed #bbf7d0', paddingBottom: '6px' }}>
                      <span style={{ color: '#15803d' }}>Next Run (GMT / UTC):</span>
                      <strong style={{ color: 'var(--webcare-text-primary, #0f172a)', fontFamily: 'monospace', fontSize: '13px' }}>
                        {scheduleTimeInfo?.next_scheduled_gmt || 'Calculating...'}
                      </strong>
                    </div>
                  </div>

                  {cronTriggerNotice && (
                    <div style={{
                      marginTop: '12px',
                      padding: '10px 12px',
                      borderRadius: '8px',
                      fontSize: '12px',
                      fontWeight: 600,
                      background: cronTriggerNotice.type === 'success' ? '#ecfdf5' : '#fef2f2',
                      color: cronTriggerNotice.type === 'success' ? '#047857' : '#b91c1c',
                      border: `1px solid ${cronTriggerNotice.type === 'success' ? '#a7f3d0' : '#fecaca'}`,
                    }}>
                      {cronTriggerNotice.message}
                    </div>
                  )}

                  <div style={{ marginTop: '14px', display: 'flex', gap: '8px' }}>
                    <button
                      type="button"
                      onClick={handleTriggerCronNow}
                      disabled={triggeringCron}
                      className="webcare-btn"
                      style={{
                        flex: 1,
                        background: '#0284c7',
                        color: '#ffffff',
                        border: 'none',
                        borderRadius: '8px',
                        padding: '9px 14px',
                        fontSize: '13px',
                        fontWeight: 700,
                        cursor: triggeringCron ? 'not-allowed' : 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '6px',
                        opacity: triggeringCron ? 0.75 : 1,
                        boxShadow: '0 1px 2px rgba(2, 132, 199, 0.2)',
                      }}
                    >
                      {triggeringCron ? (
                        <>
                          <Loader2 size={15} className="webcare-spin-icon" />
                          <span>Triggering Scheduled Scan...</span>
                        </>
                      ) : (
                        <>
                          <Zap size={15} />
                          <span>Run Scheduled Scan Now (Immediate Test)</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              ) : (
                <p style={{ margin: '8px 0 0 0', fontSize: '13px', color: '#64748b', lineHeight: 1.5 }}>
                  Automated scanning is currently paused. Activate the toggle switch on the left to start recurring background audits.
                </p>
              )}
            </div>

            <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)', borderRadius: '12px', padding: '18px', marginBottom: '20px' }}>
              <div style={{ fontSize: '12px', fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '12px' }}>
                Scheduler Clock &amp; Technical Details
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: '#64748b' }}>
                  <span>Current WordPress Time:</span>
                  <strong style={{ color: 'var(--webcare-text-primary, #0f172a)', fontFamily: 'monospace' }}>
                    {scheduleTimeInfo?.current_wp_time || 'Syncing...'}
                  </strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--webcare-text-muted, #64748b)' }}>
                  <span>Current GMT / UTC Time:</span>
                  <strong style={{ color: 'var(--webcare-text-primary, #0f172a)', fontFamily: 'monospace' }}>
                    {scheduleTimeInfo?.current_gmt_time || 'Syncing...'}
                  </strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--webcare-text-muted, #64748b)' }}>
                  <span>Active WordPress Timezone:</span>
                  <span style={{
                    background: 'var(--webcare-bg-elevated, #f1f5f9)',
                    color: 'var(--webcare-text-primary, #0f172a)',
                    border: '1px solid var(--webcare-border, #e2e8f0)',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '12px',
                    fontWeight: 600
                  }}>
                    {scheduleTimeInfo?.timezone || 'Site Timezone'}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--webcare-text-muted, #64748b)' }}>
                  <span>Cron Hook Event:</span>
                  <code style={{
                    background: 'var(--webcare-bg-elevated, #f1f5f9)',
                    color: 'var(--webcare-status-cyan, #0284c7)',
                    border: '1px solid var(--webcare-border, #e2e8f0)',
                    padding: '2px 6px',
                    borderRadius: '4px',
                    fontSize: '12px'
                  }}>webcare_scanner_scheduled_scan_event</code>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--webcare-text-muted, #64748b)' }}>
                  <span>Active Frequency:</span>
                  <strong style={{ color: 'var(--webcare-text-primary, #0f172a)', textTransform: 'capitalize' }}>
                    {settings.schedule_enabled ? settings.schedule_frequency : 'None (Manual only)'}
                  </strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--webcare-text-muted, #64748b)' }}>
                  <span>Configured Target Time:</span>
                  <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>
                    {settings.schedule_time || '00:00'} ({scheduleTimeInfo?.timezone || 'WordPress Time'})
                  </strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--webcare-text-muted, #64748b)' }}>
                  <span>WP-Cron Execution Mode:</span>
                  <span style={{
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '12px',
                    fontWeight: 600,
                    background: (scheduleTimeInfo as any)?.cron_disabled ? 'var(--webcare-status-warn-soft, #fffbeb)' : 'var(--webcare-status-clean-soft, #ecfdf5)',
                    color: (scheduleTimeInfo as any)?.cron_disabled ? 'var(--webcare-status-warn, #d97706)' : 'var(--webcare-status-clean, #047857)',
                    border: (scheduleTimeInfo as any)?.cron_disabled ? '1px solid var(--webcare-status-warn-border, #fde68a)' : '1px solid var(--webcare-status-clean-border, #a7f3d0)',
                  }}>
                    {(scheduleTimeInfo as any)?.cron_disabled ? 'Server System Cron (DISABLE_WP_CRON)' : 'Web Traffic Triggered'}
                  </span>
                </div>
                {!(scheduleTimeInfo as any)?.cron_disabled && (
                  <div style={{ marginTop: '6px', padding: '10px 12px', background: 'var(--webcare-bg-surface, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)', borderRadius: '8px', fontSize: '12px', color: '#475569', lineHeight: 1.5 }}>
                    <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>ℹ️ Web-Traffic-Triggered Notice:</strong> Standard WordPress cron triggers when visitors access the website. If nobody visits during certain hours (e.g. overnight or in staging), scans wait until the next page load. For guaranteed 24/7 background execution without visitor traffic, configure a Linux system cron or external uptime ping.
                  </div>
                )}
              </div>
            </div>

            <div style={{ fontSize: '13px', color: '#475569', lineHeight: 1.6 }}>
              <h4 style={{ margin: '0 0 10px 0', fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-primary, #1e293b)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Why schedule regular security scans?
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px' }}>
                  <Check size={16} color="#059669" style={{ marginTop: '2px', flexShrink: 0 }} />
                  <span>Detect newly injected backdoors and PHP shells immediately after compromises occur.</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px' }}>
                  <Check size={16} color="#059669" style={{ marginTop: '2px', flexShrink: 0 }} />
                  <span>Monitor unauthorized code tampering in WordPress core, plugins, and uploads trees.</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px' }}>
                  <Check size={16} color="#059669" style={{ marginTop: '2px', flexShrink: 0 }} />
                  <span>Receive instant automated notifications across Email, Slack, and Discord channels.</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB 1B: CENTRALIZED CRON MANAGER
          ========================================================================= */}
      {activeSubTab === 'cron' && (
        <div style={{ marginTop: '4px' }}>
          <CronManagerPage apiRequest={apiRequest} />
        </div>
      )}

      {/* =========================================================================
          TAB 2: EMAIL NOTIFICATIONS
          ========================================================================= */}
      {activeSubTab === 'email' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: '24px' }}>
          <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '14px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)' }}>
            
            {/* Dedicated Notification Page Deep-Link Callout */}
            <div
              style={{
                background: 'linear-gradient(135deg, rgba(79, 70, 229, 0.08) 0%, rgba(99, 102, 241, 0.04) 100%)',
                border: '1px solid rgba(79, 70, 229, 0.25)',
                borderRadius: '12px',
                padding: '16px 20px',
                marginBottom: '20px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '12px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div
                  style={{
                    width: '36px',
                    height: '36px',
                    borderRadius: '8px',
                    background: '#4f46e5',
                    color: '#ffffff',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                  }}
                >
                  <MessageSquare size={18} />
                </div>
                <div>
                  <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                    Dedicated Notification Center
                  </div>
                  <div style={{ fontSize: '12.5px', color: '#475569', marginTop: '2px' }}>
                    Configure independent Email & Webhook delivery across 60+ security events (scans, self-defense, 2FA, FIM, backups, WAF, virtual patch & forensics).
                  </div>
                </div>
              </div>
              <button
                type="button"
                onClick={() => {
                  if (onNavigateToNotifications) {
                    onNavigateToNotifications();
                  } else {
                    window.location.href = 'admin.php?page=webcare-pro-settings&tab=alerts';
                  }
                }}
                className="webcare-btn-primary"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '8px 16px',
                  fontSize: '12.5px',
                  fontWeight: 600,
                  background: '#4f46e5',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  whiteSpace: 'nowrap',
                }}
              >
                <span>Open Notification Center</span>
                <ArrowUpRight size={14} />
              </button>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px' }}>
              <div style={{ background: '#fef2f2', color: '#dc2626', padding: '10px', borderRadius: '10px', display: 'flex' }}>
                <Mail size={22} />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>Security Email Alerts</h3>
                <p style={{ margin: 0, fontSize: '13px', color: '#64748b' }}>Dispatch alerts when threats, malicious files, or CVEs are detected</p>
              </div>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <ToggleSwitch
                checked={settings.email_alerts_enabled}
                onChange={(val) => setSettings({ ...settings, email_alerts_enabled: val })}
                label="Enable Security Email Notifications"
                description="Sends automated diagnostic security alerts to administrator inboxes upon threat discovery."
                badge={settings.email_alerts_enabled ? (
                  <span style={{ fontSize: '11px', background: '#ecfdf5', color: '#059669', padding: '2px 8px', borderRadius: '10px', fontWeight: 600 }}>Active</span>
                ) : (
                  <span style={{ fontSize: '11px', background: '#f1f5f9', color: '#64748b', padding: '2px 8px', borderRadius: '10px', fontWeight: 500 }}>Disabled</span>
                )}
              />
            </div>

            {settings.email_alerts_enabled && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
                    Alert Recipient Emails (comma or new-line separated)
                  </label>
                  <textarea
                    rows={3}
                    value={settings.alert_emails}
                    onChange={(e) => setSettings({ ...settings, alert_emails: e.target.value })}
                    placeholder="security@yourdomain.com, admin@yourdomain.com"
                    style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                  />
                  <span style={{ fontSize: '12px', color: '#64748b', marginTop: '4px', display: 'block' }}>
                    Multiple recipients can be notified simultaneously.
                  </span>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
                    Minimum Severity Trigger
                  </label>
                  <select
                    value={settings.alert_min_severity}
                    onChange={(e) => setSettings({ ...settings, alert_min_severity: e.target.value })}
                    style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px', background: 'var(--webcare-bg-card, #ffffff)' }}
                  >
                    <option value="critical">Critical Only (Malware backdoors, webshells, severe exploits)</option>
                    <option value="high">High &amp; Critical (Recommended)</option>
                    <option value="medium">Medium, High &amp; Critical</option>
                    <option value="all">All Findings (Including low severity hardening notices)</option>
                  </select>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', paddingTop: '10px', borderTop: '1px solid #f1f5f9' }}>
                  <ToggleSwitch
                    checked={settings.email_on_scan_completed}
                    onChange={(val) => setSettings({ ...settings, email_on_scan_completed: val })}
                    label="Routine Scan Completion Digest"
                    description="Send email on every completed scan, even if site is completely clean."
                  />

                  <ToggleSwitch
                    checked={settings.notify_on_cve_detected}
                    onChange={(val) => setSettings({ ...settings, notify_on_cve_detected: val })}
                    label="CVE Vulnerability Advisories"
                    description="Include known software CVE vulnerability alerts for outdated plugins/themes."
                  />
                </div>

                <div style={{ paddingTop: '14px', borderTop: '1px solid #f1f5f9' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <label style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                      Max Findings in Scan Report Email (1–25)
                    </label>
                    <span style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      padding: '2px 8px',
                      borderRadius: '6px',
                      fontSize: '12px',
                      fontWeight: 700,
                      background: 'rgba(79, 70, 229, 0.1)',
                      color: '#4f46e5',
                      border: '1px solid rgba(79, 70, 229, 0.2)'
                    }}>
                      {Math.max(1, Math.min(25, Number(settings.email_report_items_limit ?? 20)))} Items Max
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                    <input
                      type="range"
                      min={1}
                      max={25}
                      step={1}
                      value={Math.max(1, Math.min(25, Number(settings.email_report_items_limit ?? 20)))}
                      onChange={(e) => setSettings({
                        ...settings,
                        email_report_items_limit: Math.max(1, Math.min(25, parseInt(e.target.value, 10) || 20))
                      })}
                      style={{ flex: 1, accentColor: '#4f46e5', cursor: 'pointer' }}
                    />
                    <input
                      type="number"
                      min={1}
                      max={25}
                      value={Math.max(1, Math.min(25, Number(settings.email_report_items_limit ?? 20)))}
                      onChange={(e) => {
                        const val = parseInt(e.target.value, 10);
                        if (!isNaN(val)) {
                          setSettings({
                            ...settings,
                            email_report_items_limit: Math.max(1, Math.min(25, val))
                          });
                        }
                      }}
                      className="webcare-input"
                      style={{
                        width: '68px',
                        padding: '6px 8px',
                        borderRadius: '6px',
                        border: '1px solid #cbd5e1',
                        fontSize: '13px',
                        textAlign: 'center',
                        fontWeight: 600
                      }}
                    />
                  </div>
                  <p style={{ margin: '6px 0 0 0', fontSize: '12px', color: '#64748b', lineHeight: 1.5 }}>
                    Controls the maximum number of threat files detailed in each email alert (1–25). Findings are automatically priority-ranked by severity (critical backdoors first) to keep emails compact and prevent delivery rejections on massive malware infections.
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* Email Preview & Best Practices */}
          <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '14px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px' }}>
              <div style={{ background: '#fef2f2', color: '#dc2626', padding: '10px', borderRadius: '10px', display: 'flex' }}>
                <ShieldAlert size={22} />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>Incident Response Digest</h3>
                <p style={{ margin: 0, fontSize: '13px', color: '#64748b' }}>Format preview and email transport guidance</p>
              </div>
            </div>

            <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '18px', borderRadius: '10px', border: '1px solid var(--webcare-border, #e2e8f0)', marginBottom: '20px' }}>
              <div style={{ fontSize: '11px', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px' }}>
                Sample Email Subject &amp; Digest
              </div>
              <div style={{ fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)', fontWeight: 700 }}>
                [🔴 SECURITY ALERT] My WordPress Site - Scan #12 Completed
              </div>
              <p style={{ fontSize: '12px', color: '#64748b', margin: '6px 0 14px 0', lineHeight: 1.5 }}>
                Contains real-time threat breakdown, risk scores, exact file locations, and direct links to the forensic code inspector modal.
              </p>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                <span style={{ background: '#ef4444', color: '#fff', fontSize: '11px', padding: '3px 9px', borderRadius: '6px', fontWeight: 700 }}>CRITICAL: 1</span>
                <span style={{ background: '#f59e0b', color: '#fff', fontSize: '11px', padding: '3px 9px', borderRadius: '6px', fontWeight: 700 }}>HIGH: 2</span>
                <span style={{ background: '#10b981', color: '#fff', fontSize: '11px', padding: '3px 9px', borderRadius: '6px', fontWeight: 700 }}>RISK SCORE: 72/100</span>
              </div>
            </div>

            <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)', borderRadius: '10px', padding: '16px', fontSize: '13px', color: '#475569', lineHeight: 1.6 }}>
              <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>Email Delivery Tip:</strong> Ensure your server's <code>wp_mail()</code> or SMTP plugin (e.g. WP Mail SMTP, FluentSMTP) is properly configured with SPF/DKIM records so security notices land reliably in your primary inbox without being filtered into spam.
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB 2B: NOTIFICATION MATRIX (ALERTS)
          ========================================================================= */}
      {activeSubTab === 'alerts' && (
        <div style={{ marginTop: '4px' }}>
          <NotificationsPage
            apiRequest={apiRequest}
            onNavigateToSettings={() => handleTabChange('webhooks')}
          />
        </div>
      )}

      {/* =========================================================================
          TAB: DEVSECOPS CHAT WEBHOOKS (SLACK & DISCORD)
          ========================================================================= */}
      {activeSubTab === 'webhooks' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {/* Test Alert Result Banner */}
          {webhookTestResult && (
            <div style={{
              padding: '14px 18px',
              borderRadius: '8px',
              fontSize: '13px',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              background: webhookTestResult.success ? '#f0fdf4' : '#fef2f2',
              color: webhookTestResult.success ? '#166534' : '#991b1b',
              border: webhookTestResult.success ? '1px solid #bbf7d0' : '1px solid #fecaca'
            }}>
              {webhookTestResult.success ? <CheckCircle2 size={18} /> : <AlertTriangle size={18} />}
              <div>
                <strong>{webhookTestResult.platform.toUpperCase()} Test:</strong> {webhookTestResult.message}
              </div>
            </div>
          )}

          {/* Slack & Discord Side-by-Side Configuration Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: '24px' }}>
            {/* 1. Slack Integration Card */}
            <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '14px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ background: '#ecfdf5', color: '#047857', padding: '10px 14px', borderRadius: '10px', fontWeight: 700, fontSize: '18px' }}>
                    #
                  </div>
                  <div>
                    <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>Slack Channel Integration</h3>
                    <p style={{ margin: 0, fontSize: '12px', color: '#64748b' }}>Incoming Webhook (Block Kit cards)</p>
                  </div>
                </div>

                <ToggleSwitch
                  checked={!!settings.slack_enabled}
                  onChange={(val) => setSettings({ ...settings, slack_enabled: val })}
                  label=""
                  badge={settings.slack_enabled ? (
                    <span style={{ fontSize: '11px', background: '#ecfdf5', color: '#059669', padding: '2px 8px', borderRadius: '10px', fontWeight: 600 }}>Active</span>
                  ) : (
                    <span style={{ fontSize: '11px', background: '#f1f5f9', color: '#64748b', padding: '2px 8px', borderRadius: '10px', fontWeight: 500 }}>Disabled</span>
                  )}
                />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <label style={{ fontSize: '13px', fontWeight: 600, color: '#334155' }}>
                      Slack Webhook URL
                    </label>
                    {settings.has_slack_webhook && (
                      <span style={{ fontSize: '11px', color: '#059669', background: '#ecfdf5', padding: '1px 6px', borderRadius: '4px', fontWeight: 600 }}>
                        ✓ Encrypted in Vault
                      </span>
                    )}
                  </div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <div style={{ position: 'relative', flex: 1 }}>
                      <input
                        type={showKey['slack'] ? 'text' : 'password'}
                        value={showKey['slack'] ? getMaskedSecret(settings.slack_webhook_url) : (settings.slack_webhook_url || '')}
                        onChange={(e) => setSettings({ ...settings, slack_webhook_url: e.target.value })}
                        readOnly={!!showKey['slack']}
                        placeholder={settings.has_slack_webhook ? '•••••••••••••••••••••••••••••••• (Encrypted in Vault)' : 'https://hooks.slack.com/services/...'}
                        style={{ width: '100%', padding: '9px 40px 9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                      />
                      <button
                        type="button"
                        onClick={() => setShowKey({ ...showKey, slack: !showKey['slack'] })}
                        title={showKey['slack'] ? 'Hide Webhook URL' : 'Show Webhook URL (Partially Masked)'}
                        style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#64748b' }}
                      >
                        {showKey['slack'] ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleSaveWebhook('slack')}
                      disabled={savingWebhook.slack}
                      className="webcare-btn webcare-btn-primary"
                      style={{ height: '38px', padding: '0 14px', fontSize: '12.5px', display: 'flex', alignItems: 'center', gap: '6px', whiteSpace: 'nowrap' }}
                      title="Save Slack Webhook"
                    >
                      {savingWebhook.slack ? (
                        <Loader2 size={13} className="webcare-spin-icon" />
                      ) : webhookSavedFeedback.slack ? (
                        <Check size={13} />
                      ) : (
                        <Save size={13} />
                      )}
                      {webhookSavedFeedback.slack ? 'Saved' : 'Save'}
                    </button>

                    {(settings.has_slack_webhook || (settings.slack_webhook_url && settings.slack_webhook_url.trim() !== '')) && (
                      <button
                        type="button"
                        onClick={() => handleRemoveWebhook('slack')}
                        disabled={savingWebhook.slack}
                        className="webcare-btn"
                        style={{
                          height: '38px',
                          padding: '0 12px',
                          fontSize: '12.5px',
                          color: '#dc2626',
                          background: 'var(--webcare-bg-surface, #fef2f2)',
                          border: '1px solid #fecaca',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '5px',
                          whiteSpace: 'nowrap'
                        }}
                        title="Remove Slack Webhook"
                      >
                        <Trash2 size={13} />
                        Remove
                      </button>
                    )}
                  </div>
                  <span style={{ fontSize: '12px', color: '#64748b', marginTop: '4px', display: 'block' }}>
                    Create via Slack App Directory &gt; Incoming WebHooks, or inside your Slack Workflow Builder.
                  </span>
                </div>

                <button
                  type="button"
                  className="webcare-btn"
                  style={{
                    background: 'var(--webcare-bg-surface, #f8fafc)',
                    color: '#334155',
                    border: '1px solid #cbd5e1',
                    fontSize: '13px',
                    width: 'fit-content',
                    cursor: testingWebhook.slack ? 'not-allowed' : 'pointer'
                  }}
                  onClick={() => handleTestWebhook('slack')}
                  disabled={testingWebhook.slack}
                >
                  {testingWebhook.slack ? <Loader2 size={14} className="webcare-spin-icon" /> : <Send size={14} />}
                  {testingWebhook.slack ? 'Sending Test Alert...' : 'Send Test Slack Notification'}
                </button>
              </div>
            </div>

            {/* 2. Discord Integration Card */}
            <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '14px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ background: '#e0e7ff', color: '#4338ca', padding: '10px 14px', borderRadius: '10px', fontWeight: 700, fontSize: '18px' }}>
                    @
                  </div>
                  <div>
                    <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>Discord Channel Integration</h3>
                    <p style={{ margin: 0, fontSize: '12px', color: '#64748b' }}>Discord Server Webhook (Rich Embeds)</p>
                  </div>
                </div>

                <ToggleSwitch
                  checked={!!settings.discord_enabled}
                  onChange={(val) => setSettings({ ...settings, discord_enabled: val })}
                  label=""
                  badge={settings.discord_enabled ? (
                    <span style={{ fontSize: '11px', background: '#ecfdf5', color: '#059669', padding: '2px 8px', borderRadius: '10px', fontWeight: 600 }}>Active</span>
                  ) : (
                    <span style={{ fontSize: '11px', background: '#f1f5f9', color: '#64748b', padding: '2px 8px', borderRadius: '10px', fontWeight: 500 }}>Disabled</span>
                  )}
                />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <label style={{ fontSize: '13px', fontWeight: 600, color: '#334155' }}>
                      Discord Webhook URL
                    </label>
                    {settings.has_discord_webhook && (
                      <span style={{ fontSize: '11px', color: '#059669', background: '#ecfdf5', padding: '1px 6px', borderRadius: '4px', fontWeight: 600 }}>
                        ✓ Encrypted in Vault
                      </span>
                    )}
                  </div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <div style={{ position: 'relative', flex: 1 }}>
                      <input
                        type={showKey['discord'] ? 'text' : 'password'}
                        value={showKey['discord'] ? getMaskedSecret(settings.discord_webhook_url) : (settings.discord_webhook_url || '')}
                        onChange={(e) => setSettings({ ...settings, discord_webhook_url: e.target.value })}
                        readOnly={!!showKey['discord']}
                        placeholder={settings.has_discord_webhook ? '•••••••••••••••••••••••••••••••• (Encrypted in Vault)' : 'https://discord.com/api/webhooks/...'}
                        style={{ width: '100%', padding: '9px 40px 9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                      />
                      <button
                        type="button"
                        onClick={() => setShowKey({ ...showKey, discord: !showKey['discord'] })}
                        title={showKey['discord'] ? 'Hide Webhook URL' : 'Show Webhook URL (Partially Masked)'}
                        style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#64748b' }}
                      >
                        {showKey['discord'] ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleSaveWebhook('discord')}
                      disabled={savingWebhook.discord}
                      className="webcare-btn webcare-btn-primary"
                      style={{ height: '38px', padding: '0 14px', fontSize: '12.5px', display: 'flex', alignItems: 'center', gap: '6px', whiteSpace: 'nowrap' }}
                      title="Save Discord Webhook"
                    >
                      {savingWebhook.discord ? (
                        <Loader2 size={13} className="webcare-spin-icon" />
                      ) : webhookSavedFeedback.discord ? (
                        <Check size={13} />
                      ) : (
                        <Save size={13} />
                      )}
                      {webhookSavedFeedback.discord ? 'Saved' : 'Save'}
                    </button>

                    {(settings.has_discord_webhook || (settings.discord_webhook_url && settings.discord_webhook_url.trim() !== '')) && (
                      <button
                        type="button"
                        onClick={() => handleRemoveWebhook('discord')}
                        disabled={savingWebhook.discord}
                        className="webcare-btn"
                        style={{
                          height: '38px',
                          padding: '0 12px',
                          fontSize: '12.5px',
                          color: '#dc2626',
                          background: 'var(--webcare-bg-surface, #fef2f2)',
                          border: '1px solid #fecaca',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '5px',
                          whiteSpace: 'nowrap'
                        }}
                        title="Remove Discord Webhook"
                      >
                        <Trash2 size={13} />
                        Remove
                      </button>
                    )}
                  </div>
                  <span style={{ fontSize: '12px', color: '#64748b', marginTop: '4px', display: 'block' }}>
                    In Discord: Server Settings &gt; Integrations &gt; Webhooks &gt; New Webhook &gt; Copy Webhook URL.
                  </span>
                </div>

                <button
                  type="button"
                  className="webcare-btn"
                  style={{
                    background: 'var(--webcare-bg-surface, #f8fafc)',
                    color: '#334155',
                    border: '1px solid #cbd5e1',
                    fontSize: '13px',
                    width: 'fit-content',
                    cursor: testingWebhook.discord ? 'not-allowed' : 'pointer'
                  }}
                  onClick={() => handleTestWebhook('discord')}
                  disabled={testingWebhook.discord}
                >
                  {testingWebhook.discord ? <Loader2 size={14} className="webcare-spin-icon" /> : <Send size={14} />}
                  {testingWebhook.discord ? 'Sending Test Alert...' : 'Send Test Discord Notification'}
                </button>
              </div>
            </div>

            {/* 3. ClickUp Integration Card */}
            <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '14px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ background: '#fdf2f8', color: '#be185d', padding: '10px 14px', borderRadius: '10px', fontWeight: 700, fontSize: '18px' }}>
                    CU
                  </div>
                  <div>
                    <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>ClickUp Integration</h3>
                    <p style={{ margin: 0, fontSize: '12px', color: '#64748b' }}>Automated DevSecOps Tasks &amp; Automations</p>
                  </div>
                </div>

                <ToggleSwitch
                  checked={!!settings.clickup_enabled}
                  onChange={(val) => setSettings({ ...settings, clickup_enabled: val })}
                  label=""
                  badge={settings.clickup_enabled ? (
                    <span style={{ fontSize: '11px', background: '#ecfdf5', color: '#059669', padding: '2px 8px', borderRadius: '10px', fontWeight: 600 }}>Active</span>
                  ) : (
                    <span style={{ fontSize: '11px', background: '#f1f5f9', color: '#64748b', padding: '2px 8px', borderRadius: '10px', fontWeight: 500 }}>Disabled</span>
                  )}
                />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <label style={{ fontSize: '13px', fontWeight: 600, color: '#334155' }}>
                      ClickUp Webhook / Automation URL
                    </label>
                    {settings.has_clickup_webhook && (
                      <span style={{ fontSize: '11px', color: '#059669', background: '#ecfdf5', padding: '1px 6px', borderRadius: '4px', fontWeight: 600 }}>
                        ✓ Encrypted in Vault
                      </span>
                    )}
                  </div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <div style={{ position: 'relative', flex: 1 }}>
                      <input
                        type={showKey['clickup'] ? 'text' : 'password'}
                        value={showKey['clickup'] ? getMaskedSecret(settings.clickup_webhook_url) : (settings.clickup_webhook_url || '')}
                        onChange={(e) => setSettings({ ...settings, clickup_webhook_url: e.target.value })}
                        readOnly={!!showKey['clickup']}
                        placeholder={settings.has_clickup_webhook ? '•••••••••••••••••••••••••••••••• (Encrypted in Vault)' : 'https://api.clickup.com/api/v2/... or Automation Webhook'}
                        style={{ width: '100%', padding: '9px 40px 9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                      />
                      <button
                        type="button"
                        onClick={() => setShowKey({ ...showKey, clickup: !showKey['clickup'] })}
                        title={showKey['clickup'] ? 'Hide Webhook URL' : 'Show Webhook URL (Partially Masked)'}
                        style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#64748b' }}
                      >
                        {showKey['clickup'] ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleSaveWebhook('clickup')}
                      disabled={savingWebhook.clickup}
                      className="webcare-btn webcare-btn-primary"
                      style={{ height: '38px', padding: '0 14px', fontSize: '12.5px', display: 'flex', alignItems: 'center', gap: '6px', whiteSpace: 'nowrap' }}
                      title="Save ClickUp Webhook"
                    >
                      {savingWebhook.clickup ? (
                        <Loader2 size={13} className="webcare-spin-icon" />
                      ) : webhookSavedFeedback.clickup ? (
                        <Check size={13} />
                      ) : (
                        <Save size={13} />
                      )}
                      {webhookSavedFeedback.clickup ? 'Saved' : 'Save'}
                    </button>

                    {(settings.has_clickup_webhook || (settings.clickup_webhook_url && settings.clickup_webhook_url.trim() !== '')) && (
                      <button
                        type="button"
                        onClick={() => handleRemoveWebhook('clickup')}
                        disabled={savingWebhook.clickup}
                        className="webcare-btn"
                        style={{
                          height: '38px',
                          padding: '0 12px',
                          fontSize: '12.5px',
                          color: '#dc2626',
                          background: 'var(--webcare-bg-surface, #fef2f2)',
                          border: '1px solid #fecaca',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '5px',
                          whiteSpace: 'nowrap'
                        }}
                        title="Remove ClickUp Webhook"
                      >
                        <Trash2 size={13} />
                        Remove
                      </button>
                    )}
                  </div>
                  <span style={{ fontSize: '12px', color: '#64748b', marginTop: '4px', display: 'block' }}>
                    Supports ClickUp Incoming Automation webhooks or direct task creation endpoints to convert threats into sprint tasks.
                  </span>
                </div>

                <button
                  type="button"
                  className="webcare-btn"
                  style={{
                    background: 'var(--webcare-bg-surface, #f8fafc)',
                    color: '#334155',
                    border: '1px solid #cbd5e1',
                    fontSize: '13px',
                    width: 'fit-content',
                    cursor: testingWebhook.clickup ? 'not-allowed' : 'pointer'
                  }}
                  onClick={() => handleTestWebhook('clickup')}
                  disabled={testingWebhook.clickup}
                >
                  {testingWebhook.clickup ? <Loader2 size={14} className="webcare-spin-icon" /> : <Send size={14} />}
                  {testingWebhook.clickup ? 'Creating Test Task...' : 'Send Test ClickUp Task'}
                </button>
              </div>
            </div>

            {/* 4. Asana Integration Card */}
            <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '14px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ background: '#fff7ed', color: '#c2410c', padding: '10px 14px', borderRadius: '10px', fontWeight: 700, fontSize: '18px' }}>
                    ::
                  </div>
                  <div>
                    <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>Asana Integration</h3>
                    <p style={{ margin: 0, fontSize: '12px', color: '#64748b' }}>Project Board Tasks &amp; Rule Automations</p>
                  </div>
                </div>

                <ToggleSwitch
                  checked={!!settings.asana_enabled}
                  onChange={(val) => setSettings({ ...settings, asana_enabled: val })}
                  label=""
                  badge={settings.asana_enabled ? (
                    <span style={{ fontSize: '11px', background: '#ecfdf5', color: '#059669', padding: '2px 8px', borderRadius: '10px', fontWeight: 600 }}>Active</span>
                  ) : (
                    <span style={{ fontSize: '11px', background: '#f1f5f9', color: '#64748b', padding: '2px 8px', borderRadius: '10px', fontWeight: 500 }}>Disabled</span>
                  )}
                />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <label style={{ fontSize: '13px', fontWeight: 600, color: '#334155' }}>
                      Asana Webhook / Rule URL
                    </label>
                    {settings.has_asana_webhook && (
                      <span style={{ fontSize: '11px', color: '#059669', background: '#ecfdf5', padding: '1px 6px', borderRadius: '4px', fontWeight: 600 }}>
                        ✓ Encrypted in Vault
                      </span>
                    )}
                  </div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <div style={{ position: 'relative', flex: 1 }}>
                      <input
                        type={showKey['asana'] ? 'text' : 'password'}
                        value={showKey['asana'] ? getMaskedSecret(settings.asana_webhook_url) : (settings.asana_webhook_url || '')}
                        onChange={(e) => setSettings({ ...settings, asana_webhook_url: e.target.value })}
                        readOnly={!!showKey['asana']}
                        placeholder={settings.has_asana_webhook ? '•••••••••••••••••••••••••••••••• (Encrypted in Vault)' : 'https://app.asana.com/api/1.0/... or Webhook URL'}
                        style={{ width: '100%', padding: '9px 40px 9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                      />
                      <button
                        type="button"
                        onClick={() => setShowKey({ ...showKey, asana: !showKey['asana'] })}
                        title={showKey['asana'] ? 'Hide Webhook URL' : 'Show Webhook URL (Partially Masked)'}
                        style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#64748b' }}
                      >
                        {showKey['asana'] ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleSaveWebhook('asana')}
                      disabled={savingWebhook.asana}
                      className="webcare-btn webcare-btn-primary"
                      style={{ height: '38px', padding: '0 14px', fontSize: '12.5px', display: 'flex', alignItems: 'center', gap: '6px', whiteSpace: 'nowrap' }}
                      title="Save Asana Webhook"
                    >
                      {savingWebhook.asana ? (
                        <Loader2 size={13} className="webcare-spin-icon" />
                      ) : webhookSavedFeedback.asana ? (
                        <Check size={13} />
                      ) : (
                        <Save size={13} />
                      )}
                      {webhookSavedFeedback.asana ? 'Saved' : 'Save'}
                    </button>

                    {(settings.has_asana_webhook || (settings.asana_webhook_url && settings.asana_webhook_url.trim() !== '')) && (
                      <button
                        type="button"
                        onClick={() => handleRemoveWebhook('asana')}
                        disabled={savingWebhook.asana}
                        className="webcare-btn"
                        style={{
                          height: '38px',
                          padding: '0 12px',
                          fontSize: '12.5px',
                          color: '#dc2626',
                          background: 'var(--webcare-bg-surface, #fef2f2)',
                          border: '1px solid #fecaca',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '5px',
                          whiteSpace: 'nowrap'
                        }}
                        title="Remove Asana Webhook"
                      >
                        <Trash2 size={13} />
                        Remove
                      </button>
                    )}
                  </div>
                  <span style={{ fontSize: '12px', color: '#64748b', marginTop: '4px', display: 'block' }}>
                    Automatically files tickets into your Asana Maintenance or DevSecOps project board upon critical detections.
                  </span>
                </div>

                <button
                  type="button"
                  className="webcare-btn"
                  style={{
                    background: 'var(--webcare-bg-surface, #f8fafc)',
                    color: '#334155',
                    border: '1px solid #cbd5e1',
                    fontSize: '13px',
                    width: 'fit-content',
                    cursor: testingWebhook.asana ? 'not-allowed' : 'pointer'
                  }}
                  onClick={() => handleTestWebhook('asana')}
                  disabled={testingWebhook.asana}
                >
                  {testingWebhook.asana ? <Loader2 size={14} className="webcare-spin-icon" /> : <Send size={14} />}
                  {testingWebhook.asana ? 'Creating Test Task...' : 'Send Test Asana Task'}
                </button>
              </div>
            </div>

            {/* 5. Generic Automations (Zapier / Make.com / n8n / Custom) */}
            <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '14px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ background: '#f5f3ff', color: '#7c3aed', padding: '10px 14px', borderRadius: '10px', fontWeight: 700, fontSize: '18px' }}>
                    ⚡
                  </div>
                  <div>
                    <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>Automation Webhook (Zapier, Make, n8n)</h3>
                    <p style={{ margin: 0, fontSize: '12px', color: '#64748b' }}>Custom REST JSON payload for enterprise pipelines</p>
                  </div>
                </div>

                <ToggleSwitch
                  checked={!!settings.generic_webhook_enabled}
                  onChange={(val) => setSettings({ ...settings, generic_webhook_enabled: val })}
                  label=""
                  badge={settings.generic_webhook_enabled ? (
                    <span style={{ fontSize: '11px', background: '#ecfdf5', color: '#059669', padding: '2px 8px', borderRadius: '10px', fontWeight: 600 }}>Active</span>
                  ) : (
                    <span style={{ fontSize: '11px', background: '#f1f5f9', color: '#64748b', padding: '2px 8px', borderRadius: '10px', fontWeight: 500 }}>Disabled</span>
                  )}
                />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <label style={{ fontSize: '13px', fontWeight: 600, color: '#334155' }}>
                      Automation Webhook URL (Zapier / Make.com / n8n / Custom endpoint)
                    </label>
                    {settings.has_generic_webhook && (
                      <span style={{ fontSize: '11px', color: '#059669', background: '#ecfdf5', padding: '1px 6px', borderRadius: '4px', fontWeight: 600 }}>
                        ✓ Encrypted in Vault
                      </span>
                    )}
                  </div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <div style={{ position: 'relative', flex: 1 }}>
                      <input
                        type={showKey['generic'] ? 'text' : 'password'}
                        value={showKey['generic'] ? getMaskedSecret(settings.generic_webhook_url) : (settings.generic_webhook_url || '')}
                        onChange={(e) => setSettings({ ...settings, generic_webhook_url: e.target.value })}
                        readOnly={!!showKey['generic']}
                        placeholder={settings.has_generic_webhook ? '•••••••••••••••••••••••••••••••• (Encrypted in Vault)' : 'https://hooks.zapier.com/hooks/catch/... or https://hook.eu1.make.com/...'}
                        style={{ width: '100%', padding: '9px 40px 9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                      />
                      <button
                        type="button"
                        onClick={() => setShowKey({ ...showKey, generic: !showKey['generic'] })}
                        title={showKey['generic'] ? 'Hide Webhook URL' : 'Show Webhook URL (Partially Masked)'}
                        style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#64748b' }}
                      >
                        {showKey['generic'] ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleSaveWebhook('generic')}
                      disabled={savingWebhook.generic}
                      className="webcare-btn webcare-btn-primary"
                      style={{ height: '38px', padding: '0 14px', fontSize: '12.5px', display: 'flex', alignItems: 'center', gap: '6px', whiteSpace: 'nowrap' }}
                      title="Save Automation Webhook"
                    >
                      {savingWebhook.generic ? (
                        <Loader2 size={13} className="webcare-spin-icon" />
                      ) : webhookSavedFeedback.generic ? (
                        <Check size={13} />
                      ) : (
                        <Save size={13} />
                      )}
                      {webhookSavedFeedback.generic ? 'Saved' : 'Save'}
                    </button>

                    {(settings.has_generic_webhook || (settings.generic_webhook_url && settings.generic_webhook_url.trim() !== '')) && (
                      <button
                        type="button"
                        onClick={() => handleRemoveWebhook('generic')}
                        disabled={savingWebhook.generic}
                        className="webcare-btn"
                        style={{
                          height: '38px',
                          padding: '0 12px',
                          fontSize: '12.5px',
                          color: '#dc2626',
                          background: 'var(--webcare-bg-surface, #fef2f2)',
                          border: '1px solid #fecaca',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '5px',
                          whiteSpace: 'nowrap'
                        }}
                        title="Remove Automation Webhook"
                      >
                        <Trash2 size={13} />
                        Remove
                      </button>
                    )}
                  </div>
                  <span style={{ fontSize: '12px', color: '#64748b', marginTop: '4px', display: 'block' }}>
                    Delivers structured JSON objects with event, site_url, risk_score, issues array, and timestamp to trigger automated workflows.
                  </span>
                </div>

                <button
                  type="button"
                  className="webcare-btn"
                  style={{
                    background: 'var(--webcare-bg-surface, #f8fafc)',
                    color: '#334155',
                    border: '1px solid #cbd5e1',
                    fontSize: '13px',
                    width: 'fit-content',
                    cursor: testingWebhook.generic ? 'not-allowed' : 'pointer'
                  }}
                  onClick={() => handleTestWebhook('generic')}
                  disabled={testingWebhook.generic}
                >
                  {testingWebhook.generic ? <Loader2 size={14} className="webcare-spin-icon" /> : <Send size={14} />}
                  {testingWebhook.generic ? 'Triggering Workflow...' : 'Send Test Automation Payload'}
                </button>
              </div>
            </div>
          </div>

          {/* 3. Event Notification Trigger Policies */}
          <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '14px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <div style={{ background: '#eff6ff', color: '#0284c7', padding: '10px', borderRadius: '10px', display: 'flex' }}>
                <Sliders size={20} />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>Automated Dispatch Triggers &amp; Policies</h3>
                <p style={{ margin: 0, fontSize: '13px', color: '#64748b' }}>Choose which security incidents automatically ping your team's chat channels</p>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <ToggleSwitch
                checked={settings.webhook_notify_on_critical !== false}
                onChange={(val) => setSettings({ ...settings, webhook_notify_on_critical: val })}
                label="Critical Threats &amp; Webshells Found"
                description="Dispatches immediate alert with malware classification, threat severity, and infected file path."
              />

              <ToggleSwitch
                checked={settings.webhook_notify_on_fim !== false}
                onChange={(val) => setSettings({ ...settings, webhook_notify_on_fim: val })}
                label="File Integrity Monitoring (FIM) Modifications"
                description="Dispatched when unauthorized WordPress core, plugin, or uploads modifications are recorded."
              />

              <ToggleSwitch
                checked={settings.webhook_notify_on_scan_finish !== false}
                onChange={(val) => setSettings({ ...settings, webhook_notify_on_scan_finish: val })}
                label="Routine Security Scan Concluded"
                description="Dispatches summary report with overall site risk score, scanned file counts, and findings total."
              />

              <ToggleSwitch
                checked={!!settings.webhook_notify_on_waf_block}
                onChange={(val) => setSettings({ ...settings, webhook_notify_on_waf_block: val })}
                label="High-Severity WAF Lite Interceptions"
                description="Notifies on blocked SQLi or XSS attacks (rate-limited to 1 alert per minute to avoid chat flood)."
              />
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB: CLOUDFLARE EDGE DEFENSE STATUS & 1-CLICK JUMP
          ========================================================================= */}
      {activeSubTab === 'cloudflare' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Compact Cloudflare Edge Status Card */}
          <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px', marginBottom: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                <div style={{
                  width: '48px',
                  height: '48px',
                  borderRadius: '12px',
                  background: 'linear-gradient(135deg, #f97316 0%, #ea580c 100%)',
                  color: '#fff',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 4px 12px rgba(234, 88, 12, 0.25)'
                }}>
                  <Cloud size={28} />
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <h3 style={{ margin: 0, fontSize: '18px', color: 'var(--webcare-text-primary, #0f172a)' }}>Cloudflare Edge Defense</h3>
                    <span style={{
                      fontSize: '11px',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      padding: '2px 8px',
                      borderRadius: '999px',
                      background: cfStatus?.configured ? '#dcfce7' : '#f1f5f9',
                      color: cfStatus?.configured ? '#166534' : '#64748b'
                    }}>
                      {cfStatus?.configured ? 'Connected' : 'Not Configured'}
                    </span>
                    {cfStatus?.proxy_status && (
                      <span style={{
                        fontSize: '11px',
                        fontWeight: 700,
                        textTransform: 'uppercase',
                        padding: '2px 8px',
                        borderRadius: '999px',
                        background: cfStatus.proxy_status.is_proxied ? '#ffedd5' : '#fee2e2',
                        color: cfStatus.proxy_status.is_proxied ? '#c2410c' : '#991b1b',
                        border: cfStatus.proxy_status.is_proxied ? '1px solid #fdba74' : '1px solid #fecaca',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px'
                      }}>
                        <span style={{
                          width: '7px',
                          height: '7px',
                          borderRadius: '50%',
                          background: cfStatus.proxy_status.is_proxied ? '#ea580c' : '#dc2626',
                          display: 'inline-block'
                        }} />
                        {cfStatus.proxy_status.is_proxied ? 'Proxy: Orange Cloud ☁ (Active)' : 'Proxy: Grey Cloud (DNS Only ⚠️)'}
                      </span>
                    )}
                  </div>
                  <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#64748b' }}>
                    All Cloudflare API tokens, Edge WAF rulesets, IP Access Rules, and live Edge logs are managed centrally under Firewall &amp; WAF.
                  </p>
                </div>
              </div>

              <button
                type="button"
                className="webcare-btn"
                onClick={() => { window.location.href = 'admin.php?page=webcare-pro-firewall&tab=cloudflare'; }}
                style={{
                  background: 'linear-gradient(135deg, #f97316 0%, #ea580c 100%)',
                  color: '#fff',
                  border: 'none',
                  padding: '9px 18px',
                  borderRadius: '8px',
                  fontWeight: 600,
                  fontSize: '13px',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  cursor: 'pointer',
                  boxShadow: '0 2px 6px rgba(234, 88, 12, 0.25)'
                }}
              >
                <Cloud size={16} />
                <span>Open Firewall → Cloudflare Edge →</span>
              </button>
            </div>

            {/* Connection Telemetry Details */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
              gap: '12px',
              padding: '16px',
              borderRadius: '8px',
              background: 'var(--webcare-bg-surface, #f8fafc)',
              border: '1px solid var(--webcare-border, #e2e8f0)',
              fontSize: '12.5px'
            }}>
              <div>
                <span style={{ color: '#64748b', display: 'block', fontSize: '11px', fontWeight: 600, textTransform: 'uppercase' }}>Zone Name</span>
                <span style={{ fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  {cfStatus?.zone_name || cfStatus?.site_root_domain || 'Auto-detection'}
                </span>
              </div>
              <div>
                <span style={{ color: '#64748b', display: 'block', fontSize: '11px', fontWeight: 600, textTransform: 'uppercase' }}>Plan</span>
                <span style={{ fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  {cfStatus?.plan || 'Free / Pro'}
                </span>
              </div>
              <div>
                <span style={{ color: '#64748b', display: 'block', fontSize: '11px', fontWeight: 600, textTransform: 'uppercase' }}>Token Status</span>
                <span style={{ fontWeight: 600, color: cfStatus?.has_token ? '#059669' : '#d97706' }}>
                  {cfStatus?.has_token ? '✓ Sealed in Vault' : 'Not Configured'}
                </span>
              </div>
              <div>
                <span style={{ color: '#64748b', display: 'block', fontSize: '11px', fontWeight: 600, textTransform: 'uppercase' }}>Auto-Ban Sync</span>
                <span style={{ fontWeight: 600, color: cfAutoSyncBans ? '#059669' : '#64748b' }}>
                  {cfAutoSyncBans ? 'Active Edge Sync' : 'Disabled'}
                </span>
              </div>
            </div>

            {/* Token Scope Guidance Banner */}
            <div style={{
              marginTop: '16px',
              padding: '12px 16px',
              background: 'rgba(2, 132, 199, 0.05)',
              border: '1px solid rgba(2, 132, 199, 0.2)',
              borderRadius: '8px',
              fontSize: '12px'
            }}>
              <strong style={{ color: 'var(--webcare-text-primary, #0f172a)', display: 'block', marginBottom: '6px' }}>
                Required Cloudflare API Token Scopes:
              </strong>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
                <span style={{ background: '#e0f2fe', color: '#0369a1', padding: '2px 8px', borderRadius: '4px', fontWeight: 600 }}>Zone.Zone: Read</span>
                <span style={{ background: '#e0f2fe', color: '#0369a1', padding: '2px 8px', borderRadius: '4px', fontWeight: 600 }}>Zone.Zone WAF: Edit</span>
                <span style={{ background: '#fef3c7', color: '#92400e', padding: '2px 8px', borderRadius: '4px', fontWeight: 600 }}>Zone.Firewall Services: Edit</span>
                <span style={{ background: '#ecfdf5', color: '#047857', padding: '2px 8px', borderRadius: '4px', fontWeight: 600 }}>Zone.Analytics: Read</span>
                <span style={{ background: '#e0f2fe', color: '#0369a1', padding: '2px 8px', borderRadius: '4px', fontWeight: 600 }}>Zone.Cache Purge: Purge</span>
              </div>
              <p style={{ margin: '8px 0 0 0', color: '#64748b', fontSize: '11.5px', lineHeight: 1.5 }}>
                Under <strong>Zone Resources</strong> in Cloudflare, choose <code>Specific zone &gt; {cfStatus?.site_root_domain || cfStatus?.zone_name || 'your-domain.com'}</code>.
              </p>
            </div>

            {/* Inputs: Token & Zone ID */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', marginTop: '16px', marginBottom: '16px' }}>
              <div>
                <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '12px', fontWeight: 600, marginBottom: '6px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                  <span>Cloudflare API Token:</span>
                  {cfStatus?.has_token && (
                    <span style={{ fontSize: '11px', color: '#059669', background: '#ecfdf5', padding: '1px 6px', borderRadius: '4px', fontWeight: 600 }}>
                      ✓ Encrypted in Vault
                    </span>
                  )}
                </label>
                <div style={{ position: 'relative' }}>
                  <input
                    type={showCfToken ? 'text' : 'password'}
                    value={cfToken}
                    onChange={(e) => setCfToken(e.target.value)}
                    placeholder={cfStatus?.configured ? '••••••••••••••••••••••••••••' : 'Enter Cloudflare API Bearer Token'}
                    className="webcare-input"
                    style={{ width: '100%', padding: '9px 36px 9px 12px', fontFamily: 'monospace', fontSize: '13px', borderRadius: '8px', border: '1px solid var(--webcare-border, #cbd5e1)' }}
                  />
                  <button
                    type="button"
                    onClick={() => setShowCfToken(!showCfToken)}
                    title={showCfToken ? 'Hide token' : 'Show token'}
                    style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#64748b', padding: 0, display: 'flex', alignItems: 'center' }}
                  >
                    {showCfToken ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              <div>
                <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '12px', fontWeight: 600, marginBottom: '6px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                  <span>Zone ID (Leave blank to auto-detect):</span>
                  {cfStatus?.zone_name && (
                    <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span style={{ color: '#0369a1', fontWeight: 600, fontSize: '11px', background: '#e0f2fe', padding: '1px 8px', borderRadius: '4px' }}>
                        Zone: {cfStatus.zone_name}
                      </span>
                      {cfZoneId && (
                        <button
                          type="button"
                          onClick={() => setCfZoneId('')}
                          style={{
                            background: 'none',
                            border: 'none',
                            color: '#0284c7',
                            fontSize: '11px',
                            cursor: 'pointer',
                            textDecoration: 'underline',
                            padding: 0
                          }}
                        >
                          Clear to Auto-detect
                        </button>
                      )}
                    </span>
                  )}
                </label>
                <div style={{ position: 'relative' }}>
                  <input
                    type={showCfZone ? 'text' : 'password'}
                    value={cfZoneId}
                    onChange={(e) => setCfZoneId(e.target.value)}
                    placeholder={cfStatus?.configured ? (cfStatus.zone_id || '••••••••••••••••••••••••••••••••') : `Leave blank to auto-detect for ${cfStatus?.site_root_domain || 'site domain'}`}
                    className="webcare-input"
                    style={{ width: '100%', padding: '9px 36px 9px 12px', fontFamily: 'monospace', fontSize: '13px', borderRadius: '8px', border: '1px solid var(--webcare-border, #cbd5e1)' }}
                  />
                  <button
                    type="button"
                    onClick={() => setShowCfZone(!showCfZone)}
                    title={showCfZone ? 'Hide Zone ID' : 'Show Zone ID'}
                    style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#64748b', padding: 0, display: 'flex', alignItems: 'center' }}
                  >
                    {showCfZone ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>
            </div>

            {/* Auto-Sync Bans Toggle */}
            <div style={{ marginBottom: '16px', padding: '12px 16px', background: 'var(--webcare-bg-surface, #f8fafc)', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
              <ToggleSwitch
                checked={cfAutoSyncBans}
                onChange={handleToggleAutoSyncBans}
                label="Real-time WAF Auto-Ban Sync to Cloudflare Edge"
                description="When WebCare Origin WAF intercepts brute-force attacks or malicious exploit attempts, automatically ban the offending IP at the Cloudflare Global Anycast Edge via IP Access Rules."
                badge={cfAutoSyncBans ? (
                  <span style={{ fontSize: '11px', background: '#ecfdf5', color: '#059669', padding: '2px 8px', borderRadius: '10px', fontWeight: 600 }}>Active</span>
                ) : (
                  <span style={{ fontSize: '11px', background: '#f1f5f9', color: '#64748b', padding: '2px 8px', borderRadius: '10px', fontWeight: 500 }}>Disabled</span>
                )}
                activeColor="#10b981"
              />
            </div>

            {/* Action Buttons & Status Result */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="webcare-btn"
                  style={{
                    background: '#ea580c',
                    color: '#fff',
                    border: 'none',
                    padding: '9px 18px',
                    fontWeight: 600,
                    fontSize: '13px',
                    borderRadius: '8px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    boxShadow: '0 2px 4px rgba(234, 88, 12, 0.2)',
                    cursor: cfVerifying ? 'not-allowed' : 'pointer'
                  }}
                  disabled={cfVerifying}
                  onClick={handleVerifyCloudflare}
                >
                  {cfVerifying ? <Loader2 size={15} className="webcare-spin" /> : <CheckCircle2 size={15} />}
                  <span>{cfStatus?.configured ? 'Re-verify & Update Credentials' : 'Verify & Save Credentials'}</span>
                </button>

                {cfStatus?.configured && (
                  <button
                    type="button"
                    className="webcare-btn"
                    style={{
                      background: 'var(--webcare-bg-card, #ffffff)',
                      color: '#dc2626',
                      border: '1px solid #fecaca',
                      padding: '9px 14px',
                      fontWeight: 600,
                      fontSize: '12px',
                      borderRadius: '8px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                      cursor: disconnectingCf ? 'not-allowed' : 'pointer'
                    }}
                    disabled={disconnectingCf}
                    onClick={handleDisconnectCloudflare}
                  >
                    {disconnectingCf ? <Loader2 size={14} className="webcare-spin" /> : <Trash2 size={14} />}
                    <span>Disconnect Cloudflare</span>
                  </button>
                )}
              </div>

              {cfVerifyResult ? (
                <div style={{ fontSize: '13px', fontWeight: 600, color: cfVerifyResult.success ? '#166534' : '#991b1b' }}>
                  {cfVerifyResult.success ? `✓ Connected to ${cfVerifyResult.zone_name} (${cfVerifyResult.plan} Plan)` : `✗ ${cfVerifyResult.message}`}
                </div>
              ) : cfStatus?.configured ? (
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#166534' }}>
                  ✓ Connected to <strong>{cfStatus.zone_name}</strong> ({cfStatus.plan} Plan)
                </div>
              ) : null}
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB 3: AI INTEGRATION (CHATGPT, GEMINI, CLAUDE)
          ========================================================================= */}
      {activeSubTab === 'ai' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '24px' }}>
          <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <div style={{ background: '#f5f3ff', color: '#7c3aed', padding: '10px', borderRadius: '8px' }}>
                <Sparkles size={20} />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: '17px', color: 'var(--webcare-text-primary, #0f172a)' }}>AI Cybersecurity Intelligence Engine</h3>
                <p style={{ margin: 0, fontSize: '13px', color: '#64748b' }}>Connect ChatGPT, Google Gemini, or Claude for instant code de-obfuscation & threat analysis</p>
              </div>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <ToggleSwitch
                checked={settings.ai_enabled}
                onChange={(val) => setSettings({ ...settings, ai_enabled: val })}
                label="Enable AI Suspicious Code &amp; Threat Forensics"
                description="Adds a 1-click 'Analyze with AI' button inside the Code Inspector Modal to explain obfuscated scripts, decode hidden base64 payloads, and recommend surgical remediation."
                badge={settings.ai_enabled ? (
                  <span style={{ fontSize: '11px', background: '#f5f3ff', color: '#7c3aed', padding: '2px 8px', borderRadius: '10px', fontWeight: 600 }}>Active</span>
                ) : (
                  <span style={{ fontSize: '11px', background: '#f1f5f9', color: '#64748b', padding: '2px 8px', borderRadius: '10px', fontWeight: 500 }}>Disabled</span>
                )}
                activeColor="#7c3aed"
              />
            </div>

            {settings.ai_enabled && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>

                {/* Status Notice: WordPress Native AI Connect Active */}
                {settings.ai_connect_status?.is_available ? (
                  <div
                    className="webcare-settings-callout webcare-settings-callout-success"
                    style={{
                      borderRadius: '10px',
                      padding: '16px 18px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '10px',
                      boxShadow: '0 1px 3px rgba(16, 185, 129, 0.08)'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <div style={{ background: '#10b981', color: '#fff', borderRadius: '50%', width: '26px', height: '26px', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                          <Check size={16} />
                        </div>
                        <div>
                          <strong className="webcare-settings-callout-title" style={{ fontSize: '13px' }}>WordPress Native AI Connect Active &amp; Ready</strong>
                          <span style={{ marginLeft: '8px', fontSize: '11px', background: 'rgba(16, 185, 129, 0.2)', color: '#10b981', padding: '2px 8px', borderRadius: '12px', fontWeight: 600 }}>
                            {settings.ai_connect_status.engine_name}
                          </span>
                        </div>
                      </div>
                      <span style={{ fontSize: '11px', color: '#10b981', fontStyle: 'italic' }}>
                        Detected: {settings.ai_connect_status.detected_via || 'Native WordPress Core/Plugin AI'}
                      </span>
                    </div>

                    <p className="webcare-settings-callout-desc" style={{ margin: 0, fontSize: '13px', lineHeight: '1.5' }}>
                      {settings.ai_connect_status.details || 'Your site already has WordPress Native AI Connect active! WebCare Pro Security & Firewall is 100% compatible with your existing WordPress AI infrastructure. You can route deep code de-obfuscation and threat forensics directly through your WordPress AI connect subsystem without needing to configure separate external API keys.'}
                    </p>

                    {/* Security Notice Callout */}
                    <div
                      className="webcare-settings-inner-callout"
                      style={{
                        borderRadius: '8px',
                        padding: '10px 14px',
                        fontSize: '12px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '6px'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '6px' }}>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontWeight: 600, color: '#f59e0b' }}>
                          <ShieldAlert size={14} color="#f59e0b" />
                          Security Note: Native Connectors Store Keys in Plaintext
                        </span>
                        <a
                          href="https://webcarepro.dev/blog/post/how-aes-256-gcm-vault-protects-wordpress-secrets"
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{
                            color: '#38bdf8',
                            fontWeight: 600,
                            textDecoration: 'none',
                            fontSize: '11px',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px'
                          }}
                        >
                          Read Cryptographic Architecture Guide ↗
                        </a>
                      </div>
                      <span className="webcare-settings-inner-callout-text" style={{ lineHeight: 1.5 }}>
                        Native WordPress AI Connectors stores Google and OpenAI keys as raw unencrypted plaintext in <code>wp_options</code>. For maximum protection against SQL dump or database backup leaks, configure keys directly in WebCare Pro Security & Firewall to encrypt them at rest with AES-256-GCM AEAD.
                      </span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', paddingTop: '4px' }}>
                      {settings.ai_provider !== 'wp_ai_connect' ? (
                        <button
                          type="button"
                          onClick={() => setSettings({ ...settings, ai_provider: 'wp_ai_connect' })}
                          style={{
                            background: '#059669',
                            color: '#fff',
                            border: 'none',
                            borderRadius: '6px',
                            padding: '6px 14px',
                            fontSize: '12px',
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '6px'
                          }}
                        >
                          <Sparkles size={13} />
                          Switch Primary Engine to WordPress Native AI Connect
                        </button>
                      ) : (
                        <span style={{ fontSize: '12px', color: '#065f46', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                          <CheckCircle size={14} color="#059669" /> Currently Selected as Primary AI Engine
                        </span>
                      )}

                      {(settings.ai_connect_status?.has_connectors_page || settings.ai_connect_status?.connectors_url) && (
                        <a
                          href={settings.ai_connect_status.connectors_url || 'options-connectors.php'}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{
                            background: 'var(--webcare-bg-card, #ffffff)',
                            color: '#065f46',
                            border: '1px solid #10b981',
                            borderRadius: '6px',
                            padding: '6px 12px',
                            fontSize: '12px',
                            fontWeight: 600,
                            textDecoration: 'none',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '6px'
                          }}
                        >
                          <ExternalLink size={13} />
                          Manage AI Connectors (options-connectors.php) ↗
                        </a>
                      )}
                    </div>
                  </div>
                ) : (
                  /* Recommendation Banner: When Native AI Connect is not active */
                  <div
                    className="webcare-settings-callout webcare-settings-callout-info"
                    style={{
                      borderRadius: '10px',
                      padding: '16px 18px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '10px'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <div style={{ background: '#6366f1', color: '#fff', borderRadius: '50%', width: '26px', height: '26px', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                          <Sparkles size={15} />
                        </div>
                        <strong style={{ fontSize: '13px', color: 'var(--webcare-text-primary, #1e293b)' }}>Recommended: WordPress Native AI Connect</strong>
                      </div>
                      <span style={{ fontSize: '11px', background: '#e0e7ff', color: '#4338ca', padding: '2px 8px', borderRadius: '12px', fontWeight: 600 }}>
                        100% Compatible with WebCare Pro
                      </span>
                    </div>

                    <p style={{ margin: 0, fontSize: '13px', color: '#475569', lineHeight: '1.5' }}>
                      Prefer unified WordPress AI management? You can use WordPress Native AI Connectors (<code>options-connectors.php</code>) or any compatible plugin (such as <em>AI Engine</em>). They are completely compatible with WebCare Pro Security & Firewall, allowing you to manage OpenAI, Gemini, Claude, and local models centrally while WebCare Pro Security & Firewall utilizes them automatically.
                    </p>

                    {/* Security Notice on Plaintext Database Storage */}
                    <div
                      className="webcare-settings-inner-callout webcare-settings-inner-callout-warning"
                      style={{
                        borderRadius: '8px',
                        padding: '10px 14px',
                        fontSize: '12px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '6px'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '6px' }}>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontWeight: 600, color: '#f59e0b' }}>
                          <ShieldAlert size={14} color="#f59e0b" />
                          Security Advisory: Native Connectors Store Plaintext in Database
                        </span>
                        <a
                          href="https://webcarepro.dev/blog/post/how-aes-256-gcm-vault-protects-wordpress-secrets"
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{
                            color: '#38bdf8',
                            fontWeight: 600,
                            textDecoration: 'none',
                            fontSize: '11px',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px'
                          }}
                        >
                          How AES-256-GCM Vault Protects Secrets ↗
                        </a>
                      </div>
                      <span className="webcare-settings-inner-callout-text" style={{ lineHeight: 1.5 }}>
                        The official WordPress AI Connectors app stores API keys in unencrypted plaintext inside the <code>wp_options</code> table. To ensure your credentials remain encrypted at rest via AES-256-GCM AEAD, consider configuring your API keys directly in WebCare Pro Security & Firewall below.
                      </span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', paddingTop: '4px' }}>
                      {settings.ai_connect_status?.has_connectors_page || settings.ai_connect_status?.connectors_url ? (
                        <a
                          href={settings.ai_connect_status?.connectors_url || 'options-connectors.php'}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{
                            background: '#059669',
                            color: '#fff',
                            textDecoration: 'none',
                            borderRadius: '6px',
                            padding: '7px 14px',
                            fontSize: '12px',
                            fontWeight: 600,
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '6px',
                            boxShadow: '0 1px 2px rgba(5, 150, 105, 0.2)'
                          }}
                        >
                          <ExternalLink size={13} />
                          Configure WordPress AI Connectors (options-connectors.php) ↗
                        </a>
                      ) : null}
                      <span style={{ fontSize: '12px', color: '#64748b' }}>
                        Or configure standalone API keys for Google Gemini, OpenAI, or Claude directly below.
                      </span>
                    </div>
                  </div>
                )}

                {/* AI Provider Selector */}
                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '8px' }}>
                    Select Primary AI Provider
                  </label>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '10px' }}>
                    {[
                      {
                        id: 'gemini',
                        name: 'Google Gemini',
                        icon: '✨',
                        badge: modelCatalog?.gemini?.models?.find((m: any) => m.id === settings.gemini_model)?.badge || modelCatalog?.gemini?.models?.[0]?.badge || '3.8 Flash',
                      },
                      {
                        id: 'openai',
                        name: 'OpenAI ChatGPT',
                        icon: '🤖',
                        badge: modelCatalog?.openai?.models?.find((m: any) => m.id === settings.openai_model)?.badge || modelCatalog?.openai?.models?.[0]?.badge || 'GPT-6.1 Sol',
                      },
                      {
                        id: 'claude',
                        name: 'Anthropic Claude',
                        icon: '🧠',
                        badge: modelCatalog?.claude?.models?.find((m: any) => m.id === settings.claude_model)?.badge || modelCatalog?.claude?.models?.[0]?.badge || 'Sonnet 5.5',
                      },
                      {
                        id: 'wp_ai_connect',
                        name: 'WP AI Connect',
                        icon: '🔌',
                        badge: settings.ai_connect_status?.is_available ? 'Native Active' : 'WordPress AI Bridge',
                      },
                    ].map((prov) => (
                      <button
                        key={prov.id}
                        type="button"
                        onClick={() => setSettings({ ...settings, ai_provider: prov.id as any })}
                        className={`webcare-settings-provider-card ${settings.ai_provider === prov.id ? 'is-selected' : ''}`}
                        style={{
                          padding: '12px 10px',
                          borderRadius: '8px',
                          cursor: 'pointer',
                          textAlign: 'center',
                          display: 'flex',
                          flexDirection: 'column',
                          alignItems: 'center',
                          gap: '4px',
                          transition: 'all 0.15s ease'
                        }}
                      >
                        <span style={{ fontSize: '20px' }}>{prov.icon}</span>
                        <strong className="webcare-settings-provider-name" style={{ fontSize: '13px' }}>{prov.name}</strong>
                        <span className="webcare-settings-provider-badge" style={{ fontSize: '11px' }}>{prov.badge}</span>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Provider Specific Configuration: WP AI Connect */}
                {settings.ai_provider === 'wp_ai_connect' && (
                  <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '16px', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
                      <div>
                        <label style={{ fontSize: '13px', fontWeight: 600, color: '#334155' }}>WordPress Native AI Connect Bridge</label>
                        <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: '#64748b' }}>
                          Threat forensics and code de-obfuscation are dispatched natively through your WordPress AI infrastructure.
                        </p>
                      </div>
                      {settings.ai_connect_status?.is_available ? (
                        <span style={{ fontSize: '11px', color: '#059669', background: '#ecfdf5', padding: '3px 8px', borderRadius: '4px', fontWeight: 600 }}>
                          ✓ Connected ({settings.ai_connect_status.engine_name})
                        </span>
                      ) : (
                        <span style={{ fontSize: '11px', color: '#d97706', background: '#fffbeb', padding: '3px 8px', borderRadius: '4px', fontWeight: 600 }}>
                          ⚠ Awaiting AI Connector Configuration
                        </span>
                      )}
                    </div>

                    <div style={{ background: 'var(--webcare-bg-card, #ffffff)', border: '1px solid var(--webcare-border, #e2e8f0)', borderRadius: '8px', padding: '12px', fontSize: '12px', color: '#475569', lineHeight: 1.6 }}>
                      <div><strong>Active Subsystem:</strong> {settings.ai_connect_status?.engine_name || 'WordPress Core AI Connectors'}</div>
                      {settings.ai_connect_status?.detected_via && (
                        <div><strong>Detected Via:</strong> <code style={{ background: '#f1f5f9', padding: '1px 4px', borderRadius: '3px' }}>{settings.ai_connect_status.detected_via}</code></div>
                      )}
                      <div style={{ marginTop: '6px' }}><strong>Universal Compatibility:</strong> Any WordPress AI connect plugin (WordPress Core AI Connectors, AI Engine by Meow Apps, WP AI Connect, Jetpack AI, or custom filters) works seamlessly with WebCare Pro Security & Firewall. No separate API key is needed.</div>
                    </div>

                    {/* Dedicated Security Advisory Card */}
                    <div
                      className="webcare-settings-callout webcare-settings-callout-warning"
                      style={{
                        borderRadius: '8px',
                        padding: '14px 16px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '8px'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <ShieldAlert size={16} color="#f59e0b" />
                          <strong className="webcare-settings-callout-title" style={{ fontSize: '13px' }}>
                            Security Advisory: Plaintext Database Storage in Native Connectors
                          </strong>
                        </div>
                        <span style={{ fontSize: '11px', background: 'rgba(239, 68, 68, 0.2)', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.35)', padding: '1px 8px', borderRadius: '10px', fontWeight: 600 }}>
                          Unencrypted at Rest
                        </span>
                      </div>
                      <p className="webcare-settings-callout-desc" style={{ margin: 0, fontSize: '12px', lineHeight: 1.55 }}>
                        Official WordPress AI Connectors (<code>options-connectors.php</code>) stores Google Gemini and OpenAI API keys unencrypted in raw plaintext inside the <code>wp_options</code> table (<code>connectors_ai_google_api_key</code> and <code>connectors_ai_openai_api_key</code>). If an attacker acquires an unencrypted SQL database backup or exploits an SQL injection vulnerability in any third-party plugin, raw API keys are exposed.
                      </p>
                      <p className="webcare-settings-callout-desc" style={{ margin: 0, fontSize: '12px', lineHeight: 1.55 }}>
                        <strong>Recommendation:</strong> To protect your API quota and infrastructure against database leaks, configure your Google Gemini, OpenAI, or Claude API keys directly within WebCare Pro Security & Firewall by choosing a dedicated provider above. WebCare Pro Security & Firewall encrypts all keys at rest using enterprise <strong>AES-256-GCM AEAD</strong> with randomized 12-byte nonces and 128-bit authentication tags.
                      </p>
                      <div style={{ paddingTop: '4px' }}>
                        <a
                          href="https://webcarepro.dev/blog/post/how-aes-256-gcm-vault-protects-wordpress-secrets"
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{
                            background: '#d97706',
                            color: '#fff',
                            textDecoration: 'none',
                            borderRadius: '6px',
                            padding: '6px 12px',
                            fontSize: '11.5px',
                            fontWeight: 600,
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '6px',
                            boxShadow: '0 1px 2px rgba(180, 83, 9, 0.2)'
                          }}
                        >
                          <Lock size={12} />
                          Read Architecture Guide: How AES-256-GCM Vault Protects Secrets ↗
                        </a>
                      </div>
                    </div>

                    {(settings.ai_connect_status?.connectors_url || settings.ai_connect_status?.has_connectors_page) && (
                      <div>
                        <a
                          href={settings.ai_connect_status.connectors_url || 'options-connectors.php'}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{
                            background: '#059669',
                            color: '#fff',
                            textDecoration: 'none',
                            borderRadius: '6px',
                            padding: '7px 14px',
                            fontSize: '12px',
                            fontWeight: 600,
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '6px',
                            boxShadow: '0 1px 2px rgba(5, 150, 105, 0.2)'
                          }}
                        >
                          <ExternalLink size={13} />
                          Open WordPress AI Connectors Settings (options-connectors.php) ↗
                        </a>
                      </div>
                    )}
                  </div>
                )}

                {/* Provider Specific Configuration: OpenAI */}
                {settings.ai_provider === 'openai' && (
                  <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '16px', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                        <label style={{ fontSize: '13px', fontWeight: 600, color: '#334155' }}>OpenAI API Key</label>
                        {settings.has_openai_key && (
                          <span style={{ fontSize: '11px', color: '#059669', background: '#ecfdf5', padding: '2px 6px', borderRadius: '4px' }}>✓ Saved in Vault</span>
                        )}
                      </div>
                      <div style={{ position: 'relative' }}>
                        <input
                          type={showKey['openai'] ? 'text' : 'password'}
                          value={showKey['openai'] ? getMaskedSecret(settings.openai_api_key) : (settings.openai_api_key || '')}
                          onChange={(e) => setSettings({ ...settings, openai_api_key: e.target.value })}
                          readOnly={!!showKey['openai']}
                          placeholder={settings.has_openai_key ? '•••••••• (Key saved, type to replace)' : 'sk-...'}
                          style={{ width: '100%', padding: '9px 40px 9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px', fontFamily: 'monospace' }}
                        />
                        <button
                          type="button"
                          onClick={() => setShowKey({ ...showKey, openai: !showKey['openai'] })}
                          title={showKey['openai'] ? 'Hide Key' : 'Show Key (Partially Masked)'}
                          style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#64748b' }}
                        >
                          {showKey['openai'] ? <EyeOff size={16} /> : <Eye size={16} />}
                        </button>
                      </div>
                    </div>

                    <div>
                      <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
                        OpenAI Model
                      </label>
                      <select
                        value={settings.openai_model || 'gpt-6.1-sol'}
                        onChange={(e) => setSettings({ ...settings, openai_model: e.target.value })}
                        style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '14px', background: 'var(--webcare-bg-card, #ffffff)' }}
                      >
                        {modelCatalog?.openai?.models?.length ? (
                          modelCatalog.openai.models.map((m: any) => (
                            <option key={m.id} value={m.id}>
                              {m.name} ({m.description})
                            </option>
                          ))
                        ) : (
                          <>
                            <option value="gpt-6.1-sol">GPT-6.1 Sol (Latest Balanced Default - Recommended)</option>
                            <option value="gpt-6-astra">GPT-6 Astra (Flagship Forensic & Autonomous Coding)</option>
                            <option value="gpt-6-luna">GPT-6 Luna (Ultra-Fast & Cost-Efficient)</option>
                          </>
                        )}
                      </select>
                    </div>
                  </div>
                )}

                {settings.ai_provider === 'gemini' && (
                  <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '16px', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                        <label style={{ fontSize: '13px', fontWeight: 600, color: '#334155' }}>Google Gemini API Key</label>
                        {settings.has_gemini_key && (
                          <span style={{ fontSize: '11px', color: '#059669', background: '#ecfdf5', padding: '2px 6px', borderRadius: '4px' }}>✓ Saved in Vault</span>
                        )}
                      </div>
                      <div style={{ position: 'relative' }}>
                        <input
                          type={showKey['gemini'] ? 'text' : 'password'}
                          value={showKey['gemini'] ? getMaskedSecret(settings.gemini_api_key) : (settings.gemini_api_key || '')}
                          onChange={(e) => setSettings({ ...settings, gemini_api_key: e.target.value })}
                          readOnly={!!showKey['gemini']}
                          placeholder={settings.has_gemini_key ? '•••••••• (Key saved, type to replace)' : 'AIzaSy...'}
                          style={{ width: '100%', padding: '9px 40px 9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px', fontFamily: 'monospace' }}
                        />
                        <button
                          type="button"
                          onClick={() => setShowKey({ ...showKey, gemini: !showKey['gemini'] })}
                          title={showKey['gemini'] ? 'Hide Key' : 'Show Key (Partially Masked)'}
                          style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#64748b' }}
                        >
                          {showKey['gemini'] ? <EyeOff size={16} /> : <Eye size={16} />}
                        </button>
                      </div>
                    </div>

                    <div>
                      <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
                        Gemini Model
                      </label>
                      <select
                        value={settings.gemini_model || 'gemini-3.8-flash'}
                        onChange={(e) => setSettings({ ...settings, gemini_model: e.target.value })}
                        style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '14px', background: 'var(--webcare-bg-card, #ffffff)' }}
                      >
                        {modelCatalog?.gemini?.models?.length ? (
                          modelCatalog.gemini.models.map((m: any) => (
                            <option key={m.id} value={m.id}>
                              {m.name} ({m.description})
                            </option>
                          ))
                        ) : (
                          <>
                            <option value="gemini-3.5-flash-lite">Gemini 3.5 Flash-Lite (Recommended Low-Token & High-Speed Engine)</option>
                            <option value="gemini-3.1-flash-lite">Gemini 3.1 Flash-Lite (Fast & Cost-Efficient Forensic Agent)</option>
                            <option value="gemini-3.8-flash">Gemini 3.8 Flash (High-Intelligence Flagship Agent)</option>
                          </>
                        )}
                      </select>
                    </div>
                  </div>
                )}

                {settings.ai_provider === 'claude' && (
                  <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '16px', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                        <label style={{ fontSize: '13px', fontWeight: 600, color: '#334155' }}>Anthropic Claude API Key</label>
                        {settings.has_claude_key && (
                          <span style={{ fontSize: '11px', color: '#059669', background: '#ecfdf5', padding: '2px 6px', borderRadius: '4px' }}>✓ Saved in Vault</span>
                        )}
                      </div>
                      <div style={{ position: 'relative' }}>
                        <input
                          type={showKey['claude'] ? 'text' : 'password'}
                          value={showKey['claude'] ? getMaskedSecret(settings.claude_api_key) : (settings.claude_api_key || '')}
                          onChange={(e) => setSettings({ ...settings, claude_api_key: e.target.value })}
                          readOnly={!!showKey['claude']}
                          placeholder={settings.has_claude_key ? '•••••••• (Key saved, type to replace)' : 'sk-ant-...'}
                          style={{ width: '100%', padding: '9px 40px 9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px', fontFamily: 'monospace' }}
                        />
                        <button
                          type="button"
                          onClick={() => setShowKey({ ...showKey, claude: !showKey['claude'] })}
                          title={showKey['claude'] ? 'Hide Key' : 'Show Key (Partially Masked)'}
                          style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#64748b' }}
                        >
                          {showKey['claude'] ? <EyeOff size={16} /> : <Eye size={16} />}
                        </button>
                      </div>
                    </div>

                    <div>
                      <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
                        Claude Model
                      </label>
                      <select
                        value={settings.claude_model || 'claude-sonnet-5-5'}
                        onChange={(e) => setSettings({ ...settings, claude_model: e.target.value })}
                        style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '14px', background: 'var(--webcare-bg-card, #ffffff)' }}
                      >
                        {modelCatalog?.claude?.models?.length ? (
                          modelCatalog.claude.models.map((m: any) => (
                            <option key={m.id} value={m.id}>
                              {m.name} ({m.description})
                            </option>
                          ))
                        ) : (
                          <>
                            <option value="claude-sonnet-5-5">Claude Sonnet 5.5 (Latest Default - Premier Code & Threat Analysis)</option>
                            <option value="claude-opus-5-5">Claude Opus 5.5 (Flagship Frontier Model)</option>
                            <option value="claude-haiku-5-5">Claude Haiku 5.5 (Ultra-Fast Low Latency Response)</option>
                          </>
                        )}
                      </select>
                    </div>
                  </div>
                )}

                {/* Action Buttons: Test Connection & Check for New AI Agent Releases */}
                <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '10px' }}>
                  <button
                    type="button"
                    className="webcare-btn"
                    style={{ background: '#7c3aed', color: '#fff', fontSize: '13px' }}
                    onClick={handleTestAi}
                    disabled={testingAi}
                  >
                    {testingAi ? <Loader2 size={14} className="webcare-spin-icon" /> : <Zap size={14} />}
                    {testingAi ? 'Testing AI Connection...' : 'Test AI Connection'}
                  </button>

                  <button
                    type="button"
                    className="webcare-btn"
                    style={{ background: '#0284c7', color: '#fff', fontSize: '13px' }}
                    onClick={handleUpdateAiModels}
                    disabled={updatingModels}
                    title="Queries provider APIs to detect newer models (e.g., Gemini 3.9) and automatically upgrades your active agent"
                  >
                    {updatingModels ? <Loader2 size={14} className="webcare-spin-icon" /> : <RefreshCw size={14} />}
                    {updatingModels ? 'Checking for AI Updates...' : 'Check & Update AI Agent Versions'}
                  </button>

                  {aiTestResult && (
                    <div style={{
                      fontSize: '13px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                      color: aiTestResult.success ? '#059669' : '#dc2626'
                    }}>
                      {aiTestResult.success ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
                      <span>{aiTestResult.success ? aiTestResult.message : aiTestResult.error}</span>
                    </div>
                  )}
                </div>

                {modelUpdateMsg && (
                  <div style={{
                    padding: '10px 14px',
                    borderRadius: '8px',
                    fontSize: '13px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    background: modelUpdateMsg.success ? '#ecfdf5' : '#fef2f2',
                    border: modelUpdateMsg.success ? '1px solid #a7f3d0' : '1px solid #fecaca',
                    color: modelUpdateMsg.success ? '#065f46' : '#991b1b',
                  }}>
                    {modelUpdateMsg.success ? <CheckCircle2 size={16} color="#10b981" /> : <AlertTriangle size={16} color="#ef4444" />}
                    <span>{modelUpdateMsg.text}</span>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* AI Features Overview Card */}
          <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px' }}>
            <h3 style={{ margin: '0 0 16px 0', fontSize: '17px', color: 'var(--webcare-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Sparkles size={18} color="#7c3aed" /> How AI Enhances Security
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', fontSize: '13px', color: '#334155' }}>
              <div style={{ padding: '12px', background: 'var(--webcare-bg-surface, #f8fafc)', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
                <strong style={{ display: 'block', color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '4px' }}>1. Obfuscated Payload Decoding</strong>
                Attackers disguise malware using layers of encoding wrappers or dynamic string concatenations. AI decodes and explains the underlying execution payload in plain English.
              </div>

              <div style={{ padding: '12px', background: 'var(--webcare-bg-surface, #f8fafc)', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
                <strong style={{ display: 'block', color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '4px' }}>2. False-Positive Validation</strong>
                Complex legitimate developer functions (such as custom evaluators or migration scripts) can be evaluated by AI to determine if they are safe or hostile.
              </div>

              <div style={{ padding: '12px', background: 'var(--webcare-bg-surface, #f8fafc)', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
                <strong style={{ display: 'block', color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '4px' }}>3. Targeted Remediation Patches</strong>
                AI recommends specific line-by-line surgical fixes to remove backdoors without crashing your WordPress theme or plugin functionality.
              </div>
            </div>
          </div>

        </div>
      )}

      {/* =========================================================================
          TAB: MODEL CONTEXT PROTOCOL (MCP) AGENT ABILITIES
          ========================================================================= */}
      {/* =========================================================================
          TAB: MODEL CONTEXT PROTOCOL (MCP) AGENT ABILITIES
          ========================================================================= */}
      {activeSubTab === 'mcp' && (
        <MCPAgentServiceCard
          settings={settings}
          onUpdateSetting={(key, val) => setSettings({ ...settings, [key]: val })}
          apiRequest={apiRequest}
        />
      )}

      {/* =========================================================================
          TAB 3.5: HTTP SECURITY HEADERS & 1-CLICK SITE HARDENING
          ========================================================================= */}
      {activeSubTab === 'headers' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {/* Top Banner: Score Card & 1-Click A+ Preset Action */}
          <div className="webcare-card" style={{
            background: 'linear-gradient(135deg, #ffffff 0%, #f8fafc 100%)',
            borderRadius: '16px',
            border: '1px solid var(--webcare-border, #e2e8f0)',
            padding: '28px',
            color: 'var(--webcare-text-primary, #0f172a)',
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '20px',
            boxShadow: '0 4px 16px rgba(15, 23, 42, 0.04)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
              <div style={{
                width: '76px',
                height: '76px',
                borderRadius: '16px',
                background: hardeningAudit?.grade === 'A+' || hardeningAudit?.grade === 'A'
                  ? 'linear-gradient(135deg, #10b981 0%, #059669 100%)'
                  : hardeningAudit?.grade === 'B'
                  ? 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)'
                  : 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#fff',
                boxShadow: '0 4px 12px rgba(16, 185, 129, 0.25)',
              }}>
                <span style={{ fontSize: '28px', fontWeight: 800, lineHeight: 1 }}>
                  {hardeningAudit?.grade || '—'}
                </span>
                <span style={{ fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.05em', opacity: 0.9, marginTop: '3px' }}>
                  Rating
                </span>
              </div>

              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                  <h3 style={{ margin: 0, fontSize: '20px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)', letterSpacing: '-0.02em' }}>
                    HTTP Security Headers &amp; Site Hardening Engine
                  </h3>
                  <span style={{
                    fontSize: '11px',
                    fontWeight: 600,
                    padding: '2px 8px',
                    borderRadius: '12px',
                    background: '#ecfdf5',
                    color: '#059669',
                    border: '1px solid #a7f3d0'
                  }}>
                    Defense-in-Depth
                  </span>
                </div>
                <p style={{ margin: 0, fontSize: '13px', color: '#475569', maxWidth: '640px', lineHeight: 1.5 }}>
                  Enforces modern browser defense standards including HSTS, Clickjacking shields, MIME sniffing guards, and administrator account enumeration protection to foil automated AI bot recon.
                </p>
                <div style={{ marginTop: '10px', display: 'flex', alignItems: 'center', gap: '16px', fontSize: '12px', color: '#64748b' }}>
                  <span>Security Score: <strong style={{ color: '#0284c7' }}>{hardeningAudit?.score ?? 0} / {hardeningAudit?.max_score ?? 100} pts</strong></span>
                  <span>•</span>
                  <span>SSL State: <strong style={{ color: hardeningAudit?.is_ssl ? '#059669' : '#dc2626' }}>{hardeningAudit?.is_ssl ? 'HTTPS Enabled (Active)' : 'HTTP Insecure'}</strong></span>
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
              <button
                type="button"
                className="webcare-btn"
                style={{
                  background: 'rgba(255, 255, 255, 0.1)',
                  color: '#fff',
                  fontSize: '13px',
                  border: '1px solid rgba(255, 255, 255, 0.2)',
                  borderRadius: '10px',
                  padding: '10px 16px'
                }}
                onClick={loadHardeningAudit}
                disabled={loadingAudit}
              >
                {loadingAudit ? <Loader2 size={15} className="webcare-spin-icon" /> : <RefreshCw size={15} />}
                {loadingAudit ? 'Auditing...' : 'Re-Audit Headers'}
              </button>

              <button
                type="button"
                className="webcare-btn"
                style={{
                  background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                  color: '#fff',
                  fontSize: '13px',
                  fontWeight: 600,
                  borderRadius: '10px',
                  padding: '10px 20px',
                  boxShadow: '0 4px 12px rgba(16, 185, 129, 0.35)',
                  border: 'none',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px'
                }}
                onClick={handleApplyHardeningPreset}
                disabled={applyingPreset}
              >
                {applyingPreset ? <Loader2 size={16} className="webcare-spin-icon" /> : <Zap size={16} />}
                {applyingPreset ? 'Applying Hardening...' : '1-Click Apply A+ Hardening'}
              </button>
            </div>
          </div>

          {/* Grid of Two Columns: Security Headers vs Server Hardening */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: '24px' }}>
            {/* Column 1: HTTP Security Headers */}
            <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '18px' }}>
                <div style={{ background: '#e0f2fe', color: '#0284c7', padding: '8px', borderRadius: '8px' }}>
                  <ShieldCheck size={20} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>HTTP Security Headers</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>Response headers sent to all client browser requests</span>
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <ToggleSwitch
                  checked={!!settings.header_hsts}
                  onChange={(val) => setSettings({ ...settings, header_hsts: val })}
                  label="HTTP Strict Transport Security (HSTS)"
                  description={<span>Sends <code>Strict-Transport-Security: max-age=31536000; includeSubDomains</code> to force browsers to strictly use HTTPS.</span>}
                  activeColor="#10b981"
                />

                {settings.header_hsts && (
                  <div style={{ marginLeft: '48px', marginTop: '-4px' }}>
                    <ToggleSwitch
                      checked={!!settings.header_hsts_preload}
                      onChange={(val) => setSettings({ ...settings, header_hsts_preload: val })}
                      label="Include HSTS Preload Directive"
                      description="Appends '; preload' allowing your domain to be hardcoded into Chrome/Firefox HSTS preload lists."
                      activeColor="#0284c7"
                    />
                  </div>
                )}

                <div style={{ borderTop: '1px solid #f1f5f9', paddingTop: '12px' }}>
                  <ToggleSwitch
                    checked={!!settings.header_x_frame_options}
                    onChange={(val) => setSettings({ ...settings, header_x_frame_options: val })}
                    label="Clickjacking Defense (X-Frame-Options)"
                    description="Prevents third-party malicious sites from embedding your WordPress site inside hidden IFRAMEs."
                    activeColor="#10b981"
                  />
                  {settings.header_x_frame_options && (
                    <div style={{ marginLeft: '48px', marginTop: '8px' }}>
                      <label style={{ fontSize: '12px', color: '#64748b', fontWeight: 600, display: 'block', marginBottom: '4px' }}>
                        X-Frame-Options Mode:
                      </label>
                      <select
                        value={settings.header_x_frame_options_mode || 'SAMEORIGIN'}
                        onChange={(e) => setSettings({ ...settings, header_x_frame_options_mode: e.target.value as any })}
                        style={{ padding: '6px 10px', fontSize: '13px', borderRadius: '6px', border: '1px solid #cbd5e1', background: 'var(--webcare-bg-card, #ffffff)' }}
                      >
                        <option value="SAMEORIGIN">SAMEORIGIN (Allow framing only by your own site domain - Recommended)</option>
                        <option value="DENY">DENY (Strictly block all framing from all origins)</option>
                      </select>
                    </div>
                  )}
                </div>

                <div style={{ borderTop: '1px solid #f1f5f9', paddingTop: '12px' }}>
                  <ToggleSwitch
                    checked={!!settings.header_nosniff}
                    onChange={(val) => setSettings({ ...settings, header_nosniff: val })}
                    label="MIME-Sniffing Defense (X-Content-Type-Options: nosniff)"
                    description="Prevents browsers from interpreting file uploads as executable scripts when disguised as images."
                    activeColor="#10b981"
                  />
                </div>

                <div style={{ borderTop: '1px solid #f1f5f9', paddingTop: '12px' }}>
                  <ToggleSwitch
                    checked={!!settings.header_referrer_policy}
                    onChange={(val) => setSettings({ ...settings, header_referrer_policy: val })}
                    label="Strict Referrer-Policy"
                    description={<span>Controls referral telemetry leaks. (Default: <code>strict-origin-when-cross-origin</code>).</span>}
                    activeColor="#10b981"
                  />
                </div>

                <div style={{ borderTop: '1px solid #f1f5f9', paddingTop: '12px' }}>
                  <ToggleSwitch
                    checked={!!settings.header_permissions_policy}
                    onChange={(val) => setSettings({ ...settings, header_permissions_policy: val })}
                    label="Hardware Permissions-Policy Restrictor"
                    description="Blocks unauthorized browser hardware sensor access (camera=(), microphone=(), geolocation=(), payment=())."
                    activeColor="#10b981"
                  />
                </div>

                <div style={{ borderTop: '1px solid #f1f5f9', paddingTop: '12px' }}>
                  <ToggleSwitch
                    checked={!!settings.header_csp_enabled}
                    onChange={(val) => setSettings({ ...settings, header_csp_enabled: val })}
                    label="Content-Security-Policy (CSP Lite)"
                    description="Advanced script execution policy. Restricts authorized content origins to eliminate script injections."
                    activeColor="#10b981"
                  />
                  {settings.header_csp_enabled && (
                    <div style={{ marginTop: '8px' }}>
                      <input
                        type="text"
                        value={settings.header_csp_custom || ''}
                        onChange={(e) => setSettings({ ...settings, header_csp_custom: e.target.value })}
                        placeholder="default-src 'self' https: data: 'unsafe-inline'; frame-ancestors 'self';"
                        style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', border: '1px solid #cbd5e1', fontSize: '12px', fontFamily: 'monospace' }}
                      />
                      <span style={{ fontSize: '11px', color: '#64748b', marginTop: '4px', display: 'block' }}>
                        Leave blank to automatically apply the baseline safe CSP preset.
                      </span>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Column 2: 1-Click Server & WordPress Hardening */}
            <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '18px' }}>
                <div style={{ background: '#fef3c7', color: '#d97706', padding: '8px', borderRadius: '8px' }}>
                  <Lock size={20} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>Runtime WordPress Hardening</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>Active runtime restrictions that eliminate common attack vectors</span>
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <ToggleSwitch
                  checked={!!settings.disable_file_editing}
                  onChange={(val) => setSettings({ ...settings, disable_file_editing: val })}
                  label={<span>Enforce <code>DISALLOW_FILE_EDIT</code> (PHP Editor Lock)</span>}
                  description="Completely disables Theme and Plugin PHP file editing in wp-admin to neutralize administrative takeover backdoors."
                  activeColor="#10b981"
                />

                <div style={{ borderTop: '1px solid #f1f5f9', paddingTop: '12px' }}>
                  <ToggleSwitch
                    checked={settings.block_user_enumeration !== false}
                    onChange={(val) => setSettings({ ...settings, block_user_enumeration: val })}
                    label="User Enumeration Shield (Author &amp; REST API)"
                    description={<span>Redirects guest scans like <code>/?author=1</code> and blocks public access to <code>/wp/v2/users</code> to protect administrator logins.</span>}
                    activeColor="#10b981"
                  />
                </div>

                <div style={{ borderTop: '1px solid #f1f5f9', paddingTop: '12px' }}>
                  <ToggleSwitch
                    checked={!!settings.waf_disable_xmlrpc}
                    onChange={(val) => setSettings({ ...settings, waf_disable_xmlrpc: val })}
                    label="Disable XML-RPC Services (xmlrpc.php)"
                    description="Blocks pingback amplification DDoS and brute-force password spraying attacks targeted at xmlrpc.php."
                    activeColor="#10b981"
                  />
                  {!!settings.waf_disable_xmlrpc && (
                    <div style={{ marginTop: '10px', marginLeft: '24px', paddingLeft: '12px', borderLeft: '2px solid #10b981' }}>
                      <ToggleSwitch
                        checked={settings.waf_allow_jetpack_xmlrpc !== false}
                        onChange={(val) => setSettings({ ...settings, waf_allow_jetpack_xmlrpc: val })}
                        label="Automattic Jetpack Smart Pass"
                        description="Safely permits authentic Jetpack synchronization by cryptographically verifying official Automattic CIDR IP ranges and signed tokens."
                        activeColor="#10b981"
                      />
                    </div>
                  )}
                </div>

                <div style={{ borderTop: '1px solid #f1f5f9', paddingTop: '12px' }}>
                  <ToggleSwitch
                    checked={!!settings.hide_wp_version}
                    onChange={(val) => setSettings({ ...settings, hide_wp_version: val })}
                    label="Information Leakage Guard (Hide WordPress Version)"
                    description="Removes WordPress generator meta tags and strips '?ver=' query strings from enqueued scripts and stylesheets."
                    activeColor="#10b981"
                  />
                </div>

                <div style={{ borderTop: '1px solid #f1f5f9', paddingTop: '12px' }}>
                  <ToggleSwitch
                    checked={!!settings.block_sensitive_files}
                    onChange={(val) => setSettings({ ...settings, block_sensitive_files: val })}
                    label="Block Sensitive System Files Access"
                    description={<span>Immediately returns 403 Forbidden on incoming requests probing for <code>.env</code>, <code>.git</code>, <code>.sql</code>, or config backups.</span>}
                    activeColor="#10b981"
                  />
                </div>

                {/* Audit Checklist Status Preview */}
                {hardeningAudit && hardeningAudit.checklist && (
                  <div style={{ marginTop: '12px', padding: '14px', background: 'var(--webcare-bg-surface, #f8fafc)', borderRadius: '10px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
                    <div style={{ fontSize: '12px', fontWeight: 700, color: '#334155', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      Active Protection Checklist:
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '6px' }}>
                      {hardeningAudit.checklist.map((item: any) => (
                        <div key={item.id} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px' }}>
                          {item.enabled ? (
                            <CheckCircle2 size={14} color="#10b981" />
                          ) : (
                            <AlertTriangle size={14} color="#94a3b8" />
                          )}
                          <span style={{ color: item.enabled ? 'var(--webcare-text-primary, #0f172a)' : 'var(--webcare-text-muted, #64748b)', fontWeight: item.enabled ? 500 : 400 }}>
                            {item.name}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {activeSubTab === 'threat_intel' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Public Threat Intelligence Feeds Moved Banner */}
          <div className="webcare-firewall-section-group" style={{ borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{ background: 'rgba(8, 145, 178, 0.12)', color: '#0891b2', padding: '10px', borderRadius: '8px', display: 'flex' }}>
                <Shield size={20} />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: '15.5px', color: 'var(--webcare-text-primary, #0f172a)' }}>Public Threat Intelligence Feeds</h3>
                <p style={{ margin: '2px 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)' }}>
                  Managed in its dedicated tab under Firewall → Threat Intel Feeds (100% pull-only, zero telemetry).
                </p>
              </div>
            </div>
            <a
              href="admin.php?page=webcare-pro-firewall&tab=intel"
              className="button button-primary"
              style={{ background: '#4f46e5', borderColor: '#4338ca', fontWeight: 600, textDecoration: 'none' }}
            >
              Open Threat Intel Feeds &rarr;
            </a>
          </div>

          {/* NIST NVD Background CVE Sync & Encrypted API Key */}
          <NistCveSyncSettingsCard apiRequest={apiRequest} />
        </div>
      )}

      {/* =========================================================================
          TAB 4: PERFORMANCE & DEVELOPER HARDENING
          ========================================================================= */}
      {activeSubTab === 'performance' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '24px' }}>
          <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px' }}>
            <h3 style={{ margin: '0 0 16px 0', fontSize: '17px', color: 'var(--webcare-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Sliders size={18} color="#0284c7" /> Scanner Engine Performance
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
                  Scan Batch Size (Files per request)
                </label>
                <select
                  value={settings.scan_batch_size}
                  onChange={(e) => setSettings({ ...settings, scan_batch_size: parseInt(e.target.value) || 50 })}
                  style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '14px', background: 'var(--webcare-bg-card, #ffffff)' }}
                >
                  <option value="25">25 files / batch (Recommended for shared/low-memory hosting)</option>
                  <option value="50">50 files / batch (Standard, Balanced)</option>
                  <option value="100">100 files / batch (High Performance VPS/Dedicated)</option>
                  <option value="200">200 files / batch (Turbo scan)</option>
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '6px' }}>
                  Dynamic Memory Safety Envelope (Visitor Uptime Protection)
                </label>
                <select
                  value={settings.scan_memory_safety_envelope || 'balanced'}
                  onChange={(e) => setSettings({ ...settings, scan_memory_safety_envelope: e.target.value })}
                  style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid var(--webcare-border, #cbd5e1)', fontSize: '14px', background: 'var(--webcare-bg-panel, #fff)', color: 'var(--webcare-text-primary, #0f172a)' }}
                >
                  <option value="strict">Strict Safety (60% Max Memory - Best for busy WooCommerce stores & shared hosting)</option>
                  <option value="balanced">Balanced Protection (70% Max Memory - Recommended, dynamically scales batch size)</option>
                  <option value="performance">High Performance (80% Max Memory - Dedicated servers & high RAM environments)</option>
                </select>
                <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px', display: 'block' }}>
                  Guarantees 30%–40% of PHP memory and CPU time is permanently reserved for active website visitors, preventing any 500 fatal errors during scans.
                </span>
              </div>

              <div>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  <input
                    type="checkbox"
                    checked={settings.scan_adaptive_throttling !== false}
                    onChange={(e) => setSettings({ ...settings, scan_adaptive_throttling: e.target.checked })}
                    style={{ borderRadius: '4px' }}
                  />
                  <span>Enable Real-Time Visitor Traffic Throttling (Micro-Sleeps &amp; Downscaling)</span>
                </label>
                <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px', display: 'block', marginLeft: '22px' }}>
                  Automatically reduces batch size and injects micro-sleep pauses when visitor traffic spikes or server RAM is tight, resuming turbo speed once memory frees.
                </span>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '6px' }}>
                  Inter-Batch CPU Throttle Delay (Micro-Pause)
                </label>
                <select
                  value={settings.scan_batch_delay_ms ?? 0}
                  onChange={(e) => setSettings({ ...settings, scan_batch_delay_ms: parseInt(e.target.value) || 0 })}
                  style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid var(--webcare-border, #cbd5e1)', fontSize: '14px', background: 'var(--webcare-bg-panel, #fff)', color: 'var(--webcare-text-primary, #0f172a)' }}
                >
                  <option value="0">0 ms (Full Turbo Speed - Cloud VPS &amp; Dedicated)</option>
                  <option value="50">50 ms (Mild Breathing Room - Standard Cloud)</option>
                  <option value="150">150 ms (Balanced - Shared Hosting / cPanel CloudLinux)</option>
                  <option value="300">300 ms (Strict CPU Throttling - Low vCPU / Budget Hosts)</option>
                  <option value="500">500 ms (Maximum Resource Preservation)</option>
                </select>
                <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px', display: 'block' }}>
                  Injects an intentional rest pause between REST batches to keep CPU utilization low and avoid hosting provider threshold alerts.
                </span>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '6px' }}>
                  Scheduled Background Execution Strategy
                </label>
                <select
                  value={settings.scan_execution_strategy || 'ajax_client'}
                  onChange={(e) => setSettings({ ...settings, scan_execution_strategy: e.target.value as any })}
                  style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid var(--webcare-border, #cbd5e1)', fontSize: '14px', background: 'var(--webcare-bg-panel, #fff)', color: 'var(--webcare-text-primary, #0f172a)' }}
                >
                  <option value="ajax_client">Interactive Client-Side Polling (Default, resilient against server gateway timeouts)</option>
                  <option value="wp_cli_cron">Autonomous WP-Cron Loop (Runs purely in background via server crontab)</option>
                  <option value="background_worker">Non-Blocking Async Worker (Spawns detached background loop)</option>
                </select>
                <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px', display: 'block' }}>
                  Select how automated scans dispatch processing chunks when running without an active browser tab.
                </span>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '6px' }}>
                  Media Uploads Library Scan Depth
                </label>
                <select
                  value={settings.scan_uploads_mode || 'deep_raster'}
                  onChange={(e) => setSettings({ ...settings, scan_uploads_mode: e.target.value as any })}
                  style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid var(--webcare-border, #cbd5e1)', fontSize: '14px', background: 'var(--webcare-bg-panel, #fff)', color: 'var(--webcare-text-primary, #0f172a)' }}
                >
                  <option value="deep_raster">Deep Raster &amp; EXIF Polyglot Audit (Thorough, inspects image headers &amp; trailing bytes)</option>
                  <option value="smart_executable">Smart Executable &amp; Stager Inspection (Fast mode, skips benign raster images)</option>
                </select>
                <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px', display: 'block' }}>
                  In Deep Raster mode, inspects image headers, embedded PHP EXIF payloads, and trailing bytes.
                </span>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '6px' }}>
                  Filesystem Symlink Traversal Policy
                </label>
                <select
                  value={settings.scan_symlink_policy || 'ignore'}
                  onChange={(e) => setSettings({ ...settings, scan_symlink_policy: e.target.value as any })}
                  style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid var(--webcare-border, #cbd5e1)', fontSize: '14px', background: 'var(--webcare-bg-panel, #fff)', color: 'var(--webcare-text-primary, #0f172a)' }}
                >
                  <option value="ignore">Ignore Symlinks (Safest - Prevents recursive symlink loops)</option>
                  <option value="follow_intree">Follow In-Tree Symlinks (Follows links resolving inside WordPress root)</option>
                  <option value="follow_all">Follow All Symlinks (Alerts on out-of-tree escapes)</option>
                </select>
                <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px', display: 'block' }}>
                  Configures directory traversal behavior for Bedrock, Roots, Composer packages, and custom symbolic links.
                </span>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
                  Temporary Memory Limit Override
                </label>
                <select
                  value={settings.memory_limit_override}
                  onChange={(e) => setSettings({ ...settings, memory_limit_override: e.target.value })}
                  style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '14px', background: 'var(--webcare-bg-card, #ffffff)' }}
                >
                  <option value="256M">256 MB</option>
                  <option value="512M">512 MB (Recommended)</option>
                  <option value="1024M">1024 MB (1 GB - Heavy Sites)</option>
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
                  Maximum File Size for Heuristic Parsing (KB)
                </label>
                <input
                  type="number"
                  value={settings.max_file_size_kb}
                  onChange={(e) => setSettings({ ...settings, max_file_size_kb: parseInt(e.target.value) || 2024 })}
                  style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '14px', background: 'var(--webcare-bg-card, #ffffff)' }}
                />
                <span style={{ fontSize: '12px', color: '#64748b', marginTop: '4px', display: 'block' }}>
                  Files larger than this limit are skipped from regex heuristic inspection to prevent out-of-memory errors.
                </span>
              </div>
            </div>
          </div>

          {/* Ignore Paths & Security Hardening Tweaks */}
          <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px' }}>
            <h3 style={{ margin: '0 0 16px 0', fontSize: '17px', color: 'var(--webcare-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Filter size={18} color="#0284c7" /> Exclusions & Developer Safeguards
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '6px' }}>
                  Excluded Paths &amp; Ignore Patterns (One per line)
                </label>
                <p style={{ margin: '0 0 8px 0', fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: '1.4' }}>
                  Configure specific directories, root folders, or file patterns to exclude from malware scans and integrity checks. All cache plugin folders, package managers, and backup directories are configurable here rather than being hardcoded in the scanner engine.
                </p>
                <textarea
                  rows={8}
                  value={settings.excluded_paths}
                  onChange={(e) => setSettings({ ...settings, excluded_paths: e.target.value })}
                  placeholder={'wp-content/cache/*\nwp-content/litespeed/*\nnode_modules/*\nvendor/*\n*.log'}
                  style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid var(--webcare-border, #cbd5e1)', background: 'var(--webcare-bg-surface, #ffffff)', color: 'var(--webcare-text-primary, #0f172a)', fontSize: '13px', fontFamily: 'monospace' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '6px' }}>
                  Database Table Exclusions (One table per line)
                </label>
                <p style={{ margin: '0 0 8px 0', fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: '1.4' }}>
                  Exclude bulky analytics, statistics, or third-party log tables from deep heuristic scanning (e.g. <code>*_actionscheduler_logs</code>, <code>*_redirection_logs</code>, <code>*_wfhits</code>).
                </p>
                <textarea
                  rows={3}
                  value={settings.scan_excluded_tables || ''}
                  onChange={(e) => setSettings({ ...settings, scan_excluded_tables: e.target.value })}
                  placeholder={'wp_actionscheduler_logs\nwp_redirection_logs\n*_wfhits\n*_matomo_*'}
                  style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid var(--webcare-border, #cbd5e1)', background: 'var(--webcare-bg-surface, #ffffff)', color: 'var(--webcare-text-primary, #0f172a)', fontSize: '13px', fontFamily: 'monospace' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '6px' }}>
                  Database Table Scan Batch Size (Rows per chunk)
                </label>
                <select
                  value={settings.scan_db_batch_size || 500}
                  onChange={(e) => setSettings({ ...settings, scan_db_batch_size: parseInt(e.target.value) || 500 })}
                  style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid var(--webcare-border, #cbd5e1)', fontSize: '14px', background: 'var(--webcare-bg-panel, #fff)', color: 'var(--webcare-text-primary, #0f172a)' }}
                >
                  <option value="100">100 rows / chunk (Conservative - Recommended for low RAM MySQL)</option>
                  <option value="250">250 rows / chunk (Balanced)</option>
                  <option value="500">500 rows / chunk (Default - Fast)</option>
                  <option value="1000">1000 rows / chunk (Turbo - Dedicated MySQL/MariaDB)</option>
                </select>
                <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px', display: 'block' }}>
                  Controls cursor batch limit for scanning post content, comments, and meta tables without SQL timeouts.
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', paddingTop: '10px', borderTop: '1px solid #f1f5f9' }}>
                <ToggleSwitch
                  checked={settings.scan_skip_vcs !== false}
                  onChange={(val) => setSettings({ ...settings, scan_skip_vcs: val })}
                  label={<span>Fast-Skip VCS Repositories (<code>.git</code>, <code>.svn</code>, <code>.hg</code>)</span>}
                  description="Bypasses deep inspection into version control internal git objects and metadata trees to conserve scan time."
                />

                <ToggleSwitch
                  checked={settings.scan_skip_vendor !== false}
                  onChange={(val) => setSettings({ ...settings, scan_skip_vendor: val })}
                  label={<span>Skip Node.js &amp; Package Manager Dirs (<code>node_modules</code>, <code>bower_components</code>)</span>}
                  description="Automatically skips massive nested node_modules hierarchies from scanning."
                />

                <ToggleSwitch
                  checked={settings.scan_skip_cache !== false}
                  onChange={(val) => setSettings({ ...settings, scan_skip_cache: val })}
                  label={<span>Skip Static Page Builder &amp; Minification Caches</span>}
                  description="Bypasses ephemeral cache folders (e.g. wp-content/cache/*, elementor/css/*) that are regularly purged and regenerated."
                />

                <ToggleSwitch
                  checked={!!settings.scan_profiling_enabled}
                  onChange={(val) => setSettings({ ...settings, scan_profiling_enabled: val })}
                  label="Enable Developer Scan Benchmarking &amp; Engine Profiling"
                  description="Logs millisecond execution timing breakdowns per file and engine in scan diagnostics to identify performance bottlenecks."
                />

                <ToggleSwitch
                  checked={!!settings.scan_dry_run_mode}
                  onChange={(val) => setSettings({ ...settings, scan_dry_run_mode: val })}
                  label="Developer Dry-Run Audit Mode (Testing &amp; CI/CD)"
                  description="Runs full security scanners without updating risk scores or altering quarantine records, useful for testing staging environments."
                />

                <ToggleSwitch
                  checked={settings.disable_file_editing}
                  onChange={(val) => setSettings({ ...settings, disable_file_editing: val })}
                  label={<span>Advise <code>DISALLOW_FILE_EDIT</code> in Theme &amp; Plugin Editor</span>}
                  description="Flags warning if internal WordPress PHP file editors are enabled, protecting against administrative account takeovers."
                />

                <ToggleSwitch
                  checked={settings.hide_wp_version}
                  onChange={(val) => setSettings({ ...settings, hide_wp_version: val })}
                  label="Hide WordPress Generator Version Tag"
                  description="Strips the public WordPress generator meta tag from site HTML source to deter automated bot scanning."
                />

                <ToggleSwitch
                  checked={settings.block_sensitive_files}
                  onChange={(val) => setSettings({ ...settings, block_sensitive_files: val })}
                  label={<span>Audit &amp; Alert on Exposed Sensitive Files</span>}
                  description={<span>Checks and alerts if exposed <code>.env</code>, <code>.git</code>, or backup SQL dumps are accessible over public HTTP.</span>}
                />

                <div style={{ marginTop: '6px' }}>
                  <ToggleSwitch
                    checked={!!settings.delete_data_on_uninstall}
                    onChange={(val) => setSettings({ ...settings, delete_data_on_uninstall: val })}
                    label="Auto-Remove All Database Tables &amp; Data on Uninstall"
                    description={<span>Completely drops all custom database tables, options, and backups upon plugin deletion. (Disabled by default to retain quarantine files and settings; configurable in <a href="#cleanup" onClick={(e) => { e.preventDefault(); setActiveSubTab('cleanup'); }} style={{ color: '#dc2626', fontWeight: 600, textDecoration: 'underline' }}>Data &amp; Cleanup</a>).</span>}
                    activeColor="#e11d48"
                  />
                </div>
              </div>
            </div>
          </div>

          {/* False-Positive Tuning & Engine Confidence Thresholds */}
          <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px', gridColumn: '1 / -1' }}>
            <h3 style={{ margin: '0 0 8px 0', fontSize: '17px', color: 'var(--webcare-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Filter size={18} color="#0284c7" /> False-Positive Tuning &amp; Engine Confidence Thresholds
            </h3>
            <p style={{ margin: '0 0 20px 0', fontSize: '13px', color: '#64748b' }}>
              Fine-tune the minimum confidence percentage required for each detection engine to flag security findings. Lower values catch edge cases; higher values eliminate benign false positives.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '20px' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <label style={{ fontSize: '13px', fontWeight: 600, color: '#334155' }}>Filesystem Heuristic Engine</label>
                  <span style={{ fontSize: '13px', fontWeight: 700, color: '#0284c7' }}>{settings.confidence_threshold_filesystem ?? 50}%</span>
                </div>
                <input
                  type="range"
                  min="10"
                  max="95"
                  step="5"
                  value={settings.confidence_threshold_filesystem ?? 50}
                  onChange={(e) => setSettings({ ...settings, confidence_threshold_filesystem: parseInt(e.target.value) })}
                  style={{ width: '100%', accentColor: '#0284c7' }}
                />
                <span style={{ fontSize: '11px', color: '#64748b' }}>Threshold for regex signatures, webshell patterns, and suspicious eval blocks (Default: 50%).</span>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <label style={{ fontSize: '13px', fontWeight: 600, color: '#334155' }}>Living-off-the-Land (LotL) Hooks</label>
                  <span style={{ fontSize: '13px', fontWeight: 700, color: '#0284c7' }}>{settings.confidence_threshold_lotl ?? 60}%</span>
                </div>
                <input
                  type="range"
                  min="20"
                  max="95"
                  step="5"
                  value={settings.confidence_threshold_lotl ?? 60}
                  onChange={(e) => setSettings({ ...settings, confidence_threshold_lotl: parseInt(e.target.value) })}
                  style={{ width: '100%', accentColor: '#0284c7' }}
                />
                <span style={{ fontSize: '11px', color: '#64748b' }}>Threshold for dynamic filter tampering, anonymous closures, and hijacked admin hooks (Default: 60%).</span>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <label style={{ fontSize: '13px', fontWeight: 600, color: '#334155' }}>AI Code De-obfuscation</label>
                  <span style={{ fontSize: '13px', fontWeight: 700, color: '#0284c7' }}>{settings.confidence_threshold_ai ?? 70}%</span>
                </div>
                <input
                  type="range"
                  min="30"
                  max="95"
                  step="5"
                  value={settings.confidence_threshold_ai ?? 70}
                  onChange={(e) => setSettings({ ...settings, confidence_threshold_ai: parseInt(e.target.value) })}
                  style={{ width: '100%', accentColor: '#0284c7' }}
                />
                <span style={{ fontSize: '11px', color: '#64748b' }}>Minimum LLM probability score required before confirming malicious backdoor payload (Default: 70%).</span>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <label style={{ fontSize: '13px', fontWeight: 600, color: '#334155' }}>Database Infiltration Engine</label>
                  <span style={{ fontSize: '13px', fontWeight: 700, color: '#0284c7' }}>{settings.confidence_threshold_db ?? 50}%</span>
                </div>
                <input
                  type="range"
                  min="10"
                  max="95"
                  step="5"
                  value={settings.confidence_threshold_db ?? 50}
                  onChange={(e) => setSettings({ ...settings, confidence_threshold_db: parseInt(e.target.value) })}
                  style={{ width: '100%', accentColor: '#0284c7' }}
                />
                <span style={{ fontSize: '11px', color: '#64748b' }}>Threshold for autoload transients, rogue administrator roles, and SQL injections (Default: 50%).</span>
              </div>
            </div>

            <div style={{ marginTop: '20px', paddingTop: '16px', borderTop: '1px solid #f1f5f9' }}>
              <ToggleSwitch
                checked={settings.auto_suppress_whitelisted !== false}
                onChange={(val) => setSettings({ ...settings, auto_suppress_whitelisted: val })}
                label="Auto-Suppress Whitelisted Findings from Security Posture &amp; Risk Score"
                description="When enabled, whitelisted files and developer-approved signatures are automatically silenced from active threat notifications and risk calculations."
                activeColor="#059669"
              />
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB 5: SETTINGS IMPORT & EXPORT
          ========================================================================= */}
      {activeSubTab === 'import_export' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '24px' }}>
          {/* Export Card */}
          <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <div style={{ background: '#ecfdf5', color: '#059669', padding: '10px', borderRadius: '8px' }}>
                <Download size={20} />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: '17px', color: 'var(--webcare-text-primary, #0f172a)' }}>Export Security Settings</h3>
                <p style={{ margin: 0, fontSize: '13px', color: '#64748b' }}>Download complete configuration as a JSON file</p>
              </div>
            </div>

            <p style={{ fontSize: '13px', color: '#475569', lineHeight: 1.6, marginBottom: '20px' }}>
              Ideal for WordPress agencies and developers managing multiple client websites. Export your calibrated scan schedules, email alert recipients, and exclusion rules to quickly deploy uniform security across all sites.
            </p>

            <button
              type="button"
              className="webcare-btn webcare-btn-primary"
              style={{ background: '#059669', color: '#fff', fontSize: '14px', padding: '10px 20px', width: '100%', justifyContent: 'center' }}
              onClick={handleExport}
            >
              <Download size={16} /> Export Settings to JSON
            </button>
          </div>

          {/* Import Card */}
          <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <div style={{ background: '#eff6ff', color: '#2563eb', padding: '10px', borderRadius: '8px' }}>
                <Upload size={20} />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: '17px', color: 'var(--webcare-text-primary, #0f172a)' }}>Import Security Settings</h3>
                <p style={{ margin: 0, fontSize: '13px', color: '#64748b' }}>Upload a settings JSON backup to restore configurations</p>
              </div>
            </div>

            <p style={{ fontSize: '13px', color: '#475569', lineHeight: 1.6, marginBottom: '20px' }}>
              Select a previously exported <code>webcare-security-settings-*.json</code> configuration file to instantly apply schedule, email, and scan performance settings.
            </p>

            {importStatus && (
              <div style={{ padding: '10px 14px', background: '#ecfdf5', color: '#065f46', border: '1px solid #a7f3d0', borderRadius: '8px', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
                <CheckCircle2 size={16} color="#10b981" />
                <span>{importStatus}</span>
              </div>
            )}

            {isTemporarySupport ? (
              <div style={{ padding: '14px 16px', borderRadius: '8px', background: 'rgba(239, 68, 68, 0.06)', border: '1px dashed rgba(239, 68, 68, 0.3)', color: '#dc2626', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Lock size={16} />
                <span>Importing settings is locked for temporary support accounts under Zero-Trust policies.</span>
              </div>
            ) : (
              <div style={{ position: 'relative' }}>
                <input
                  type="file"
                  accept=".json"
                  onChange={handleImportFile}
                  disabled={importing}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '2px dashed #cbd5e1',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    background: 'var(--webcare-bg-surface, #f8fafc)',
                    fontSize: '13px'
                  }}
                />
                {importing && (
                  <div style={{ marginTop: '8px', display: 'flex', alignItems: 'center', gap: '8px', color: '#2563eb', fontSize: '13px' }}>
                    <Loader2 size={14} className="webcare-spin-icon" /> Importing configuration...
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB 6: DATA PRIVACY & CLEAN UNINSTALL
          ========================================================================= */}
      {(activeSubTab === 'cleanup' || activeSubTab === 'activity_logs') && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '24px' }}>
          {/* Main Card: Uninstall & Data Purge */}
          <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <div style={{ background: '#fef2f2', color: '#dc2626', padding: '10px', borderRadius: '8px' }}>
                <Trash2 size={20} />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: '17px', color: 'var(--webcare-text-primary, #0f172a)' }}>Data Removal on Plugin Deletion</h3>
                <p style={{ margin: 0, fontSize: '13px', color: '#64748b' }}>Configure automatic database & file purge upon uninstallation</p>
              </div>
            </div>

            {/* Main Toggle Box */}
            <div style={{ marginBottom: '20px' }}>
              <ToggleSwitch
                checked={!!settings.delete_data_on_uninstall}
                onChange={(val) => setSettings({ ...settings, delete_data_on_uninstall: val })}
                label="Auto-Remove All Data on Plugin Deletion"
                description={
                  <span>
                    By default, this is disabled so your <strong>quarantined malware vault</strong>, firewall rules, and security history remain safe if you deactivate or reinstall the plugin. Enable this only if you want to permanently purge all data on deletion.
                  </span>
                }
                activeColor="#e11d48"
                badge={
                  <span style={{ fontSize: '11px', background: settings.delete_data_on_uninstall ? '#ffe4e6' : '#ecfdf5', color: settings.delete_data_on_uninstall ? '#be123c' : '#047857', padding: '2px 8px', borderRadius: '4px', fontWeight: 700 }}>
                    {settings.delete_data_on_uninstall ? 'PURGE ACTIVE' : 'RETAIN ALL DATA (SAFE)'}
                  </span>
                }
              />
            </div>

            {/* Current Status Badge */}
            <div
              className={`webcare-settings-callout ${settings.delete_data_on_uninstall ? 'webcare-settings-callout-warning' : 'webcare-settings-callout-success'}`}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '12px 16px',
                borderRadius: '8px',
                fontSize: '13px',
                fontWeight: 600,
                marginBottom: '20px'
              }}
            >
              {settings.delete_data_on_uninstall ? <AlertTriangle size={16} /> : <CheckCircle2 size={16} />}
              <span className="webcare-settings-callout-title" style={{ fontSize: '13px' }}>
                {settings.delete_data_on_uninstall
                  ? 'Warning: All quarantine vaults, virtual patches, and database records will be erased if deleted.'
                  : 'Protected (Default): All quarantine vaults, rollback snapshots, and scan configurations are preserved across reinstallation.'}
              </span>
            </div>

            {/* Breakdown of what gets purged with Developer Freedom Checkboxes */}
            <div style={{ marginBottom: '24px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                <h4 className="webcare-settings-subcard-title" style={{ margin: 0, fontSize: '14px', fontWeight: 700 }}>
                  Select Components to Purge on Deletion:
                </h4>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    type="button"
                    onClick={() => setSettings({
                      ...settings,
                      uninstall_drop_tables: true,
                      uninstall_delete_options: true,
                      uninstall_delete_crons: true,
                      uninstall_delete_uploads: true,
                    })}
                    className="webcare-btn-micro"
                    style={{ fontSize: '11px', padding: '2px 8px', cursor: 'pointer' }}
                  >
                    Select All
                  </button>
                  <button
                    type="button"
                    onClick={() => setSettings({
                      ...settings,
                      uninstall_drop_tables: false,
                      uninstall_delete_options: false,
                      uninstall_delete_crons: false,
                      uninstall_delete_uploads: false,
                    })}
                    className="webcare-btn-micro"
                    style={{ fontSize: '11px', padding: '2px 8px', cursor: 'pointer' }}
                  >
                    Deselect All
                  </button>
                </div>
              </div>

              <div className="webcare-settings-item-list" style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13px' }}>
                {/* 1. Custom Database Tables */}
                <label
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '10px',
                    padding: '10px 12px',
                    borderRadius: '8px',
                    border: '1px solid var(--webcare-border, #e2e8f0)',
                    background: (settings.uninstall_drop_tables ?? true) ? 'rgba(239, 68, 68, 0.04)' : 'transparent',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <input
                    type="checkbox"
                    checked={settings.uninstall_drop_tables ?? true}
                    onChange={(e) => setSettings({ ...settings, uninstall_drop_tables: e.target.checked })}
                    style={{ marginTop: '3px', accentColor: '#dc2626', width: '16px', height: '16px', cursor: 'pointer' }}
                  />
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Database size={15} color="#ef4444" />
                      <strong className="webcare-settings-highlight-text">Custom Database Tables</strong>
                      <span className="webcare-badge-pill webcare-badge-danger" style={{ fontSize: '10px', padding: '1px 6px' }}>4 Core Tables</span>
                    </div>
                    <div style={{ fontSize: '12px', color: '#64748b', marginTop: '3px', lineHeight: 1.4 }}>
                      Drops <code>wp_webcareproscan_scans</code>, <code>wp_webcareproscan_scan_issues</code>, <code>wp_webcareproscan_scan_files</code>, <code>wp_webcareproscan_quarantine</code>.
                    </div>
                  </div>
                </label>

                {/* 2. Options & API Keys */}
                <label
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '10px',
                    padding: '10px 12px',
                    borderRadius: '8px',
                    border: '1px solid var(--webcare-border, #e2e8f0)',
                    background: (settings.uninstall_delete_options ?? true) ? 'rgba(239, 68, 68, 0.04)' : 'transparent',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <input
                    type="checkbox"
                    checked={settings.uninstall_delete_options ?? true}
                    onChange={(e) => setSettings({ ...settings, uninstall_delete_options: e.target.checked })}
                    style={{ marginTop: '3px', accentColor: '#dc2626', width: '16px', height: '16px', cursor: 'pointer' }}
                  />
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Key size={15} color="#ef4444" />
                      <strong className="webcare-settings-highlight-text">Options, API Keys &amp; Transients</strong>
                    </div>
                    <div style={{ fontSize: '12px', color: '#64748b', marginTop: '3px', lineHeight: 1.4 }}>
                      Deletes <code>webcareproscan_settings</code>, <code>webcareproscan_db_version</code>, Cloudflare/AI keys, and temporary cache transients.
                    </div>
                  </div>
                </label>

                {/* 3. WP-Cron Schedules */}
                <label
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '10px',
                    padding: '10px 12px',
                    borderRadius: '8px',
                    border: '1px solid var(--webcare-border, #e2e8f0)',
                    background: (settings.uninstall_delete_crons ?? true) ? 'rgba(239, 68, 68, 0.04)' : 'transparent',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <input
                    type="checkbox"
                    checked={settings.uninstall_delete_crons ?? true}
                    onChange={(e) => setSettings({ ...settings, uninstall_delete_crons: e.target.checked })}
                    style={{ marginTop: '3px', accentColor: '#dc2626', width: '16px', height: '16px', cursor: 'pointer' }}
                  />
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Clock size={15} color="#ef4444" />
                      <strong className="webcare-settings-highlight-text">WP-Cron Scheduled Events</strong>
                    </div>
                    <div style={{ fontSize: '12px', color: '#64748b', marginTop: '3px', lineHeight: 1.4 }}>
                      Clears recurring background scans, threat intelligence synchronization, and log retention prune cron jobs.
                    </div>
                  </div>
                </label>

                {/* 4. Upload Storage Directory */}
                <label
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '10px',
                    padding: '10px 12px',
                    borderRadius: '8px',
                    border: '1px solid var(--webcare-border, #e2e8f0)',
                    background: (settings.uninstall_delete_uploads ?? true) ? 'rgba(239, 68, 68, 0.04)' : 'transparent',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <input
                    type="checkbox"
                    checked={settings.uninstall_delete_uploads ?? true}
                    onChange={(e) => setSettings({ ...settings, uninstall_delete_uploads: e.target.checked })}
                    style={{ marginTop: '3px', accentColor: '#dc2626', width: '16px', height: '16px', cursor: 'pointer' }}
                  />
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Trash2 size={15} color="#ef4444" />
                      <strong className="webcare-settings-highlight-text">Upload Storage Directory</strong>
                      <span className="webcare-badge-pill webcare-badge-warning" style={{ fontSize: '10px', padding: '1px 6px' }}>Quarantine Vault &amp; Backups</span>
                    </div>
                    <div style={{ fontSize: '12px', color: '#64748b', marginTop: '3px', lineHeight: 1.4 }}>
                      Purges <code>uploads/webcare-pro-security/</code> containing daily JSON WAF logs, encrypted quarantine vaults, and rollback archives.
                    </div>
                  </div>
                </label>
              </div>
            </div>

            <button
              type="button"
              className="webcare-btn webcare-btn-primary"
              style={{ background: '#0284c7', color: '#fff', fontSize: '13px', padding: '9px 20px', width: '100%', justifyContent: 'center' }}
              onClick={() => handleSave()}
              disabled={saving}
            >
              {saving ? <Loader2 size={15} className="webcare-spin-icon" /> : <Save size={15} />}
              {saving ? 'Saving...' : 'Save Uninstall Preferences'}
            </button>
          </div>

          {/* Secondary Card: WordPress Lifecycle Policy */}
          <div className="webcare-card" style={{ borderRadius: '12px', padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <div style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#10b981', padding: '10px', borderRadius: '8px' }}>
                <ShieldCheck size={20} />
              </div>
              <div>
                <h3 className="webcare-settings-subcard-title" style={{ margin: 0, fontSize: '17px', fontWeight: 700 }}>WordPress Lifecycle &amp; Safety</h3>
                <p className="webcare-settings-subcard-desc" style={{ margin: 0, fontSize: '13px' }}>Best practice data retention policies</p>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', fontSize: '13px' }}>
              <div className="webcare-settings-inner-box" style={{ padding: '14px', borderRadius: '8px' }}>
                <strong className="webcare-settings-inner-box-title" style={{ display: 'block', marginBottom: '4px' }}>
                  Temporary Plugin Deactivation
                </strong>
                <span className="webcare-settings-inner-box-desc">
                  Deactivating the plugin (via the "Deactivate" link) pauses background scan crons but <strong>never</strong> deletes any data or tables. This allows you to safely troubleshoot plugin conflicts or update without data loss.
                </span>
              </div>

              <div className="webcare-settings-inner-box" style={{ padding: '14px', borderRadius: '8px' }}>
                <strong className="webcare-settings-inner-box-title" style={{ display: 'block', marginBottom: '4px' }}>
                  Permanent Plugin Deletion (Uninstall)
                </strong>
                <span className="webcare-settings-inner-box-desc">
                  When you click "Delete" in WordPress, WordPress triggers <code>uninstall.php</code>. If the option on the left is active, the entire footprint is cleanly removed, keeping your WordPress database 100% lean and tidy.
                </span>
              </div>

              <div className="webcare-settings-advisory-box" style={{ padding: '14px', borderRadius: '8px' }}>
                <strong className="webcare-settings-advisory-title" style={{ display: 'block', marginBottom: '4px' }}>
                  Multi-Site &amp; Staging Migration Advisory
                </strong>
                <span className="webcare-settings-advisory-desc">
                  If you are migrating or spinning up staging sites, you can export your settings and configuration from the <strong>Import &amp; Export</strong> tab first before uninstalling.
                </span>
              </div>
            </div>
          </div>

          {/* Third Card: WAF Incident Log Retention on Filesystem */}
          <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px', display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <div style={{ background: '#eef2ff', color: '#4f46e5', padding: '10px', borderRadius: '8px' }}>
                <Clock size={20} />
              </div>
              <div>
                <h3 className="webcare-settings-subcard-title" style={{ margin: 0, fontSize: '17px', fontWeight: 700 }}>WAF Incident Log Retention</h3>
                <p className="webcare-settings-subcard-desc" style={{ margin: 0, fontSize: '13px' }}>Filesystem storage retention policy</p>
              </div>
            </div>

            {/* Status Highlight */}
            <div
              className="webcare-settings-inner-box"
              style={{
                padding: '12px 14px',
                borderRadius: '8px',
                marginBottom: '18px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '8px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <CheckCircle2 size={16} color="#10b981" />
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>Zero-SQL Daily JSON Partitions</span>
              </div>
              <span className="webcare-badge-pill" style={{ background: '#ecfdf5', color: '#047857', border: '1px solid #a7f3d0', fontSize: '11px', padding: '2px 8px', borderRadius: '4px', fontWeight: 700 }}>
                Default: 60 Days
              </span>
            </div>

            {/* Retention Control Form */}
            <div style={{ marginBottom: '18px', flex: 1 }}>
              <label htmlFor="webcare-waf-log-retention-select" style={{ display: 'block', fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '6px' }}>
                Retain Daily WAF Logs For:
              </label>
              <select
                id="webcare-waf-log-retention-select"
                value={settings?.waf_log_retention_days ?? 60}
                onChange={(e) => setSettings(settings ? { ...settings, waf_log_retention_days: Number(e.target.value) } : null)}
                className="webcare-input"
                style={{ fontSize: '13px', padding: '9px 12px', borderRadius: '8px', width: '100%', fontWeight: 600, marginBottom: '8px' }}
                title="Select WAF incident log retention period"
              >
                <option value={7}>7 Days (1 Week)</option>
                <option value={14}>14 Days (2 Weeks)</option>
                <option value={30}>30 Days (1 Month)</option>
                <option value={60}>60 Days (2 Months - Recommended)</option>
                <option value={90}>90 Days (3 Months)</option>
                <option value={180}>180 Days (6 Months)</option>
                <option value={365}>365 Days (1 Year)</option>
                <option value={0}>Keep Forever (Unlimited)</option>
              </select>
              <p style={{ margin: 0, fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5 }}>
                Daily JSON files older than this threshold are automatically pruned by daily WP-Cron to maintain a lean storage footprint.
              </p>
            </div>

            {/* Storage Directory Info Box */}
            <div className="webcare-settings-advisory-box" style={{ padding: '12px 14px', borderRadius: '8px', marginBottom: '20px', fontSize: '12px' }}>
              <strong className="webcare-settings-advisory-title" style={{ display: 'block', marginBottom: '4px' }}>
                Hardened Storage Directory
              </strong>
              <span className="webcare-settings-advisory-desc" style={{ wordBreak: 'break-all' }}>
                <code>uploads/webcare-pro-security/waf-logs/</code> protected by zero-execution <code>.htaccess</code> and index silencing.
              </span>
            </div>

            <button
              type="button"
              className="webcare-btn webcare-btn-primary"
              style={{ background: '#4f46e5', color: '#fff', fontSize: '13px', padding: '9px 20px', width: '100%', justifyContent: 'center' }}
              onClick={() => handleSave()}
              disabled={saving}
            >
              {saving ? <Loader2 size={15} className="webcare-spin-icon" /> : <Save size={15} />}
              {saving ? 'Saving...' : 'Save Retention Policy'}
            </button>
          </div>

          {/* Fourth Card: Plugin Activity & Forensic Audit Logs Engine */}
          <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '24px', display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <div style={{ background: '#e0f2fe', color: '#0284c7', padding: '10px', borderRadius: '8px' }}>
                <Activity size={20} />
              </div>
              <div>
                <h3 className="webcare-settings-subcard-title" style={{ margin: 0, fontSize: '17px', fontWeight: 700 }}>Plugin Activity &amp; Audit Logs</h3>
                <p className="webcare-settings-subcard-desc" style={{ margin: 0, fontSize: '13px' }}>Cryptographic audit trail with AES-256-GCM AEAD encryption</p>
              </div>
            </div>

            {/* Status Highlight */}
            <div
              className="webcare-settings-inner-box"
              style={{
                padding: '12px 14px',
                borderRadius: '8px',
                marginBottom: '18px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '8px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <CheckCircle2 size={16} color="#0284c7" />
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>Continuous SHA-256 Hash Chain</span>
              </div>
              <span className="webcare-badge-pill" style={{ background: '#e0f2fe', color: '#0369a1', border: '1px solid #bae6fd', fontSize: '11px', padding: '2px 8px', borderRadius: '4px', fontWeight: 700 }}>
                Minimum: 7-Day Immutability
              </span>
            </div>

            {/* Retention Control Form */}
            <div style={{ marginBottom: '18px', flex: 1 }}>
              <label htmlFor="webcare-activity-log-retention-select" style={{ display: 'block', fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '6px' }}>
                Audit Log Retention Policy:
              </label>
              <select
                id="webcare-activity-log-retention-select"
                value={(settings as any)?.activity_log_settings?.retention_days ?? 30}
                onChange={(e) => {
                  const val = Number(e.target.value);
                  const existingAct = (settings as any)?.activity_log_settings || {};
                  setSettings(settings ? {
                    ...settings,
                    activity_log_settings: {
                      ...existingAct,
                      retention_days: val,
                    }
                  } as any : null);
                }}
                className="webcare-input"
                style={{ fontSize: '13px', padding: '9px 12px', borderRadius: '8px', width: '100%', fontWeight: 600, marginBottom: '8px' }}
                title="Select forensic audit log retention period"
              >
                <option value={7}>7 Days (Strict Forensic Immutability Floor)</option>
                <option value={14}>14 Days (2 Weeks)</option>
                <option value={30}>30 Days (1 Month - Recommended)</option>
                <option value={60}>60 Days (2 Months)</option>
                <option value={90}>90 Days (Quarterly Compliance)</option>
                <option value={180}>180 Days (6 Months)</option>
                <option value={365}>365 Days (1 Year SOC2 / ISO)</option>
                <option value={0}>Keep Forever (Unlimited Audit Ledger)</option>
              </select>
              <p style={{ margin: 0, fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5 }}>
                Partitions younger than 7 days are strictly immutable and cannot be pruned even by administrators. Older partitions are securely archived with checkpoint verification ledgers.
              </p>
            </div>

            {/* Storage Directory Info Box */}
            <div className="webcare-settings-advisory-box" style={{ padding: '12px 14px', borderRadius: '8px', marginBottom: '20px', fontSize: '12px' }}>
              <strong className="webcare-settings-advisory-title" style={{ display: 'block', marginBottom: '4px' }}>
                Encrypted Storage &amp; Tamper Defense
              </strong>
              <span className="webcare-settings-advisory-desc" style={{ wordBreak: 'break-all' }}>
                Protected in <code>uploads/webcare-pro-security/.activity-logs/</code> via direct PHP death-guards, zero execution headers, and automated tamper incident notifications.
              </span>
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <button
                type="button"
                className="webcare-btn webcare-btn-primary"
                style={{ background: '#0284c7', color: '#fff', fontSize: '13px', padding: '9px 16px', flex: 1, justifyContent: 'center' }}
                onClick={() => handleSave()}
                disabled={saving}
              >
                {saving ? <Loader2 size={15} className="webcare-spin-icon" /> : <Save size={15} />}
                {saving ? 'Saving...' : 'Save Audit Policy'}
              </button>
              <button
                type="button"
                className="webcare-btn"
                style={{
                  background: 'var(--webcare-bg-surface-elevated, #f1f5f9)',
                  color: 'var(--webcare-text-primary, #0f172a)',
                  border: '1px solid var(--webcare-border, #cbd5e1)',
                  fontSize: '13px',
                  padding: '9px 14px',
                  borderRadius: '8px',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  cursor: 'pointer',
                  whiteSpace: 'nowrap'
                }}
                onClick={() => {
                  if (onNavigateToActivityLogs) {
                    onNavigateToActivityLogs();
                  } else {
                    window.location.href = 'admin.php?page=webcare-pro-logs&tab=activity';
                  }
                }}
                title="Launch Live Forensic Audit & Activity Log Viewer"
              >
                <Activity size={14} color="#0284c7" />
                <span>Open Stream →</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB: DEDICATED SUPPORT & SOCIAL CHANNELS
          ========================================================================= */}
      {activeSubTab === 'support' && (() => {
        const rawSiteUrl = (window as any).webcareScannerSettings?.siteUrl || window.location.origin || '';
        const siteName = (window as any).webcareScannerSettings?.siteName || (document.title ? document.title.split('‹')[0].replace('Dashboard', '').trim() : 'My WordPress Site') || 'My WordPress Site';
        let domain = '';
        try {
          domain = new URL(rawSiteUrl || window.location.href).hostname;
        } catch (e) {
          domain = window.location.hostname || '';
        }

        const prebuiltWhatsappUrl = `https://wa.me/8801322691090?text=${encodeURIComponent(
          `Hello WebCare Pro, I need technical assistance with my website "${siteName}" (${domain || rawSiteUrl}).`
        )}`;

        const prebuiltEmailUrl = `mailto:hello@webcarepro.dev?subject=${encodeURIComponent(
          `Inquiry regarding ${siteName} (${domain || rawSiteUrl}) - WebCare Pro Security & Firewall Support`
        )}&body=${encodeURIComponent(
          `Hello Mir Alamin (WebCare Pro),\n\nI need technical assistance regarding WebCare Pro Security & Firewall on my WordPress site.\n\nWebsite Title: ${siteName}\nDomain / URL: ${domain || rawSiteUrl}\nIssue / Question:\n\nThank you!`
        )}`;

        const UPWORK_PROFILE_URL = 'https://www.upwork.com/freelancers/~0162afa9a578170c67';
        const TEAMS_INVITE_URL = 'https://teams.live.com/l/invite/FEAI60zv48mwbIKhA?v=g1';

        const socialChannels = [
          {
            title: 'WhatsApp (Instant Chat)',
            handle: '+880 1322 691090',
            description: 'Instant direct messaging with a pre-formatted diagnostic inquiry for this site.',
            badge: 'Fastest Response',
            badgeBg: '#dcfce7',
            badgeColor: '#15803d',
            icon: Phone,
            href: prebuiltWhatsappUrl,
            btnText: 'Chat on WhatsApp',
            btnBg: '#25D366',
            btnColor: '#ffffff'
          },
          {
            title: 'Direct Support Email',
            handle: 'hello@webcarepro.dev',
            description: 'Direct email support with automated diagnostic context pre-filled.',
            badge: 'Official Desk',
            badgeBg: '#fee2e2',
            badgeColor: '#b91c1c',
            icon: Mail,
            href: prebuiltEmailUrl,
            btnText: 'Send Support Email',
            btnBg: '#EA4335',
            btnColor: '#ffffff'
          },
          {
            title: 'Upwork Top Rated Plus Profile',
            handle: 'Mir Alamin (100% Job Success)',
            description: 'Hire our certified Senior Linux SysAdmin with escrow protection and guaranteed delivery.',
            badge: 'Top Rated Plus',
            badgeBg: '#f0fdf4',
            badgeColor: '#16a34a',
            icon: Star,
            href: UPWORK_PROFILE_URL,
            btnText: 'View Upwork Profile',
            btnBg: '#14a800',
            btnColor: '#ffffff'
          },
          {
            title: 'Microsoft Teams Meeting',
            handle: 'Live Audio/Video Session',
            description: 'Schedule or join a live screen-share consultation for complex security audits.',
            badge: 'Screen Share',
            badgeBg: '#ede9fe',
            badgeColor: '#6d28d9',
            icon: Users,
            href: TEAMS_INVITE_URL,
            btnText: 'Join on MS Teams',
            btnBg: '#6264a7',
            btnColor: '#ffffff'
          },
          {
            title: 'GitHub Organization',
            handle: 'github.com/WebCarePro',
            description: 'Explore our open-source tools, issue tracker, and public security repositories.',
            badge: 'Open Source',
            badgeBg: '#f1f5f9',
            badgeColor: '#334155',
            icon: Globe,
            href: 'https://github.com/WebCarePro',
            btnText: 'Visit GitHub Org',
            btnBg: 'var(--webcare-primary, #4f46e5)',
            btnColor: '#ffffff'
          },
          {
            title: 'WebCare Pro Official Website',
            handle: 'webcarepro.dev',
            description: 'Discover enterprise speed tuning, hack recovery, and dedicated cloud server management.',
            badge: 'Enterprise Firm',
            badgeBg: '#e0f2fe',
            badgeColor: '#0369a1',
            icon: Globe,
            href: 'https://webcarepro.dev',
            btnText: 'Visit webcarepro.dev',
            btnBg: '#0284c7',
            btnColor: '#ffffff'
          }
        ];

        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            {/* Hero Support Banner */}
            <div className="webcare-settings-support-hero" style={{
              borderRadius: '16px',
              padding: '28px 32px',
              position: 'relative',
              overflow: 'hidden'
            }}>
              <div style={{ maxWidth: '780px', position: 'relative', zIndex: 1 }}>
                <div className="webcare-settings-support-pill" style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '4px 12px',
                  borderRadius: '20px',
                  fontSize: '12px',
                  fontWeight: 600,
                  marginBottom: '14px'
                }}>
                  <LifeBuoy size={14} /> Official WebCare Pro Support Desk
                </div>

                <h2 className="webcare-settings-support-hero-title" style={{ margin: '0 0 10px 0', fontSize: '24px', fontWeight: 800, letterSpacing: '-0.02em' }}>
                  Direct Expert Support &amp; Technical Assistance
                </h2>

                <p className="webcare-settings-support-hero-desc" style={{ margin: 0, fontSize: '14px', lineHeight: 1.6 }}>
                  Have questions about WebCare Pro Security & Firewall, dealing with an emergency webshell infection, or need custom server hardening? Connect with Mir Alamin directly for 1-on-1 expert technical assistance.
                </p>
              </div>
            </div>

            {/* Prebuilt Quick Dispatch Card */}
            <div className="webcare-card" style={{
              background: 'var(--webcare-bg-surface, #f8fafc)',
              border: '1px solid #cbd5e1',
              borderRadius: '14px',
              padding: '20px 24px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '16px'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                <div style={{
                  background: '#25D366',
                  color: '#ffffff',
                  width: '44px',
                  height: '44px',
                  borderRadius: '12px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 2px 8px rgba(37, 211, 102, 0.3)'
                }}>
                  <Phone size={22} />
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                      1-Click WhatsApp Support with Pre-Built Diagnostic Context
                    </h4>
                    <span style={{ fontSize: '11px', background: '#dcfce7', color: '#15803d', padding: '2px 8px', borderRadius: '10px', fontWeight: 600 }}>
                      Instant
                    </span>
                  </div>
                  <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#64748b' }}>
                    Clicking launches WhatsApp with your site name (<strong style={{ color: '#334155' }}>{siteName}</strong>) and domain (<strong style={{ color: '#334155' }}>{domain || rawSiteUrl}</strong>) already pre-filled.
                  </p>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                <a
                  href={prebuiltWhatsappUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="webcare-btn"
                  style={{
                    background: '#25D366',
                    color: '#ffffff',
                    border: 'none',
                    fontWeight: 600,
                    fontSize: '13px',
                    padding: '9px 18px',
                    borderRadius: '8px',
                    textDecoration: 'none',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '8px'
                  }}
                >
                  <MessageSquare size={15} />
                  <span>Open WhatsApp with Prebuilt Message</span>
                  <ArrowUpRight size={14} />
                </a>

                <a
                  href={prebuiltEmailUrl}
                  className="webcare-btn"
                  style={{
                    background: '#ffffff',
                    color: '#334155',
                    border: '1px solid #cbd5e1',
                    fontWeight: 600,
                    fontSize: '13px',
                    padding: '9px 18px',
                    borderRadius: '8px',
                    textDecoration: 'none',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '8px'
                  }}
                >
                  <Mail size={15} />
                  <span>Send Pre-Filled Email</span>
                </a>
              </div>
            </div>

            {/* Social Channels Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '18px' }}>
              {socialChannels.map((item, idx) => {
                const Icon = item.icon;
                return (
                  <div
                    key={idx}
                    className="webcare-card"
                    style={{
                      background: '#ffffff',
                      borderRadius: '14px',
                      border: '1px solid var(--webcare-border, #e2e8f0)',
                      padding: '22px',
                      display: 'flex',
                      flexDirection: 'column',
                      justifyContent: 'space-between',
                      boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)'
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
                        <span style={{
                          background: item.badgeBg,
                          color: item.badgeColor,
                          fontSize: '11px',
                          fontWeight: 700,
                          padding: '3px 10px',
                          borderRadius: '12px'
                        }}>
                          {item.badge}
                        </span>

                        <div style={{
                          width: '36px',
                          height: '36px',
                          borderRadius: '10px',
                          background: 'var(--webcare-bg-surface, #f8fafc)',
                          border: '1px solid var(--webcare-border, #e2e8f0)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          color: '#334155'
                        }}>
                          <Icon size={18} />
                        </div>
                      </div>

                      <h4 style={{ margin: '0 0 4px 0', fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                        {item.title}
                      </h4>
                      <div style={{ fontSize: '13px', fontWeight: 600, color: '#475569', marginBottom: '8px', fontFamily: 'monospace' }}>
                        {item.handle}
                      </div>
                      <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: '#64748b', lineHeight: 1.5 }}>
                        {item.description}
                      </p>
                    </div>

                    <a
                      href={item.href}
                      target={item.href.startsWith('mailto:') ? '_self' : '_blank'}
                      rel="noopener noreferrer"
                      className="webcare-btn"
                      style={{
                        background: item.btnBg,
                        color: item.btnColor,
                        border: 'none',
                        fontSize: '13px',
                        fontWeight: 600,
                        padding: '9px 14px',
                        borderRadius: '8px',
                        textDecoration: 'none',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '8px',
                        width: '100%',
                        boxSizing: 'border-box'
                      }}
                    >
                      <span>{item.btnText}</span>
                      <ExternalLink size={14} />
                    </a>
                  </div>
                );
              })}
            </div>

            {/* Direct Verification & Guarantee Footer */}
            <div className="webcare-settings-guarantee-footer" style={{
              borderRadius: '12px',
              padding: '16px 20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '12px',
              fontSize: '13px'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <CheckCircle2 size={18} color="#10b981" />
                <span className="webcare-settings-guarantee-text">
                  <strong className="webcare-settings-guarantee-bold">100% Confidentiality &amp; NDA Guarantee:</strong> All direct consultations, diagnostic audits, and server credentials shared with Mir Alamin (WebCare Pro) are encrypted and handled with strict confidentiality.
                </span>
              </div>
              <a
                href="https://webcarepro.dev/contact"
                target="_blank"
                rel="noopener noreferrer"
                className="webcare-settings-guarantee-link"
                style={{ fontWeight: 700, textDecoration: 'underline' }}
              >
                Schedule Consultation &rarr;
              </a>
            </div>
          </div>
        );
      })()}

      {/* Reset Defaults Confirmation Modal */}
      {resetModalOpen && (
        <div
          className="webcare-modal-backdrop"
          onClick={() => {
            if (!resetting) {
              setResetModalOpen(false);
            }
          }}
          style={{ zIndex: 999999 }}
        >
          <div
            className="webcare-modal-window-light webcare-settings-reset-modal"
            onClick={(e) => e.stopPropagation()}
            style={{
              maxWidth: '520px',
              width: '90%',
              borderRadius: '16px',
              boxShadow: '0 25px 50px -12px rgba(15, 23, 42, 0.35)',
              overflow: 'hidden',
              display: 'flex',
              flexDirection: 'column'
            }}
          >
            {/* Modal Header */}
            <div
              className="webcare-settings-reset-header"
              style={{
                padding: '20px 24px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div
                  style={{
                    width: '42px',
                    height: '42px',
                    borderRadius: '10px',
                    background: '#dc2626',
                    color: '#ffffff',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    boxShadow: '0 4px 10px rgba(220, 38, 38, 0.25)'
                  }}
                >
                  <AlertTriangle size={22} />
                </div>
                <div>
                  <h3 className="webcare-settings-reset-title" style={{ margin: 0, fontSize: '17px', fontWeight: 700 }}>
                    Reset All Plugin Settings?
                  </h3>
                  <div className="webcare-settings-reset-subtitle" style={{ fontSize: '12px', fontWeight: 500, marginTop: '2px' }}>
                    Irreversible Factory Reset Action
                  </div>
                </div>
              </div>

              <button
                type="button"
                onClick={() => {
                  if (!resetting) {
                    setResetModalOpen(false);
                  }
                }}
                disabled={resetting}
                className="webcare-settings-reset-close"
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: resetting ? 'not-allowed' : 'pointer',
                  padding: '4px',
                  borderRadius: '6px',
                  display: 'flex',
                  alignItems: 'center',
                  opacity: resetting ? 0.5 : 1
                }}
                title="Cancel"
              >
                <X size={20} />
              </button>
            </div>

            {/* Modal Body */}
            <div className="webcare-settings-reset-body" style={{ padding: '24px' }}>
              <div
                className="webcare-settings-reset-warning"
                style={{
                  borderRadius: '10px',
                  padding: '14px 16px',
                  marginBottom: '18px'
                }}
              >
                <p className="webcare-settings-reset-warning-title" style={{ margin: 0, fontSize: '13px', lineHeight: 1.5, fontWeight: 600 }}>
                  Are you sure you want to reset all settings?
                </p>
                <p className="webcare-settings-reset-warning-desc" style={{ margin: '6px 0 0 0', fontSize: '12px', lineHeight: 1.5 }}>
                  Everything will be removed if you reset this plugin, including all scan configurations, custom schedules, notification webhooks, AI API keys, Cloudflare tokens, and rate limits.
                </p>
              </div>

              <div style={{ marginBottom: '6px' }}>
                <label className="webcare-settings-reset-label" style={{ display: 'block', fontSize: '13px', fontWeight: 600, marginBottom: '8px' }}>
                  Please type <span style={{ color: '#dc2626', background: '#fee2e2', padding: '2px 8px', borderRadius: '4px', fontFamily: 'monospace', fontWeight: 700 }}>reset</span> to confirm:
                </label>
                <input
                  type="text"
                  value={resetConfirmText}
                  onChange={(e) => setResetConfirmText(e.target.value)}
                  placeholder="Type 'reset' here"
                  autoFocus
                  disabled={resetting}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && resetConfirmText.trim().toLowerCase() === 'reset' && !resetting) {
                      e.preventDefault();
                      handleConfirmReset();
                    }
                  }}
                  className="webcare-settings-reset-input"
                  style={{
                    width: '100%',
                    padding: '10px 14px',
                    borderRadius: '8px',
                    fontSize: '14px',
                    fontWeight: 600,
                    boxSizing: 'border-box',
                    outline: 'none',
                    transition: 'border-color 0.15s ease'
                  }}
                />
              </div>
            </div>

            {/* Modal Footer */}
            <div
              className="webcare-settings-reset-footer"
              style={{
                padding: '16px 24px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'flex-end',
                gap: '12px'
              }}
            >
              <button
                type="button"
                className="webcare-btn webcare-settings-reset-cancel-btn"
                onClick={() => setResetModalOpen(false)}
                disabled={resetting}
                style={{
                  borderRadius: '8px',
                  padding: '9px 18px',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: resetting ? 'not-allowed' : 'pointer'
                }}
              >
                Cancel
              </button>

              <button
                type="button"
                className="webcare-btn webcare-settings-reset-confirm-btn"
                onClick={handleConfirmReset}
                disabled={resetting || resetConfirmText.trim().toLowerCase() !== 'reset'}
                style={{
                  background: resetConfirmText.trim().toLowerCase() === 'reset' ? '#dc2626' : undefined,
                  color: resetConfirmText.trim().toLowerCase() === 'reset' ? '#ffffff' : undefined,
                  border: resetConfirmText.trim().toLowerCase() === 'reset' ? '1px solid #dc2626' : undefined,
                  borderRadius: '8px',
                  padding: '9px 20px',
                  fontSize: '13px',
                  fontWeight: 700,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  cursor: (resetting || resetConfirmText.trim().toLowerCase() !== 'reset') ? 'not-allowed' : 'pointer',
                  boxShadow: resetConfirmText.trim().toLowerCase() === 'reset' ? '0 2px 6px rgba(220, 38, 38, 0.3)' : 'none',
                  transition: 'all 0.2s ease'
                }}
              >
                {resetting ? (
                  <>
                    <Loader2 size={15} className="webcare-spin-icon" /> Resetting...
                  </>
                ) : (
                  <>
                    <RotateCcw size={15} /> Confirm Reset
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Sticky Unsaved Changes Action Bar */}
      <UnsavedChangesBar
        isDirty={isDirty}
        isSaving={saving}
        onSave={() => handleSave()}
        onDiscard={handleDiscardChanges}
      />

      {/* Confirmation Modal */}
      <ConfirmDialog
        isOpen={settingsConfirmDialog.isOpen}
        title={settingsConfirmDialog.title}
        message={settingsConfirmDialog.message}
        targetItem={settingsConfirmDialog.targetItem}
        confirmLabel={settingsConfirmDialog.confirmLabel}
        variant={settingsConfirmDialog.variant}
        isLoading={settingsConfirmDialog.isLoading}
        onConfirm={settingsConfirmDialog.onConfirm || (() => {})}
        onClose={() => setSettingsConfirmDialog((prev) => ({ ...prev, isOpen: false }))}
      />
    </div>
  );
};

export default SettingsPage;


function NistCveSyncSettingsCard({ apiRequest }: { apiRequest: (opts: any) => Promise<any> }) {
  const [status, setStatus] = useState<{
    is_running: boolean;
    total_components: number;
    checked_count: number;
    last_fetch_human: string;
    has_api_key: boolean;
  } | null>(null);
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadStatus = async () => {
    try {
      const res = await apiRequest({ path: '/cve/nist-status', method: 'GET' });
      if (res?.success && res.status) {
        setStatus(res.status);
      }
    } catch (e) {}
  };

  useEffect(() => {
    loadStatus();
  }, []);

  return (
    <div className="webcare-firewall-section-group" style={{ borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h3 style={{ margin: 0, fontSize: '15.5px', color: 'var(--webcare-text-primary, #0f172a)' }}>
            NIST NVD Background CVE Sync &amp; API Key
          </h3>
          <p style={{ margin: '2px 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)' }}>
            Checked <strong>{status ? `${status.checked_count} / ${status.total_components}` : '0 / 0'}</strong> plugins &amp; themes &bull; Last Fetch: <strong>{status?.last_fetch_human || 'Never'}</strong> &bull; {status?.has_api_key ? 'NIST API Connected (25 req / 35s)' : 'Free NIST Fetch (5 req / 35s)'}
          </p>
        </div>

        <button
          type="button"
          className="button button-primary"
          disabled={busy || status?.is_running}
          style={{ background: '#4f46e5', borderColor: '#4338ca', fontWeight: 600 }}
          onClick={async () => {
            setBusy(true);
            setNotice(null);
            try {
              const res = await apiRequest({ path: '/cve/nist-sync-start', method: 'POST' });
              if (res?.success) {
                setStatus(res.status);
                setNotice({ type: 'success', text: res.message || 'Background NIST NVD CVE sync started.' });
              }
            } catch (e: any) {
              setNotice({ type: 'error', text: e?.message || 'Failed to start NIST background sync.' });
            } finally {
              setBusy(false);
            }
          }}
        >
          {status?.is_running ? `Syncing (${status.checked_count}/${status.total_components})…` : 'Start Background NIST Sync'}
        </button>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
        <input
          type="password"
          className="webcare-input"
          value={apiKeyInput}
          onChange={(e) => setApiKeyInput(e.target.value)}
          placeholder={status?.has_api_key ? 'NIST API Key saved in Vault (paste to replace)' : 'Optional NIST NVD API Key'}
          style={{ width: '280px' }}
        />
        <button
          type="button"
          className="button"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            setNotice(null);
            try {
              const res = await apiRequest({
                path: '/cve/nist-api-key',
                method: 'POST',
                data: { api_key: apiKeyInput },
              });
              if (res?.success) {
                setStatus(res.status);
                setApiKeyInput('');
                setNotice({ type: 'success', text: 'NIST NVD API Key encrypted & saved in Vault.' });
              }
            } catch (e: any) {
              setNotice({ type: 'error', text: e?.message || 'Failed to save NIST API Key.' });
            } finally {
              setBusy(false);
            }
          }}
        >
          Save Key
        </button>
        {notice && (
          <span style={{ fontSize: '12px', fontWeight: 600, color: notice.type === 'success' ? '#059669' : '#dc2626' }}>
            {notice.text}
          </span>
        )}
      </div>
    </div>
  );
}
