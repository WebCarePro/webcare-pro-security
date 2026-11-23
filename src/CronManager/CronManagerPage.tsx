import type React from 'react';
import { Fragment, useEffect, useId, useMemo, useState } from '@wordpress/element';
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Calendar,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  Clock,
  Cpu,
  Download,
  Filter,
  Info,
  Layers,
  Loader2,
  Lock,
  Play,
  RefreshCw,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Terminal,
  Trash2,
  XCircle,
  Zap,
} from 'lucide-react';
import { showConfirm } from '../utils/dialog';

export interface CronRecurrenceOption {
  value: string;
  label: string;
}

export interface CronLastRun {
  log_id: number;
  task_id: string;
  status: 'success' | 'skipped' | 'disabled' | 'failed';
  trigger_source: string;
  duration_ms: number;
  summary: string;
  error_message?: string;
  completed_at: string;
  completed_at_gmt: string;
  timestamp: number;
}

export interface CronTaskItem {
  id: string;
  hook: string;
  title: string;
  description: string;
  category: string;
  kind: 'recurring' | 'on_demand_worker' | 'security_safeguard';
  can_disable: boolean;
  enabled: boolean;
  dependency_met: boolean;
  dependency_note: string;
  setting_key: string | null;
  setting_location: string;
  deep_link: string;
  recurrence: string;
  recurrence_label: string;
  live_schedule: string | null;
  allowed_recurrences: CronRecurrenceOption[];
  is_scheduled: boolean;
  next_run_timestamp: number | null;
  next_run_local: string | null;
  next_run_relative: string | null;
  is_overdue: boolean;
  extra?: {
    schedule_time?: string;
    schedule_scan_type?: string;
  };
  last_run: CronLastRun | null;
}

export interface CronHealth {
  disable_wp_cron: boolean;
  alternate_wp_cron: boolean;
  site_time: string;
  timezone: string;
  total_tasks: number;
  enabled_count: number;
  disabled_count: number;
  overdue_count: number;
  missing_schedule_count: number;
  third_party_hooks_count: number;
  retention_days: number;
  runs_24h: number;
  success_24h: number;
  skipped_24h: number;
  failed_24h: number;
}

export interface CronLogRow {
  id: number;
  task_id: string;
  hook_name: string;
  task_title: string;
  category: string;
  trigger_source: string;
  status: 'running' | 'success' | 'skipped' | 'disabled' | 'failed';
  started_at: string;
  completed_at: string | null;
  duration_ms: number;
  summary: string;
  metrics: Record<string, any>;
  error_message: string | null;
  actor_id: number;
  actor_label: string;
  created_at_gmt: string;
}

interface CronManagerPageProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
}

const TRIGGER_LABELS: Record<string, string> = {
  wp_cron: 'WP-Cron',
  manual_admin: 'Manual (Admin)',
  wp_cli: 'WP-CLI',
  loopback: 'Loopback',
};

const SCAN_TARGET_LABELS: Record<string, string> = {
  plugins_themes: 'Plugins & Themes',
  full: 'Full Site Audit',
  core_integrity: 'WordPress Core Integrity',
  suspicious_uploads: 'Suspicious Uploads',
  spam_content: 'Database & Spam Content',
};

const resolveCronTabFromUrl = (): 'tasks' | 'logs' => {
  try {
    const p = new URLSearchParams(window.location.search).get('subtab');
    return p === 'logs' ? 'logs' : 'tasks';
  } catch {
    return 'tasks';
  }
};

export const CronManagerPage: React.FC<CronManagerPageProps> = ({ apiRequest }) => {
  const [activeTab, setActiveTab] = useState<'tasks' | 'logs'>(() => resolveCronTabFromUrl());

  const syncCronTabUrl = (tab: 'tasks' | 'logs', replace = false) => {
    try {
      const url = new URL(window.location.href);
      url.searchParams.set('subtab', tab);
      if (replace) {
        window.history.replaceState({ subtab: tab }, '', url.toString());
      } else {
        window.history.pushState({ subtab: tab }, '', url.toString());
      }
    } catch {}
  };

  const switchCronTab = (tab: 'tasks' | 'logs') => {
    setActiveTab(tab);
    syncCronTabUrl(tab, false);
  };

  useEffect(() => {
    try {
      const current = new URLSearchParams(window.location.search).get('subtab');
      if (current !== activeTab) {
        syncCronTabUrl(activeTab, true);
      }
    } catch {}

    const handlePopState = () => {
      setActiveTab(resolveCronTabFromUrl());
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const [loading, setLoading] = useState(true);
  const [health, setHealth] = useState<CronHealth | null>(null);
  const [categories, setCategories] = useState<Record<string, string>>({});
  const [tasks, setTasks] = useState<CronTaskItem[]>([]);
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [taskSearch, setTaskSearch] = useState<string>('');
  const [busyHooks, setBusyHooks] = useState<Record<string, string>>({});
  const [bulkBusy, setBulkBusy] = useState<boolean>(false);
  const [banner, setBanner] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);

  // Scheduled Scan Inline Config Editor state
  const [scanTimeDraft, setScanTimeDraft] = useState<string>('02:00');
  const [scanTypeDraft, setScanTypeDraft] = useState<string>('plugins_themes');

  // Execution Logs Tab state
  const [logsLoading, setLogsLoading] = useState<boolean>(false);
  const [logs, setLogs] = useState<CronLogRow[]>([]);
  const [logsTotal, setLogsTotal] = useState<number>(0);
  const [logsPage, setLogsPage] = useState<number>(1);
  const [logsTotalPages, setLogsTotalPages] = useState<number>(1);
  const [logHookFilter, setLogHookFilter] = useState<string>('all');
  const [logStatusFilter, setLogStatusFilter] = useState<string>('all');
  const [logTriggerFilter, setLogTriggerFilter] = useState<string>('all');
  const [logSearch, setLogSearch] = useState<string>('');
  const [expandedLogId, setExpandedLogId] = useState<number | null>(null);

  const tasksCaptionId = useId();
  const logsCaptionId = useId();

  const applyOverviewPayload = (res: any) => {
    if (!res) return;
    if (res.health) setHealth(res.health);
    if (res.categories) setCategories(res.categories);
    if (Array.isArray(res.tasks)) {
      setTasks(res.tasks);
      const mainScan = res.tasks.find((t: CronTaskItem) => t.hook === 'webcareproscan_scheduled_scan_event');
      if (mainScan?.extra?.schedule_time) {
        setScanTimeDraft(mainScan.extra.schedule_time);
      }
      if (mainScan?.extra?.schedule_scan_type) {
        setScanTypeDraft(mainScan.extra.schedule_scan_type);
      }
    }
  };

  const fetchOverview = async () => {
    setLoading(true);
    try {
      const res = await apiRequest({
        path: '/cron-manager/overview',
        method: 'GET',
      });
      if (res?.success) {
        applyOverviewPayload(res);
      }
    } catch (err: any) {
      setBanner({
        type: 'error',
        message: err?.message || 'Failed to load Cron Control Center state.',
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchLogs = async (pageOverride?: number, hookOverride?: string) => {
    setLogsLoading(true);
    try {
      const targetPage = pageOverride ?? logsPage;
      const targetHook = hookOverride ?? logHookFilter;
      const qs = new URLSearchParams({
        hook: targetHook,
        status: logStatusFilter,
        trigger: logTriggerFilter,
        search: logSearch,
        days: String(health?.retention_days ?? 30),
        page: String(targetPage),
        per_page: '20',
      });
      const res = await apiRequest({
        path: `/cron-manager/logs?${qs.toString()}`,
        method: 'GET',
      });
      if (res?.success) {
        setLogs(Array.isArray(res.items) ? res.items : []);
        setLogsTotal(Number(res.total || 0));
        setLogsPage(Number(res.page || 1));
        setLogsTotalPages(Number(res.total_pages || 1));
      }
    } catch (err: any) {
      setBanner({
        type: 'error',
        message: err?.message || 'Failed to query cron execution logs.',
      });
    } finally {
      setLogsLoading(false);
    }
  };

  useEffect(() => {
    fetchOverview();
  }, []);

  useEffect(() => {
    if (activeTab === 'logs') {
      fetchLogs();
    }
  }, [activeTab, logHookFilter, logStatusFilter, logTriggerFilter, logsPage]);

  const handleToggleTask = async (task: CronTaskItem) => {
    if (!task.can_disable) return;
    setBusyHooks((prev) => ({ ...prev, [task.hook]: 'toggle' }));
    setBanner(null);
    try {
      const res = await apiRequest({
        path: '/cron-manager/task/toggle',
        method: 'POST',
        data: { hook: task.hook, enabled: !task.enabled },
      });
      if (res?.overview) {
        applyOverviewPayload(res.overview);
      }
      setBanner({
        type: 'success',
        message: res?.message || `${task.title} synchronized.`,
      });
    } catch (err: any) {
      setBanner({
        type: 'error',
        message: err?.message || `Failed to update ${task.title}.`,
      });
    } finally {
      setBusyHooks((prev) => {
        const next = { ...prev };
        delete next[task.hook];
        return next;
      });
    }
  };

  const handleScheduleChange = async (
    task: CronTaskItem,
    frequency: string,
    extra?: { schedule_time?: string; schedule_scan_type?: string }
  ) => {
    setBusyHooks((prev) => ({ ...prev, [task.hook]: 'schedule' }));
    setBanner(null);
    try {
      const res = await apiRequest({
        path: '/cron-manager/task/schedule',
        method: 'POST',
        data: {
          hook: task.hook,
          frequency,
          ...(extra || {}),
        },
      });
      if (res?.overview) {
        applyOverviewPayload(res.overview);
      }
      setBanner({
        type: 'success',
        message: res?.message || `Updated schedule for ${task.title}.`,
      });
    } catch (err: any) {
      setBanner({
        type: 'error',
        message: err?.message || `Failed to update schedule for ${task.title}.`,
      });
    } finally {
      setBusyHooks((prev) => {
        const next = { ...prev };
        delete next[task.hook];
        return next;
      });
    }
  };

  const handleRunNow = async (task: CronTaskItem) => {
    setBusyHooks((prev) => ({ ...prev, [task.hook]: 'run' }));
    setBanner(null);
    try {
      const res = await apiRequest({
        path: '/cron-manager/task/run',
        method: 'POST',
        data: { hook: task.hook },
      });
      if (res?.overview) {
        applyOverviewPayload(res.overview);
      }
      setBanner({
        type: res?.status === 'failed' ? 'error' : 'success',
        message: `${task.title}: ${res?.summary || 'Executed'} (${res?.duration_ms ?? 0}ms)`,
      });
      if (activeTab === 'logs') {
        fetchLogs(1);
      }
    } catch (err: any) {
      setBanner({
        type: 'error',
        message: err?.message || `Manual execution failed for ${task.title}.`,
      });
    } finally {
      setBusyHooks((prev) => {
        const next = { ...prev };
        delete next[task.hook];
        return next;
      });
    }
  };

  const handleBulkAction = async (action: 'enable_recommended' | 'disable_optional' | 'repair_schedules') => {
    if (action === 'disable_optional') {
      const confirmed = await showConfirm({
        title: 'Pause All Optional Scheduled Tasks?',
        message: 'This will pause all toggleable recurring plugin crons and update their corresponding Settings flags. Security safeguards (temp-admin expiry and WAF auto re-arm) remain active.',
        confirmLabel: 'Pause Optional Tasks',
        variant: 'warning',
      });
      if (!confirmed) return;
    }

    setBulkBusy(true);
    setBanner(null);
    try {
      const res = await apiRequest({
        path: '/cron-manager/bulk',
        method: 'POST',
        data: { action },
      });
      applyOverviewPayload(res);
      setBanner({
        type: 'success',
        message:
          res?.message ||
          (action === 'repair_schedules'
            ? `Repaired or rescheduled ${res?.repaired_count ?? 0} WP-Cron schedule(s).`
            : 'Bulk cron synchronization complete.'),
      });
    } catch (err: any) {
      setBanner({
        type: 'error',
        message: err?.message || 'Bulk operation failed.',
      });
    } finally {
      setBulkBusy(false);
    }
  };

  const handleRetentionChange = async (days: number) => {
    try {
      const res = await apiRequest({
        path: '/cron-manager/retention',
        method: 'POST',
        data: { retention_days: days },
      });
      if (health) {
        setHealth({ ...health, retention_days: days });
      }
      setBanner({
        type: 'success',
        message: res?.message || `Retention updated to ${days} days.`,
      });
    } catch (err: any) {
      setBanner({
        type: 'error',
        message: err?.message || 'Failed to update retention policy.',
      });
    }
  };

  const handleClearLogs = async () => {
    const scopeLabel = logHookFilter === 'all' ? 'all tasks' : logHookFilter;
    const confirmed = await showConfirm({
      title: 'Clear Cron Execution History?',
      message: `Permanently remove stored execution log entries for ${scopeLabel}? This action is recorded in Plugin Activity & Audit Logs.`,
      confirmLabel: 'Clear History',
      variant: 'danger',
    });
    if (!confirmed) return;

    try {
      const res = await apiRequest({
        path: '/cron-manager/logs/clear',
        method: 'POST',
        data: { hook: logHookFilter },
      });
      setBanner({
        type: 'success',
        message: res?.message || 'Cron execution logs cleared.',
      });
      await fetchOverview();
      await fetchLogs(1);
    } catch (err: any) {
      setBanner({
        type: 'error',
        message: err?.message || 'Failed to clear cron execution logs.',
      });
    }
  };

  const handleExportJson = async () => {
    try {
      const qs = new URLSearchParams({
        hook: logHookFilter,
        status: logStatusFilter,
        trigger: logTriggerFilter,
        search: logSearch,
      });
      const res = await apiRequest({
        path: `/cron-manager/logs/export?${qs.toString()}`,
        method: 'GET',
      });
      const blob = new Blob([JSON.stringify(res, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `webcare-cron-telemetry-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setBanner({
        type: 'error',
        message: err?.message || 'Failed to export cron telemetry JSON.',
      });
    }
  };

  const openTaskLogs = (hook: string) => {
    setLogHookFilter(hook);
    setLogsPage(1);
    switchCronTab('logs');
  };

  const filteredTasks = useMemo(() => {
    const q = taskSearch.trim().toLowerCase();
    return tasks.filter((t) => {
      if (categoryFilter !== 'all' && t.category !== categoryFilter) {
        return false;
      }
      if (!q) return true;
      return (
        t.title.toLowerCase().includes(q) ||
        t.hook.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q) ||
        t.setting_location.toLowerCase().includes(q)
      );
    });
  }, [tasks, categoryFilter, taskSearch]);

  const handleTabKeyDown = (e: React.KeyboardEvent, tab: 'tasks' | 'logs') => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault();
      switchCronTab(tab === 'tasks' ? 'logs' : 'tasks');
    }
  };

  const renderStatusBadge = (status?: string) => {
    if (status === 'success') {
      return (
        <span className="webcare-cron-status-badge is-success">
          <CheckCircle2 size={12} />
          <span>Success</span>
        </span>
      );
    }
    if (status === 'failed') {
      return (
        <span className="webcare-cron-status-badge is-failed">
          <XCircle size={12} />
          <span>Failed</span>
        </span>
      );
    }
    if (status === 'disabled') {
      return (
        <span className="webcare-cron-status-badge is-disabled">
          <Lock size={12} />
          <span>Disabled</span>
        </span>
      );
    }
    if (status === 'skipped') {
      return (
        <span className="webcare-cron-status-badge is-skipped">
          <Info size={12} />
          <span>Skipped</span>
        </span>
      );
    }
    if (status === 'running') {
      return (
        <span className="webcare-cron-status-badge is-running">
          <Loader2 size={12} className="webcare-spin" />
          <span>Running</span>
        </span>
      );
    }
    return (
      <span className="webcare-cron-status-badge is-neutral">
        <Clock size={12} />
        <span>Never Run</span>
      </span>
    );
  };

  return (
    <div className="webcare-cron-page">
      {/* Executive Header */}
      <section className="webcare-cron-hero">
        <div className="webcare-cron-hero-top">
          <div>
            <div className="webcare-cron-hero-badge">
              <Clock size={13} />
              <span>Centralized WP-Cron &amp; Automation Control</span>
              <span className="webcare-cron-version-chip">
                v{((window as any).webcareScannerSettings?.version) || '2.12.0'}
              </span>
              <span className={`webcare-cron-status-chip ${health?.disable_wp_cron ? 'is-disabled' : 'is-enabled'}`}>
                <span className="webcare-cron-status-dot" />
                {health?.disable_wp_cron ? 'Cron: Disabled (System Mode)' : 'Cron: Enabled (Native)'}
              </span>
            </div>
            <h1 className="webcare-cron-hero-title">Cron &amp; Scheduled Tasks Control Center</h1>
            <p className="webcare-cron-hero-desc">
              Manage every scheduled task and background worker across WebCare Pro from one console.
              Toggles and frequencies stay bidirectionally synchronized with plugin Settings, Notifications, Firewall, and Setup Studio.
            </p>
          </div>

          <div className="webcare-cron-hero-actions">
            <button
              type="button"
              className="webcare-cron-btn webcare-cron-btn-secondary"
              onClick={() => {
                fetchOverview();
                if (activeTab === 'logs') fetchLogs();
              }}
              disabled={loading}
            >
              <RefreshCw size={14} className={loading ? 'webcare-spin' : ''} />
              <span>Refresh</span>
            </button>

            <button
              type="button"
              className="webcare-cron-btn webcare-cron-btn-secondary"
              onClick={() => handleBulkAction('repair_schedules')}
              disabled={bulkBusy}
              title="Verify all enabled tasks are registered in WordPress cron storage"
            >
              <Zap size={14} />
              <span>Sync &amp; Repair Schedules</span>
            </button>

            <button
              type="button"
              className="webcare-cron-btn webcare-cron-btn-primary"
              onClick={handleExportJson}
            >
              <Download size={14} />
              <span>Export JSON</span>
            </button>
          </div>
        </div>

        {/* KPI Strip */}
        <div className="webcare-cron-kpi-grid">
          <div className="webcare-cron-kpi-card">
            <div className="webcare-cron-kpi-label">
              <Cpu size={14} />
              <span>Active Tasks</span>
            </div>
            <div className="webcare-cron-kpi-val">
              {health ? `${health.enabled_count} / ${health.total_tasks}` : '—'}
            </div>
            <div className="webcare-cron-kpi-sub">
              {health ? `${health.disabled_count} paused • ${health.third_party_hooks_count} external site hooks` : 'Loading telemetry...'}
            </div>
          </div>

          <div className="webcare-cron-kpi-card">
            <div className="webcare-cron-kpi-label">
              <Activity size={14} />
              <span>Executions (24h)</span>
            </div>
            <div className="webcare-cron-kpi-val">
              {health ? health.runs_24h.toLocaleString() : '—'}
            </div>
            <div className="webcare-cron-kpi-sub">
              {health
                ? `${health.success_24h} succeeded • ${health.skipped_24h} skipped • ${health.failed_24h} failed`
                : 'Aggregating logs...'}
            </div>
          </div>

          <div className="webcare-cron-kpi-card">
            <div className="webcare-cron-kpi-label">
              <ShieldCheck size={14} />
              <span>WP-Cron Engine</span>
            </div>
            <div className="webcare-cron-kpi-val">
              {health?.disable_wp_cron ? 'System Cron Mode' : 'WordPress Native'}
            </div>
            <div className="webcare-cron-kpi-sub">
              {health
                ? `${health.site_time} (${health.timezone})`
                : 'Checking runtime constants...'}
            </div>
          </div>

          <div className={`webcare-cron-kpi-card ${health && (health.overdue_count > 0 || health.missing_schedule_count > 0 || health.failed_24h > 0) ? 'is-alert' : ''}`}>
            <div className="webcare-cron-kpi-label">
              <AlertTriangle size={14} />
              <span>Queue Health</span>
            </div>
            <div className="webcare-cron-kpi-val">
              {health
                ? health.overdue_count === 0 && health.missing_schedule_count === 0 && health.failed_24h === 0
                  ? 'Healthy'
                  : `${health.overdue_count} Overdue • ${health.missing_schedule_count} Missing`
                : '—'}
            </div>
            <div className="webcare-cron-kpi-sub">
              {health ? `Log retention: ${health.retention_days} days` : 'Inspecting schedule slots...'}
            </div>
          </div>
        </div>
      </section>

      {/* DISABLE_WP_CRON Advisory Banner */}
      {health?.disable_wp_cron && (
        <div className="webcare-cron-advisory" role="status">
          <AlertTriangle size={16} />
          <div>
            <strong>Notice: <code>DISABLE_WP_CRON</code> is enabled in <code>wp-config.php</code>.</strong>{' '}
            Ensure your server crontab executes <code>wp cron event run --due-now</code> (or requests <code>wp-cron.php?doing_wp_cron</code>) every 1–5 minutes so scheduled tasks fire on time.
          </div>
        </div>
      )}

      {/* Live Feedback Banner */}
      {banner && (
        <div className={`webcare-cron-banner is-${banner.type}`} role="status" aria-live="polite">
          <span>{banner.message}</span>
          <button
            type="button"
            className="webcare-cron-banner-close"
            onClick={() => setBanner(null)}
            aria-label="Dismiss notification"
          >
            &times;
          </button>
        </div>
      )}

      {/* Primary Accessible Tablist */}
      <div className="webcare-cron-main-card">
        <div className="webcare-cron-tabs-header">
          <div className="webcare-cron-tablist" role="tablist" aria-label="Cron Control Views">
            <button
              type="button"
              role="tab"
              id="cron-tab-tasks"
              aria-selected={activeTab === 'tasks'}
              tabIndex={activeTab === 'tasks' ? 0 : -1}
              className="webcare-cron-tab-btn"
              onClick={() => switchCronTab('tasks')}
              onKeyDown={(e) => handleTabKeyDown(e, 'tasks')}
            >
              <Sliders size={15} />
              <span>Tasks &amp; Schedules</span>
              <span className="webcare-cron-tab-count">{tasks.length}</span>
            </button>

            <button
              type="button"
              role="tab"
              id="cron-tab-logs"
              aria-selected={activeTab === 'logs'}
              tabIndex={activeTab === 'logs' ? 0 : -1}
              className="webcare-cron-tab-btn"
              onClick={() => switchCronTab('logs')}
              onKeyDown={(e) => handleTabKeyDown(e, 'logs')}
            >
              <Terminal size={15} />
              <span>Execution Logs</span>
              <span className="webcare-cron-tab-count">{health?.runs_24h ?? logsTotal}</span>
            </button>
          </div>

          {/* Retention & Status Strip */}
          <div className="webcare-cron-retention-wrap">
            <div className="webcare-cron-header-status-wrap">
              <span className="webcare-cron-header-status-label">WP-Cron:</span>
              <span className={`webcare-cron-engine-badge ${health?.disable_wp_cron ? 'is-disabled' : 'is-enabled'}`}>
                <span className="webcare-cron-status-dot" />
                {health?.disable_wp_cron ? 'Disabled' : 'Enabled'}
              </span>
            </div>

            <label htmlFor="cron-retention-select" className="webcare-cron-retention-label">
              Log Retention:
            </label>
            <select
              id="cron-retention-select"
              className="webcare-input webcare-cron-select"
              value={health?.retention_days ?? 30}
              onChange={(e) => handleRetentionChange(Number(e.target.value))}
            >
              <option value={7}>7 Days</option>
              <option value={14}>14 Days</option>
              <option value={30}>30 Days</option>
              <option value={60}>60 Days</option>
              <option value={90}>90 Days</option>
            </select>
          </div>
        </div>

        {/* TAB PANEL 1: TASKS & SCHEDULES */}
        <div
          role="tabpanel"
          aria-labelledby="cron-tab-tasks"
          hidden={activeTab !== 'tasks'}
          tabIndex={0}
          className="webcare-cron-tabpanel"
        >
          {/* Real-Time Cron Status Strip for subtab=tasks */}
          <div className={`webcare-cron-status-strip ${health?.disable_wp_cron ? 'is-disabled' : 'is-enabled'}`}>
            <div className="webcare-cron-status-strip-left">
              <div className="webcare-cron-status-icon-wrap">
                {health?.disable_wp_cron ? (
                  <AlertTriangle size={18} />
                ) : (
                  <CheckCircle2 size={18} />
                )}
              </div>
              <div className="webcare-cron-status-content">
                <div className="webcare-cron-status-title-line">
                  <span className="webcare-cron-status-title">WP-Cron Engine:</span>
                  <span className={`webcare-cron-engine-badge ${health?.disable_wp_cron ? 'is-disabled' : 'is-enabled'}`}>
                    <span className="webcare-cron-status-dot" />
                    {health?.disable_wp_cron ? 'Disabled' : 'Enabled'}
                  </span>
                  <span className="webcare-cron-status-mode-pill">
                    {health?.disable_wp_cron
                      ? 'System Cron Mode (wp-config.php: DISABLE_WP_CRON)'
                      : 'WordPress Native Engine (Spawns on visitor traffic)'}
                  </span>
                  {health?.alternate_wp_cron && (
                    <span className="webcare-cron-status-mode-pill is-alt">
                      ALTERNATE_WP_CRON
                    </span>
                  )}
                </div>
                <div className="webcare-cron-status-subline">
                  {health?.disable_wp_cron
                    ? 'WordPress built-in visitor cron execution is disabled. Scheduled jobs will only run when invoked externally via server crontab (e.g. cPanel / Linux cron) or WP-CLI.'
                    : 'WordPress internal cron is active and automatically dispatches background security tasks when requests hit the site.'}
                  {health && (
                    <span className="webcare-cron-status-clock">
                      &bull; Server Clock: <strong>{health.site_time}</strong> ({health.timezone})
                    </span>
                  )}
                </div>
              </div>
            </div>

            <div className="webcare-cron-status-strip-right">
              {health && health.overdue_count > 0 ? (
                <div className="webcare-cron-strip-overdue">
                  <span className="webcare-cron-strip-overdue-tag">
                    {health.overdue_count} {health.overdue_count === 1 ? 'Task' : 'Tasks'} Overdue
                  </span>
                  <button
                    type="button"
                    className="webcare-cron-btn-repair-micro"
                    onClick={() => handleBulkAction('repair_schedules')}
                    disabled={bulkBusy}
                    title="Reschedule overdue tasks into future execution windows"
                  >
                    <Zap size={11} />
                    <span>Reschedule Overdue</span>
                  </button>
                </div>
              ) : (
                <div className="webcare-cron-strip-clean">
                  <ShieldCheck size={14} />
                  <span>All Tasks On Schedule</span>
                </div>
              )}
            </div>
          </div>

          <div className="webcare-cron-toolbar">
            <div className="webcare-cron-chips">
              <button
                type="button"
                className={`webcare-cron-chip ${categoryFilter === 'all' ? 'is-active' : ''}`}
                onClick={() => setCategoryFilter('all')}
              >
                All ({tasks.length})
              </button>
              {Object.entries(categories).map(([catKey, catLabel]) => {
                const cnt = tasks.filter((t) => t.category === catKey).length;
                if (cnt === 0) return null;
                return (
                  <button
                    key={catKey}
                    type="button"
                    className={`webcare-cron-chip ${categoryFilter === catKey ? 'is-active' : ''}`}
                    onClick={() => setCategoryFilter(catKey)}
                  >
                    {catLabel} ({cnt})
                  </button>
                );
              })}
            </div>

            <div className="webcare-cron-toolbar-right">
              <div className="webcare-cron-search-box">
                <Search size={14} />
                <input
                  type="search"
                  className="webcare-input webcare-cron-search-input"
                  placeholder="Search hooks, tasks, or synced setting..."
                  value={taskSearch}
                  onChange={(e) => setTaskSearch(e.target.value)}
                  aria-label="Filter scheduled tasks"
                />
              </div>

              <button
                type="button"
                className="webcare-cron-btn webcare-cron-btn-ghost"
                onClick={() => handleBulkAction('enable_recommended')}
                disabled={bulkBusy}
              >
                Enable All Recurring
              </button>

              <button
                type="button"
                className="webcare-cron-btn webcare-cron-btn-danger-soft"
                onClick={() => handleBulkAction('disable_optional')}
                disabled={bulkBusy}
              >
                Pause Optional
              </button>
            </div>
          </div>

          <div
            tabIndex={0}
            role="region"
            aria-labelledby={tasksCaptionId}
            className="webcare-cron-table-wrapper"
          >
            <table className="webcare-cron-table webcare-cron-tasks-table">
              <caption id={tasksCaptionId} className="screen-reader-text">
                WebCare Pro Security &amp; Firewall scheduled tasks and synchronization controls
              </caption>
              <thead>
                <tr>
                  <th scope="col">Task &amp; Synchronized Module</th>
                  <th scope="col">State</th>
                  <th scope="col">Frequency &amp; Options</th>
                  <th scope="col">Next Scheduled Run</th>
                  <th scope="col">Latest Execution</th>
                  <th scope="col">Controls</th>
                </tr>
              </thead>
              <tbody>
                {loading && tasks.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="webcare-cron-empty-cell">
                      <Loader2 size={18} className="webcare-spin" />
                      <span>Loading registered plugin tasks and schedules...</span>
                    </td>
                  </tr>
                ) : filteredTasks.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="webcare-cron-empty-cell">
                      <span>No scheduled tasks match your current filter.</span>
                    </td>
                  </tr>
                ) : (
                  filteredTasks.map((task) => {
                    const busyState = busyHooks[task.hook];
                    const isMainScan = task.hook === 'webcareproscan_scheduled_scan_event';
                    return (
                      <tr key={task.hook} className={!task.enabled ? 'is-paused-row' : ''}>
                        <th scope="row" className="webcare-cron-task-cell">
                          <div className="webcare-cron-task-title-row">
                            <span className="webcare-cron-task-title">{task.title}</span>
                            {!task.can_disable && (
                              <span
                                className="webcare-cron-safeguard-pill"
                                title="Security safeguard timers cannot be disabled to prevent permanent privilege exposure or WAF bypass."
                              >
                                <ShieldAlert size={11} />
                                <span>Security Enforced</span>
                              </span>
                            )}
                            {task.kind === 'on_demand_worker' && (
                              <span className="webcare-cron-worker-pill">On-Demand Worker</span>
                            )}
                          </div>

                          <p className="webcare-cron-task-desc">{task.description}</p>

                          <div className="webcare-cron-meta-links">
                            <code className="webcare-cron-hook-code">{task.hook}</code>
                            <a
                              href={task.deep_link}
                              className="webcare-cron-sync-link"
                              title={`Synchronized with ${task.setting_location}`}
                            >
                              <Settings size={11} />
                              <span>Synced: {task.setting_location}</span>
                              <ArrowUpRight size={11} />
                            </a>
                          </div>

                          {!task.dependency_met && task.dependency_note && (
                            <div className="webcare-cron-dep-warn">
                              <AlertTriangle size={12} />
                              <span>{task.dependency_note}</span>
                            </div>
                          )}
                        </th>

                        <td data-label="State">
                          <div className="webcare-cron-switch-wrap">
                            <button
                              type="button"
                              role="switch"
                              aria-checked={task.enabled}
                              aria-label={`Toggle ${task.title}`}
                              disabled={!task.can_disable || Boolean(busyState)}
                              onClick={() => handleToggleTask(task)}
                              className={`webcare-cron-switch ${task.enabled ? 'is-on' : 'is-off'} ${!task.can_disable ? 'is-locked' : ''}`}
                              title={
                                !task.can_disable
                                  ? 'Security-enforced safeguard timer'
                                  : task.enabled
                                  ? 'Click to pause this scheduled task & update synced settings'
                                  : 'Click to enable this scheduled task & update synced settings'
                              }
                            >
                              <span className="webcare-cron-switch-thumb" />
                            </button>
                            <span className="webcare-cron-switch-text">
                              {!task.can_disable ? 'Enforced' : task.enabled ? 'Enabled' : 'Paused'}
                            </span>
                          </div>
                        </td>

                        <td data-label="Frequency">
                          {task.allowed_recurrences.length > 0 ? (
                            <div className="webcare-cron-freq-stack">
                              <select
                                className="webcare-input webcare-cron-select"
                                value={task.recurrence}
                                disabled={Boolean(busyState)}
                                aria-label={`Schedule interval for ${task.title}`}
                                onChange={(e) =>
                                  handleScheduleChange(
                                    task,
                                    e.target.value,
                                    isMainScan
                                      ? { schedule_time: scanTimeDraft, schedule_scan_type: scanTypeDraft }
                                      : undefined
                                  )
                                }
                              >
                                {task.allowed_recurrences.map((opt) => (
                                  <option key={opt.value} value={opt.value}>
                                    {opt.label}
                                  </option>
                                ))}
                              </select>

                              {isMainScan && (
                                <div className="webcare-cron-scan-extras">
                                  <input
                                    type="time"
                                    className="webcare-input webcare-cron-time-input"
                                    value={scanTimeDraft}
                                    onChange={(e) => setScanTimeDraft(e.target.value)}
                                    aria-label="Scheduled scan run time"
                                  />
                                  <select
                                    className="webcare-input webcare-cron-select-compact"
                                    value={scanTypeDraft}
                                    onChange={(e) => setScanTypeDraft(e.target.value)}
                                    aria-label="Scheduled scan scope"
                                  >
                                    {Object.entries(SCAN_TARGET_LABELS).map(([k, lbl]) => (
                                      <option key={k} value={k}>
                                        {lbl}
                                      </option>
                                    ))}
                                  </select>
                                  <button
                                    type="button"
                                    className="webcare-btn-micro"
                                    disabled={Boolean(busyState)}
                                    onClick={() =>
                                      handleScheduleChange(task, task.recurrence, {
                                        schedule_time: scanTimeDraft,
                                        schedule_scan_type: scanTypeDraft,
                                      })
                                    }
                                  >
                                    Apply
                                  </button>
                                </div>
                              )}
                            </div>
                          ) : (
                            <span className="webcare-cron-ondemand-tag">{task.recurrence_label}</span>
                          )}
                        </td>

                        <td data-label="Next Run">
                          {task.is_scheduled && task.next_run_local ? (
                            <div className="webcare-cron-next-run">
                              <span className={`webcare-cron-next-rel ${task.is_overdue ? 'is-overdue' : ''}`}>
                                {task.next_run_relative}
                              </span>
                              <span className="webcare-cron-next-exact">{task.next_run_local}</span>
                            </div>
                          ) : (
                            <span className="webcare-cron-muted-label">
                              {task.kind === 'recurring'
                                ? task.enabled && task.dependency_met
                                  ? 'Pending schedule sync'
                                  : 'Not scheduled'
                                : 'Idle (Triggered by events)'}
                            </span>
                          )}
                        </td>

                        <td data-label="Latest Execution">
                          {task.last_run ? (
                            <div className="webcare-cron-last-run">
                              <div className="webcare-cron-last-top">
                                {renderStatusBadge(task.last_run.status)}
                                <span className="webcare-cron-duration-chip">{task.last_run.duration_ms}ms</span>
                              </div>
                              <div className="webcare-cron-last-summary" title={task.last_run.summary}>
                                {task.last_run.summary || 'Completed cleanly.'}
                              </div>
                              <div className="webcare-cron-last-meta">
                                {TRIGGER_LABELS[task.last_run.trigger_source] || task.last_run.trigger_source} &bull;{' '}
                                {task.last_run.completed_at}
                              </div>
                            </div>
                          ) : (
                            renderStatusBadge(undefined)
                          )}
                        </td>

                        <td data-label="Controls">
                          <div className="webcare-cron-row-actions">
                            <button
                              type="button"
                              className="webcare-cron-btn webcare-cron-btn-run"
                              disabled={Boolean(busyState)}
                              onClick={() => handleRunNow(task)}
                              title={`Run ${task.title} immediately and record telemetry log`}
                            >
                              {busyState === 'run' ? (
                                <Loader2 size={13} className="webcare-spin" />
                              ) : (
                                <Play size={13} />
                              )}
                              <span>{busyState === 'run' ? 'Running...' : 'Run Now'}</span>
                            </button>

                            <button
                              type="button"
                              className="webcare-cron-btn webcare-cron-btn-ghost"
                              onClick={() => openTaskLogs(task.hook)}
                              title="Inspect execution history for this task"
                            >
                              <Layers size={13} />
                              <span>Logs</span>
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* TAB PANEL 2: EXECUTION LOGS */}
        <div
          role="tabpanel"
          aria-labelledby="cron-tab-logs"
          hidden={activeTab !== 'logs'}
          tabIndex={0}
          className="webcare-cron-tabpanel"
        >
          <div className="webcare-cron-toolbar">
            <div className="webcare-cron-filters-row">
              <select
                className="webcare-input webcare-cron-select"
                value={logHookFilter}
                onChange={(e) => {
                  setLogHookFilter(e.target.value);
                  setLogsPage(1);
                }}
                aria-label="Filter logs by task"
              >
                <option value="all">All Scheduled Tasks</option>
                {tasks.map((t) => (
                  <option key={t.hook} value={t.hook}>
                    {t.title}
                  </option>
                ))}
              </select>

              <select
                className="webcare-input webcare-cron-select"
                value={logStatusFilter}
                onChange={(e) => {
                  setLogStatusFilter(e.target.value);
                  setLogsPage(1);
                }}
                aria-label="Filter logs by status"
              >
                <option value="all">All Statuses</option>
                <option value="success">Success</option>
                <option value="skipped">Skipped</option>
                <option value="disabled">Disabled</option>
                <option value="failed">Failed</option>
              </select>

              <select
                className="webcare-input webcare-cron-select"
                value={logTriggerFilter}
                onChange={(e) => {
                  setLogTriggerFilter(e.target.value);
                  setLogsPage(1);
                }}
                aria-label="Filter logs by trigger source"
              >
                <option value="all">All Triggers</option>
                <option value="wp_cron">WP-Cron</option>
                <option value="manual_admin">Manual (Admin)</option>
                <option value="wp_cli">WP-CLI</option>
              </select>
            </div>

            <div className="webcare-cron-toolbar-right">
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  setLogsPage(1);
                  fetchLogs(1);
                }}
                className="webcare-cron-search-form"
              >
                <div className="webcare-cron-search-box">
                  <Search size={14} />
                  <input
                    type="search"
                    className="webcare-input webcare-cron-search-input"
                    placeholder="Search summary or error..."
                    value={logSearch}
                    onChange={(e) => setLogSearch(e.target.value)}
                    aria-label="Search execution logs"
                  />
                </div>
                <button type="submit" className="webcare-cron-btn webcare-cron-btn-secondary">
                  <Filter size={13} />
                  <span>Filter</span>
                </button>
              </form>

              <button
                type="button"
                className="webcare-cron-btn webcare-cron-btn-danger-soft"
                onClick={handleClearLogs}
              >
                <Trash2 size={13} />
                <span>Clear Logs</span>
              </button>
            </div>
          </div>

          <div
            tabIndex={0}
            role="region"
            aria-labelledby={logsCaptionId}
            className="webcare-cron-table-wrapper"
          >
            <table className="webcare-cron-table webcare-cron-logs-table">
              <caption id={logsCaptionId} className="screen-reader-text">
                Chronological execution history for WebCare Pro scheduled tasks
              </caption>
              <thead>
                <tr>
                  <th scope="col">Task &amp; Hook</th>
                  <th scope="col">Status</th>
                  <th scope="col">Trigger &amp; Actor</th>
                  <th scope="col">Duration</th>
                  <th scope="col">Summary</th>
                  <th scope="col">Completed (Site Time)</th>
                  <th scope="col">Forensics</th>
                </tr>
              </thead>
              <tbody>
                {logsLoading ? (
                  <tr>
                    <td colSpan={7} className="webcare-cron-empty-cell">
                      <Loader2 size={18} className="webcare-spin" />
                      <span>Querying execution history...</span>
                    </td>
                  </tr>
                ) : logs.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="webcare-cron-empty-cell">
                      <span>No execution logs recorded for the active filter yet. Run any task manually or wait for WP-Cron.</span>
                    </td>
                  </tr>
                ) : (
                  logs.map((row) => {
                    const isExpanded = expandedLogId === row.id;
                    return (
                      <Fragment key={row.id}>
                        <tr>
                          <th scope="row" className="webcare-cron-log-task-cell">
                            <span className="webcare-cron-log-title">{row.task_title}</span>
                            <code className="webcare-cron-hook-code">{row.hook_name}</code>
                          </th>
                          <td data-label="Status">{renderStatusBadge(row.status)}</td>
                          <td data-label="Trigger">
                            <div className="webcare-cron-trigger-cell">
                              <span className="webcare-cron-trigger-pill">
                                {TRIGGER_LABELS[row.trigger_source] || row.trigger_source}
                              </span>
                              <span className="webcare-cron-actor-text">{row.actor_label}</span>
                            </div>
                          </td>
                          <td data-label="Duration">
                            <span className="webcare-cron-duration-chip">{row.duration_ms}ms</span>
                          </td>
                          <td data-label="Summary" className="webcare-cron-summary-cell">
                            {row.summary || '—'}
                          </td>
                          <td data-label="Completed">
                            <span className="webcare-cron-time-cell">{row.completed_at || row.started_at}</span>
                          </td>
                          <td data-label="Forensics">
                            <button
                              type="button"
                              className="webcare-cron-btn webcare-cron-btn-ghost"
                              onClick={() => setExpandedLogId(isExpanded ? null : row.id)}
                              aria-expanded={isExpanded}
                            >
                              {isExpanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                              <span>{isExpanded ? 'Hide' : 'Inspect'}</span>
                            </button>
                          </td>
                        </tr>
                        {isExpanded && (
                          <tr className="webcare-cron-log-expanded-row">
                            <td colSpan={7}>
                              <div className="webcare-cron-log-drawer">
                                <div className="webcare-cron-drawer-grid">
                                  <div>
                                    <strong>Log Entry ID:</strong> #{row.id} ({row.task_id})
                                  </div>
                                  <div>
                                    <strong>Started (Local):</strong> {row.started_at}
                                  </div>
                                  <div>
                                    <strong>Timestamp (UTC):</strong> {row.created_at_gmt} UTC
                                  </div>
                                  <div>
                                    <strong>Execution Time:</strong> {row.duration_ms} ms
                                  </div>
                                </div>
                                {row.error_message && (
                                  <div className="webcare-cron-drawer-error">
                                    <strong>Exception / Error Detail:</strong>
                                    <pre>{row.error_message}</pre>
                                  </div>
                                )}
                                {row.metrics && Object.keys(row.metrics).length > 0 && (
                                  <div className="webcare-cron-drawer-metrics">
                                    <strong>Captured Telemetry Payload:</strong>
                                    <pre>{JSON.stringify(row.metrics, null, 2)}</pre>
                                  </div>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {logsTotalPages > 1 && (
            <div className="webcare-cron-pagination">
              <span className="webcare-cron-page-meta">
                Showing page {logsPage} of {logsTotalPages} ({logsTotal.toLocaleString()} total entries)
              </span>
              <div className="webcare-cron-page-btns">
                <button
                  type="button"
                  className="webcare-cron-btn webcare-cron-btn-secondary"
                  disabled={logsPage <= 1}
                  onClick={() => setLogsPage((p) => Math.max(1, p - 1))}
                >
                  <ChevronLeft size={14} />
                  <span>Previous</span>
                </button>
                <button
                  type="button"
                  className="webcare-cron-btn webcare-cron-btn-secondary"
                  disabled={logsPage >= logsTotalPages}
                  onClick={() => setLogsPage((p) => Math.min(logsTotalPages, p + 1))}
                >
                  <span>Next</span>
                  <ChevronRight size={14} />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default CronManagerPage;
