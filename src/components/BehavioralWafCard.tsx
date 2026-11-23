import { useState, useEffect } from '@wordpress/element';
import {
  Sliders,
  ShieldCheck,
  ShieldAlert,
  Shield,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Zap,
  Target,
  RotateCcw,
  Trash2,
  Search,
  ExternalLink,
  Copy,
  Check,
  Loader2,
  Terminal,
  Activity,
  SlidersHorizontal,
  Bot,
  Lock,
  Unlock,
  AlertCircle,
  Clock,
  Eye,
  Settings,
  Flame
} from 'lucide-react';
import { formatRelativeTime } from '../timeUtils';

interface BehavioralWafCardProps {
  apiRequest: (options: any) => Promise<any>;
  initialSubTab?: 'learning' | 'honeytoken' | 'ratelimit' | 'distributed';
  onSubTabChange?: (tab: 'learning' | 'honeytoken' | 'ratelimit' | 'distributed') => void;
}

export const BehavioralWafCard = ({
  apiRequest,
  initialSubTab = 'learning',
  onSubTabChange,
}: BehavioralWafCardProps) => {
  const [activeSubTab, setActiveSubTab] = useState<'learning' | 'honeytoken' | 'ratelimit' | 'distributed'>(initialSubTab);

  useEffect(() => {
    if (initialSubTab && initialSubTab !== activeSubTab) {
      setActiveSubTab(initialSubTab);
    }
  }, [initialSubTab]);

  const handleSubTabSwitch = (tab: 'learning' | 'honeytoken' | 'ratelimit' | 'distributed') => {
    setActiveSubTab(tab);
    if (onSubTabChange) {
      onSubTabChange(tab);
    }
  };
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Telemetry Data State
  const [learningStats, setLearningStats] = useState<any>({
    adaptive_enabled: true,
    total_profiles: 0,
    graduated_count: 0,
    learning_count: 0,
    total_benign_requests: 0,
    total_threats_encountered: 0,
    graduation_threshold: 25,
    graduation_confidence: 85,
  });
  const [routeProfiles, setRouteProfiles] = useState<any[]>([]);
  const [learningSettings, setLearningSettings] = useState<any>({
    adaptive_learning_enabled: true,
    auto_graduate: true,
    graduation_threshold: 25,
    graduation_confidence: 85,
  });
  const [honeytokenData, setHoneytokenData] = useState<any>({
    settings: {
      enable_form_traps: true,
      enable_phantom_endpoints: true,
      auto_ban_bot_ip: true,
      ban_duration_hours: 24,
    },
    total_caught: 0,
    active_banned_ips: 0,
    recent_catches: [],
  });
  const [rateLimiterData, setRateLimiterData] = useState<any>({
    settings: {
      enabled: true,
      auth_limit_per_min: 12,
      ajax_limit_per_min: 60,
      rest_limit_per_min: 120,
      global_limit_per_min: 240,
      enable_auto_escalation: true,
    },
    active_tracked_ips: 0,
    total_throttled_requests: 0,
    total_escalated_bans: 0,
    recent_throttled: [],
  });

  // Pillar 4: Distributed Velocity Shield State
  const [distributedData, setDistributedData] = useState<any>({
    settings: {
      enabled: true,
      checkout_fail_limit: 10,
      checkout_unique_ips_threshold: 6,
      login_fail_limit: 20,
      login_unique_ips_threshold: 10,
      auto_activate_under_attack: true,
      under_attack_duration: 900,
      under_attack_action: 'pow',
      pow_difficulty: 4,
      notify_on_attack: true,
      whitelist_ips: [],
    },
    under_attack: {
      is_active: false,
      attack_type: null,
      trigger: null,
      activated_at: null,
      expires_at: null,
      remaining_secs: 0,
      failures: 0,
      unique_ips: 0,
      action: null,
    },
    live_velocity: {
      checkout: { failures_last_min: 0, unique_ips: 0, fail_limit: 10, unique_ips_limit: 6, pct_failures: 0, pct_unique_ips: 0 },
      auth: { failures_last_min: 0, unique_ips: 0, fail_limit: 20, unique_ips_limit: 10, pct_failures: 0, pct_unique_ips: 0 },
    },
    attack_history: [],
  });
  const [simulatingAttack, setSimulatingAttack] = useState<boolean>(false);
  const [togglingAttack, setTogglingAttack] = useState<boolean>(false);

  // Filter & Action State
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [updatingRoute, setUpdatingRoute] = useState<string | null>(null);
  const [savingSettings, setSavingSettings] = useState<boolean>(false);
  const [savedBanner, setSavedBanner] = useState<'learning' | 'honeytoken' | 'ratelimit' | 'distributed' | null>(null);
  const [unbanningIp, setUnbanningIp] = useState<string | null>(null);
  const [reseedingCanaries, setReseedingCanaries] = useState<boolean>(false);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const showNotification = (type: 'success' | 'error', text: string) => {
    setNotification({ type, text });
    setTimeout(() => setNotification(null), 4500);
  };

  const copyToClipboard = (text: string, id: string) => {
    if (!text) return;
    try {
      navigator.clipboard.writeText(text);
      setCopiedText(id);
      setTimeout(() => setCopiedText(null), 2000);
    } catch {
      // ignore
    }
  };

  // Fetch full telemetry
  const fetchTelemetry = async (silent = false) => {
    if (!silent) setLoading(true);
    setRefreshing(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/behavioral/status',
        method: 'GET',
      });
      if (res?.success) {
        if (res.learning_stats) setLearningStats(res.learning_stats);
        if (res.route_profiles) setRouteProfiles(res.route_profiles);
        if (res.learning_settings) {
          const ls = res.learning_settings;
          setLearningSettings({
            ...ls,
            auto_graduate: ls.auto_graduate ?? ls.auto_graduate_mature ?? true,
          });
        }
        if (res.honeytoken) {
          const ht = res.honeytoken;
          const hts = ht.settings || {};
          setHoneytokenData({
            ...ht,
            settings: {
              ...hts,
              enable_form_traps: hts.enable_form_traps ?? hts.trap_login_forms ?? true,
              enable_phantom_endpoints: hts.enable_phantom_endpoints ?? hts.trap_phantom_endpoints ?? true,
              auto_ban_bot_ip: hts.auto_ban_bot_ip ?? true,
            },
          });
        }
        if (res.rate_limiter) {
          const rl = res.rate_limiter;
          const rls = rl.settings || {};
          setRateLimiterData({
            ...rl,
            settings: {
              ...rls,
              auth_limit_per_min: rls.auth_limit_per_min ?? rls.limit_auth ?? 12,
              ajax_limit_per_min: rls.ajax_limit_per_min ?? rls.limit_ajax ?? 60,
              rest_limit_per_min: rls.rest_limit_per_min ?? rls.limit_rest ?? 120,
              global_limit_per_min: rls.global_limit_per_min ?? rls.limit_global ?? 240,
              enable_auto_escalation: rls.enable_auto_escalation ?? rls.escalate_to_ban ?? true,
            },
          });
        }
      }

      // Fetch Distributed Velocity Shield Telemetry
      try {
        const distRes = await apiRequest({
          path: '/webcare-pro-security/v1/defense/distributed-shield/status',
          method: 'GET',
        });
        if (distRes?.success) {
          setDistributedData({
            settings: distRes.settings || {},
            under_attack: distRes.under_attack || {},
            live_velocity: distRes.live_velocity || {},
            attack_history: distRes.attack_history || [],
          });
        }
      } catch (e) {
        // silent fallback if starting up
      }
    } catch (err: any) {
      console.error('Failed to load behavioral WAF status:', err);
      showNotification('error', 'Failed to retrieve behavioral telemetry from server.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchTelemetry();
  }, []);

  // Live countdown timer for Under-Attack Mode
  useEffect(() => {
    if (!distributedData?.under_attack?.is_active || distributedData?.under_attack?.remaining_secs <= 0) {
      return;
    }
    const timer = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return;
      setDistributedData((prev: any) => {
        if (!prev?.under_attack?.is_active) return prev;
        const nextSecs = Math.max(0, (prev.under_attack.remaining_secs || 0) - 1);
        if (nextSecs === 0) {
          fetchTelemetry(true);
        }
        return {
          ...prev,
          under_attack: {
            ...prev.under_attack,
            remaining_secs: nextSecs,
          },
        };
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [distributedData?.under_attack?.is_active]);

  // Update Route Status
  const handleSetRouteStatus = async (routeKey: string, action: 'graduate' | 'enforce' | 'learn' | 'reset') => {
    setUpdatingRoute(routeKey);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/behavioral/route-status',
        method: 'POST',
        data: { route_key: routeKey, action },
      });
      if (res?.success) {
        showNotification('success', res.message || `Route status updated to ${action}.`);
        await fetchTelemetry(true);
      } else {
        showNotification('error', res?.message || 'Failed to update route status.');
      }
    } catch (err: any) {
      showNotification('error', err.message || 'Error communicating with server.');
    } finally {
      setUpdatingRoute(null);
    }
  };

  // Save Learning Mode Settings
  const handleSaveLearningSettings = async () => {
    setSavingSettings(true);
    try {
      const payload = {
        adaptive_learning_enabled: !!learningSettings.adaptive_learning_enabled,
        auto_graduate: !!learningSettings.auto_graduate,
        auto_graduate_mature: !!learningSettings.auto_graduate,
        graduation_threshold: learningSettings.graduation_threshold || 25,
        graduation_confidence: learningSettings.graduation_confidence || 85,
        auto_tune_admin_benign: learningSettings.auto_tune_admin_benign ?? true,
      };
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/behavioral/learning-settings',
        method: 'POST',
        data: payload,
      });
      if (res?.success) {
        showNotification('success', 'Learning Mode 2.0 settings saved successfully.');
        setSavedBanner('learning');
        setTimeout(() => setSavedBanner(null), 3500);
        await fetchTelemetry(true);
      } else {
        showNotification('error', res?.message || 'Failed to save settings.');
      }
    } catch (err: any) {
      showNotification('error', err.message || 'Error updating settings.');
    } finally {
      setSavingSettings(false);
    }
  };

  // Save HoneyToken Settings
  const handleSaveHoneytokenSettings = async () => {
    setSavingSettings(true);
    try {
      const formTraps = !!(honeytokenData.settings?.enable_form_traps ?? honeytokenData.settings?.trap_login_forms);
      const phantomTraps = !!(honeytokenData.settings?.enable_phantom_endpoints ?? honeytokenData.settings?.trap_phantom_endpoints);
      const autoBan = !!honeytokenData.settings?.auto_ban_bot_ip;
      const canaryAdmin = honeytokenData.settings?.enable_canary_admin !== false;
      const honeyOptions = honeytokenData.settings?.enable_honey_options !== false;

      const payload = {
        enabled: true,
        enable_form_traps: formTraps,
        trap_login_forms: formTraps,
        trap_comment_forms: formTraps,
        enable_phantom_endpoints: phantomTraps,
        trap_phantom_endpoints: phantomTraps,
        auto_ban_bot_ip: autoBan,
        enable_canary_admin: canaryAdmin,
        enable_honey_options: honeyOptions,
        ban_duration_hours: honeytokenData.settings?.ban_duration_hours || 24,
      };

      const res = await apiRequest({
        path: '/webcare-pro-security/v1/behavioral/honeytoken/settings',
        method: 'POST',
        data: payload,
      });
      if (res?.success) {
        showNotification('success', 'Honey-Token Bot Trap settings saved successfully.');
        setSavedBanner('honeytoken');
        setTimeout(() => setSavedBanner(null), 3500);
        if (res.settings) {
          setHoneytokenData((prev: any) => ({
            ...prev,
            settings: {
              ...prev.settings,
              ...res.settings,
              enable_form_traps: res.settings.enable_form_traps ?? res.settings.trap_login_forms ?? true,
              enable_phantom_endpoints: res.settings.enable_phantom_endpoints ?? res.settings.trap_phantom_endpoints ?? true,
              auto_ban_bot_ip: res.settings.auto_ban_bot_ip ?? true,
              enable_canary_admin: res.settings.enable_canary_admin !== false,
              enable_honey_options: res.settings.enable_honey_options !== false,
            },
          }));
        }
        await fetchTelemetry(true);
      } else {
        showNotification('error', res?.message || 'Failed to save settings.');
      }
    } catch (err: any) {
      showNotification('error', err.message || 'Error updating settings.');
    } finally {
      setSavingSettings(false);
    }
  };

  // Reseed / verify database canaries (Ghost Admin & Honey Options)
  const handleReseedCanaries = async () => {
    setReseedingCanaries(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/behavioral/honeytoken/reseed-db-canaries',
        method: 'POST',
      });
      if (res?.success) {
        showNotification('success', res.message || 'Database Canaries verified and seeded successfully.');
        if (res.summary) {
          setHoneytokenData(res.summary);
        }
      } else {
        showNotification('error', res?.message || 'Failed to reseed database canaries.');
      }
    } catch (err: any) {
      showNotification('error', err.message || 'Error reseeding database canaries.');
    } finally {
      setReseedingCanaries(false);
    }
  };

  // Unban HoneyToken IP
  const handleUnbanIp = async (ip: string) => {
    setUnbanningIp(ip);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/behavioral/honeytoken/unban',
        method: 'POST',
        data: { ip },
      });
      if (res?.success) {
        showNotification('success', res.message || `IP ${ip} unbanned successfully.`);
        await fetchTelemetry(true);
      } else {
        showNotification('error', res?.message || 'Failed to unban IP.');
      }
    } catch (err: any) {
      showNotification('error', err.message || 'Error unbanning IP.');
    } finally {
      setUnbanningIp(null);
    }
  };

  // Save Rate Limiter Settings
  const handleSaveRateLimiterSettings = async () => {
    setSavingSettings(true);
    try {
      const payload = {
        enabled: rateLimiterData.settings?.enabled ?? true,
        limit_auth: rateLimiterData.settings?.auth_limit_per_min || 12,
        auth_limit_per_min: rateLimiterData.settings?.auth_limit_per_min || 12,
        limit_ajax: rateLimiterData.settings?.ajax_limit_per_min || 60,
        ajax_limit_per_min: rateLimiterData.settings?.ajax_limit_per_min || 60,
        limit_rest: rateLimiterData.settings?.rest_limit_per_min || 120,
        rest_limit_per_min: rateLimiterData.settings?.rest_limit_per_min || 120,
        limit_global: rateLimiterData.settings?.global_limit_per_min || 240,
        global_limit_per_min: rateLimiterData.settings?.global_limit_per_min || 240,
        escalate_to_ban: !!rateLimiterData.settings?.enable_auto_escalation,
        enable_auto_escalation: !!rateLimiterData.settings?.enable_auto_escalation,
      };
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/behavioral/rate-limiter/settings',
        method: 'POST',
        data: payload,
      });
      if (res?.success) {
        showNotification('success', 'Adaptive Rate Limiter thresholds saved successfully.');
        setSavedBanner('ratelimit');
        setTimeout(() => setSavedBanner(null), 3500);
        await fetchTelemetry(true);
      } else {
        showNotification('error', res?.message || 'Failed to save rate limiter settings.');
      }
    } catch (err: any) {
      showNotification('error', err.message || 'Error updating settings.');
    } finally {
      setSavingSettings(false);
    }
  };

  // Save Distributed Velocity Shield Settings
  const handleSaveDistributedSettings = async () => {
    setSavingSettings(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/defense/distributed-shield/settings',
        method: 'POST',
        data: distributedData.settings,
      });
      if (res?.success) {
        showNotification('success', 'Distributed Velocity Shield settings saved successfully.');
        setSavedBanner('distributed');
        setTimeout(() => setSavedBanner(null), 3500);
        if (res.status) {
          setDistributedData(res.status);
        }
      } else {
        showNotification('error', res?.message || 'Failed to save distributed shield settings.');
      }
    } catch (err: any) {
      showNotification('error', err.message || 'Error updating settings.');
    } finally {
      setSavingSettings(false);
    }
  };

  // Toggle Under-Attack Mode
  const handleToggleUnderAttack = async (active: boolean, duration = 900) => {
    setTogglingAttack(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/defense/distributed-shield/toggle-under-attack',
        method: 'POST',
        data: { active, duration, action: distributedData.settings?.under_attack_action || 'pow' },
      });
      if (res?.success) {
        showNotification('success', res.message || 'Under-Attack mode updated.');
        await fetchTelemetry(true);
      } else {
        showNotification('error', res?.message || 'Failed to toggle Under-Attack mode.');
      }
    } catch (err: any) {
      showNotification('error', err.message || 'Error updating Under-Attack mode.');
    } finally {
      setTogglingAttack(false);
    }
  };

  // Simulate Distributed Attack Swarm
  const handleSimulateAttack = async (type: 'carding' | 'login') => {
    setSimulatingAttack(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/defense/distributed-shield/simulate',
        method: 'POST',
        data: { type },
      });
      if (res?.success) {
        showNotification('success', res.message || 'Distributed attack simulation generated.');
        if (res.under_attack) {
          setDistributedData((prev: any) => ({
            ...prev,
            under_attack: res.under_attack,
            live_velocity: res.live_velocity || prev.live_velocity,
            attack_history: res.attack_history || prev.attack_history,
          }));
        }
      } else {
        showNotification('error', res?.message || 'Failed to simulate attack.');
      }
    } catch (err: any) {
      showNotification('error', err.message || 'Error during simulation.');
    } finally {
      setSimulatingAttack(false);
    }
  };

  const formatTimer = (seconds: number) => {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  // Filtered route profiles
  const filteredProfiles = routeProfiles.filter((p: any) => {
    if (!searchFilter) return true;
    const q = searchFilter.toLowerCase();
    return (
      (p.route_key || '').toLowerCase().includes(q) ||
      (p.status || '').toLowerCase().includes(q)
    );
  });

  return (
    <div className="webcare-behavioral-waf-container">
      {/* Toast Notification */}
      {notification && (
        <div
          className={`webcare-alert ${notification.type === 'success' ? 'webcare-alert-success' : 'webcare-alert-error'}`}
          style={{
            marginBottom: '16px',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            borderRadius: '8px',
            padding: '12px 16px',
          }}
        >
          {notification.type === 'success' ? <CheckCircle2 size={18} /> : <AlertTriangle size={18} />}
          <span style={{ fontSize: '13px', fontWeight: 500 }}>{notification.text}</span>
        </div>
      )}

      {/* Header Banner Card */}
      <div className="webcare-firewall-card" style={{ marginBottom: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
              <div
                style={{
                  width: '36px',
                  height: '36px',
                  borderRadius: '10px',
                  background: 'linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#ffffff',
                }}
              >
                <Sliders size={20} />
              </div>
              <div>
                <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'inherit' }}>
                  Behavioral WAF &amp; Anti-Automated Abuse
                </h2>
                <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  Pillar 3: Adaptive Route-Aware Learning 2.0, Phantom Bot Traps &amp; Token-Bucket Rate Limiter
                </span>
              </div>
            </div>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)', maxWidth: '780px', lineHeight: 1.5 }}>
              Replaces Wordfence's blunt all-or-nothing 7-day cliff with route-by-route behavioral profiling. Catches automated credential stuffers with zero-overhead server-side decoys and throttles high-frequency volumetric scans before database or hash exhaustion.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button
              type="button"
              className="webcare-btn-secondary"
              onClick={() => fetchTelemetry()}
              disabled={refreshing}
              style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', padding: '8px 14px' }}
            >
              <RefreshCw size={14} className={refreshing ? 'webcare-spin' : ''} />
              <span>{refreshing ? 'Updating...' : 'Refresh Telemetry'}</span>
            </button>
          </div>
        </div>

        {/* 4 Top KPI Cards */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
            gap: '14px',
            marginTop: '20px',
          }}
        >
          {/* Card 1: Graduated Routes */}
          <div
            className="webcare-firewall-rule-card"
            style={{
              padding: '14px 18px',
              borderRadius: '8px',
              borderLeft: '4px solid #10b981',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)' }}>
                GRADUATED ENFORCING
              </span>
              <ShieldCheck size={18} style={{ color: '#10b981' }} />
            </div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: 'inherit' }}>
              {learningStats.graduated_count || 0}{' '}
              <span style={{ fontSize: '13px', fontWeight: 500, color: 'var(--webcare-text-muted, #64748b)' }}>
                / {learningStats.total_profiles || 0} routes
              </span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
              Actively blocking threats based on verified clean baselines
            </div>
          </div>

          {/* Card 2: Benign Requests Profiled */}
          <div
            className="webcare-firewall-rule-card"
            style={{
              padding: '14px 18px',
              borderRadius: '8px',
              borderLeft: '4px solid #4f46e5',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)' }}>
                BENIGN TRAFFIC LEARNED
              </span>
              <Activity size={18} style={{ color: '#4f46e5' }} />
            </div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: 'inherit' }}>
              {(learningStats.total_benign_requests || 0).toLocaleString()}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
              Zero-overhead non-blocking parameter schema observation
            </div>
          </div>

          {/* Card 3: HoneyToken Bot Traps */}
          <div
            className="webcare-firewall-rule-card"
            style={{
              padding: '14px 18px',
              borderRadius: '8px',
              borderLeft: '4px solid #ea580c',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)' }}>
                PHANTOM BOTS CAUGHT
              </span>
              <Bot size={18} style={{ color: '#ea580c' }} />
            </div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: 'inherit' }}>
              {honeytokenData.total_caught || 0}{' '}
              <span style={{ fontSize: '13px', fontWeight: 500, color: 'var(--webcare-text-muted, #64748b)' }}>
                ({honeytokenData.active_banned_ips || 0} active bans)
              </span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
              Banned instantly before password hashing runs
            </div>
          </div>

          {/* Card 4: Rate Limiter Throttling */}
          <div
            className="webcare-firewall-rule-card"
            style={{
              padding: '14px 18px',
              borderRadius: '8px',
              borderLeft: '4px solid #0284c7',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)' }}>
                ADAPTIVE THROTTLES
              </span>
              <Zap size={18} style={{ color: '#0284c7' }} />
            </div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: 'inherit' }}>
              {rateLimiterData.total_throttled_requests || 0}{' '}
              <span style={{ fontSize: '13px', fontWeight: 500, color: 'var(--webcare-text-muted, #64748b)' }}>
                ({rateLimiterData.active_tracked_ips || 0} active IPs)
              </span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
              HTTP 429 graceful backoff applied before harsh ban
            </div>
          </div>
        </div>
      </div>

      {/* Sub-Tabs Bar */}
      <div className="webcare-tabs-bar" style={{ marginBottom: '20px' }}>
        <button
          type="button"
          className={`webcare-tab-link ${activeSubTab === 'learning' ? 'is-active' : ''}`}
          onClick={() => handleSubTabSwitch('learning')}
        >
          <Target size={15} />
          Learning Mode 2.0 &amp; Route Profiles
        </button>

        <button
          type="button"
          className={`webcare-tab-link ${activeSubTab === 'honeytoken' ? 'is-active' : ''}`}
          onClick={() => handleSubTabSwitch('honeytoken')}
        >
          <Bot size={15} />
          Phantom Bot Traps (Honey-Tokens)
        </button>

        <button
          type="button"
          className={`webcare-tab-link ${activeSubTab === 'ratelimit' ? 'is-active' : ''}`}
          onClick={() => handleSubTabSwitch('ratelimit')}
        >
          <Zap size={15} />
          Adaptive Rate Limiter &amp; Throttling
        </button>

        <button
          type="button"
          className={`webcare-tab-link ${activeSubTab === 'distributed' ? 'is-active' : ''}`}
          onClick={() => handleSubTabSwitch('distributed')}
        >
          <Flame size={15} />
          Distributed Botnet &amp; Under-Attack Shield
          {distributedData?.under_attack?.is_active && (
            <span
              style={{
                marginLeft: '8px',
                fontSize: '10px',
                fontWeight: 700,
                background: '#dc2626',
                color: '#ffffff',
                padding: '1px 6px',
                borderRadius: '10px',
                letterSpacing: '0.4px',
              }}
            >
              UNDER ATTACK
            </span>
          )}
        </button>
      </div>

      {/* SUB-TAB 1: Learning Mode 2.0 */}
      {activeSubTab === 'learning' && (
        <div>
          {/* Controls & Search Strip */}
          <div
            className="webcare-waf-toolbar-card"
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '12px',
              padding: '14px 18px',
              borderRadius: '8px',
              marginBottom: '16px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, minWidth: '260px' }}>
              <div style={{ position: 'relative', width: '100%', maxWidth: '360px' }}>
                <Search
                  size={15}
                  style={{
                    position: 'absolute',
                    left: '10px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                    color: 'var(--webcare-text-muted, #64748b)',
                  }}
                />
                <input
                  type="text"
                  placeholder="Filter routes (e.g. rest, ajax, admin)..."
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  className="webcare-input"
                  style={{ paddingLeft: '32px', width: '100%', fontSize: '13px' }}
                />
              </div>
              {searchFilter && (
                <button
                  type="button"
                  className="webcare-btn-micro"
                  onClick={() => setSearchFilter('')}
                  style={{ fontSize: '12px' }}
                >
                  Clear
                </button>
              )}
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                Graduation Criteria: <strong>{learningSettings.graduation_threshold} requests</strong> &amp;{' '}
                <strong>{learningSettings.graduation_confidence}% confidence</strong>
              </span>
            </div>
          </div>

          {/* Route Profiling Table */}
          <div className="webcare-waf-table-card" style={{ borderRadius: '8px', overflow: 'hidden' }}>
            <table className="webcare-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
              <thead>
                <tr>
                  <th style={{ textAlign: 'left', padding: '12px 16px' }}>Route Endpoint</th>
                  <th style={{ textAlign: 'center', padding: '12px 14px', width: '130px' }}>Requests Profiled</th>
                  <th style={{ textAlign: 'center', padding: '12px 14px', width: '110px' }}>Threats Detected</th>
                  <th style={{ textAlign: 'left', padding: '12px 16px', width: '200px' }}>Confidence Score</th>
                  <th style={{ textAlign: 'center', padding: '12px 14px', width: '130px' }}>Enforcement Status</th>
                  <th style={{ textAlign: 'right', padding: '12px 16px', width: '220px' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', padding: '40px', color: 'var(--webcare-text-muted, #64748b)' }}>
                      <Loader2 size={24} className="webcare-spin" style={{ margin: '0 auto 8px' }} />
                      <div>Analyzing route profiles and behavioral schemas...</div>
                    </td>
                  </tr>
                ) : filteredProfiles.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', padding: '40px', color: 'var(--webcare-text-muted, #64748b)' }}>
                      <Shield size={28} style={{ margin: '0 auto 8px', opacity: 0.4 }} />
                      <div>No route profiles recorded yet. Traffic will profile automatically as incoming requests arrive.</div>
                    </td>
                  </tr>
                ) : (
                  filteredProfiles.map((p: any) => {
                    const isGraduated = p.status === 'graduated' || p.forced_status === 'enforcing';
                    const isForcedLearning = p.forced_status === 'learning';
                    const isUpdating = updatingRoute === p.route_key;

                    return (
                      <tr key={p.route_key} className="webcare-waf-ip-row">
                        <td style={{ padding: '12px 16px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span
                              style={{
                                fontFamily: 'monospace',
                                fontWeight: 600,
                                fontSize: '13px',
                                color: 'var(--webcare-accent-cyan, #0284c7)',
                              }}
                            >
                              {p.route_key}
                            </span>
                            {p.forced_status && (
                              <span
                                className="webcare-badge-pill"
                                style={{
                                  fontSize: '10px',
                                  padding: '2px 6px',
                                  background: 'rgba(99, 102, 241, 0.1)',
                                  color: '#4f46e5',
                                  border: '1px solid rgba(99, 102, 241, 0.3)',
                                }}
                              >
                                Forced {p.forced_status}
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
                            Params learned: {Object.keys(p.learned_params || {}).length} parameters • Last seen{' '}
                            {formatRelativeTime(p.last_seen)}
                          </div>
                        </td>

                        <td style={{ textAlign: 'center', padding: '12px 14px', fontWeight: 600 }}>
                          {(p.benign_count || p.request_count || 0).toLocaleString()}
                        </td>

                        <td style={{ textAlign: 'center', padding: '12px 14px' }}>
                          {p.threat_count > 0 ? (
                            <span
                              style={{
                                color: '#dc2626',
                                fontWeight: 600,
                                background: 'rgba(239, 68, 68, 0.1)',
                                padding: '2px 8px',
                                borderRadius: '4px',
                              }}
                            >
                              {p.threat_count}
                            </span>
                          ) : (
                            <span style={{ color: 'var(--webcare-text-muted, #64748b)' }}>0</span>
                          )}
                        </td>

                        <td style={{ padding: '12px 16px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <div
                              style={{
                                flex: 1,
                                height: '8px',
                                borderRadius: '4px',
                                background: 'var(--webcare-bg-surface, #e2e8f0)',
                                overflow: 'hidden',
                              }}
                            >
                              <div
                                style={{
                                  width: `${Math.min(100, Math.max(0, p.confidence || 0))}%`,
                                  height: '100%',
                                  background:
                                    (p.confidence || 0) >= 85
                                      ? '#10b981'
                                      : (p.confidence || 0) >= 50
                                      ? '#4f46e5'
                                      : '#f59e0b',
                                  transition: 'width 0.3s ease',
                                }}
                              />
                            </div>
                            <span style={{ fontSize: '12px', fontWeight: 600, minWidth: '35px' }}>
                              {p.confidence || 0}%
                            </span>
                          </div>
                        </td>

                        <td style={{ textAlign: 'center', padding: '12px 14px' }}>
                          {isGraduated && !isForcedLearning ? (
                            <span
                              className="webcare-badge-pill"
                              style={{
                                background: 'rgba(16, 185, 129, 0.12)',
                                color: '#047857',
                                border: '1px solid rgba(16, 185, 129, 0.3)',
                                fontSize: '11px',
                                padding: '3px 8px',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px',
                              }}
                            >
                              <ShieldCheck size={12} />
                              ENFORCING
                            </span>
                          ) : (
                            <span
                              className="webcare-badge-pill"
                              style={{
                                background: 'rgba(245, 158, 11, 0.12)',
                                color: '#b45309',
                                border: '1px solid rgba(245, 158, 11, 0.3)',
                                fontSize: '11px',
                                padding: '3px 8px',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px',
                              }}
                            >
                              <Activity size={12} />
                              LEARNING
                            </span>
                          )}
                        </td>

                        <td style={{ textAlign: 'right', padding: '12px 16px' }}>
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                            {isGraduated && !isForcedLearning ? (
                              <button
                                type="button"
                                className="webcare-btn-micro"
                                onClick={() => handleSetRouteStatus(p.route_key, 'learn')}
                                disabled={isUpdating}
                                title="Force back into learning mode"
                                style={{ fontSize: '11px' }}
                              >
                                {isUpdating ? <Loader2 size={11} className="webcare-spin" /> : 'Force Learn'}
                              </button>
                            ) : (
                              <button
                                type="button"
                                className="webcare-btn-micro webcare-action-btn-clean"
                                onClick={() => handleSetRouteStatus(p.route_key, 'enforce')}
                                disabled={isUpdating}
                                title="Graduate immediately into active blocking"
                                style={{ fontSize: '11px' }}
                              >
                                {isUpdating ? <Loader2 size={11} className="webcare-spin" /> : 'Force Enforce'}
                              </button>
                            )}

                            <button
                              type="button"
                              className="webcare-btn-micro"
                              onClick={() => handleSetRouteStatus(p.route_key, 'reset')}
                              disabled={isUpdating}
                              title="Wipe learned parameters and recalibrate"
                              style={{ fontSize: '11px', color: '#dc2626' }}
                            >
                              <RotateCcw size={11} />
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

          {/* Learning Settings Card */}
          <div className="webcare-firewall-card" style={{ marginTop: '20px' }}>
            <h3 style={{ fontSize: '15px', fontWeight: 700, margin: '0 0 14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Settings size={16} />
              Learning Mode 2.0 Automation Settings
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px' }}>
              <div>
                <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer', marginBottom: '10px' }}>
                  <input
                    type="checkbox"
                    checked={!!learningSettings.adaptive_learning_enabled}
                    onChange={(e) => setLearningSettings({ ...learningSettings, adaptive_learning_enabled: e.target.checked })}
                    style={{ width: '16px', height: '16px', accentColor: '#4f46e5' }}
                  />
                  <div>
                    <span style={{ fontSize: '13px', fontWeight: 600 }}>Enable Route-Aware Learning Engine</span>
                    <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                      Profiles parameters per endpoint to prevent false positives on custom themes and plugins.
                    </div>
                  </div>
                </label>

                <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={!!learningSettings.auto_graduate}
                    onChange={(e) => setLearningSettings({ ...learningSettings, auto_graduate: e.target.checked })}
                    style={{ width: '16px', height: '16px', accentColor: '#4f46e5' }}
                  />
                  <div>
                    <span style={{ fontSize: '13px', fontWeight: 600 }}>Automatic Route Graduation</span>
                    <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                      Automatically promote routes into active blocking once request &amp; confidence thresholds are satisfied.
                    </div>
                  </div>
                </label>
              </div>

              <div>
                <div style={{ marginBottom: '12px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <span style={{ fontSize: '12px', fontWeight: 600 }}>Graduation Request Threshold</span>
                    <span style={{ fontSize: '12px', fontWeight: 700, color: '#4f46e5' }}>
                      {learningSettings.graduation_threshold} requests
                    </span>
                  </div>
                  <input
                    type="range"
                    min="10"
                    max="100"
                    step="5"
                    value={learningSettings.graduation_threshold || 25}
                    onChange={(e) => setLearningSettings({ ...learningSettings, graduation_threshold: parseInt(e.target.value) })}
                    style={{ width: '100%', accentColor: '#4f46e5' }}
                  />
                </div>

                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <span style={{ fontSize: '12px', fontWeight: 600 }}>Required Confidence Score</span>
                    <span style={{ fontSize: '12px', fontWeight: 700, color: '#4f46e5' }}>
                      {learningSettings.graduation_confidence}%
                    </span>
                  </div>
                  <input
                    type="range"
                    min="50"
                    max="95"
                    step="5"
                    value={learningSettings.graduation_confidence || 85}
                    onChange={(e) => setLearningSettings({ ...learningSettings, graduation_confidence: parseInt(e.target.value) })}
                    style={{ width: '100%', accentColor: '#4f46e5' }}
                  />
                </div>
              </div>
            </div>

            <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: '12px' }}>
              {savedBanner === 'learning' && (
                <span style={{ fontSize: '13px', color: '#10b981', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <CheckCircle2 size={16} /> Learning Settings Saved!
                </span>
              )}
              <button
                type="button"
                className="webcare-btn-primary"
                onClick={handleSaveLearningSettings}
                disabled={savingSettings}
                style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', padding: '8px 16px' }}
              >
                {savingSettings ? <Loader2 size={14} className="webcare-spin" /> : <Check size={14} />}
                <span>Save Learning Settings</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB 2: Honey-Token Bot Traps */}
      {activeSubTab === 'honeytoken' && (
        <div>
          {/* Trap Architecture Strip */}
          <div
            className="webcare-firewall-card"
            style={{
              padding: '16px 20px',
              borderRadius: '8px',
              marginBottom: '20px',
              background: 'linear-gradient(135deg, rgba(79, 70, 229, 0.04) 0%, rgba(234, 88, 12, 0.04) 100%)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
              <Bot size={28} style={{ color: '#ea580c', flexShrink: 0, marginTop: '2px' }} />
              <div>
                <h4 style={{ margin: '0 0 6px', fontSize: '15px', fontWeight: 700 }}>
                  Zero-Friction Phantom Decoys &amp; Honeypot Form Traps
                </h4>
                <p style={{ margin: 0, fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5 }}>
                  Automated headless bots and credential-stuffers blindly fill invisible form inputs (hidden from legitimate humans via CSS off-screen clip) or probe alluring phantom paths like <code>/.well-known/webcare-security-decoy</code> and <code>/wp-content/debug_dump.sql</code>. Intercepting here executes an instant IP ban, protecting PHP worker threads from heavy bcrypt/Argon2 password hashing loops.
                </p>
              </div>
            </div>
          </div>

          {/* Bot Trap Settings */}
          <div className="webcare-firewall-card" style={{ marginBottom: '20px' }}>
            <h3 style={{ fontSize: '15px', fontWeight: 700, margin: '0 0 16px' }}>
              Honey-Token Decoy Configuration
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '16px' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={!!(honeytokenData.settings?.enable_form_traps ?? honeytokenData.settings?.trap_login_forms)}
                  onChange={(e) =>
                    setHoneytokenData({
                      ...honeytokenData,
                      settings: {
                        ...honeytokenData.settings,
                        enable_form_traps: e.target.checked,
                        trap_login_forms: e.target.checked,
                        trap_comment_forms: e.target.checked,
                      },
                    })
                  }
                  style={{ width: '16px', height: '16px', accentColor: '#ea580c' }}
                />
                <div>
                  <span style={{ fontSize: '13px', fontWeight: 600 }}>Invisible Honeypot Form Fields</span>
                  <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    Renders invisible decoy fields on wp-login.php, registration, lost-password, and comment forms.
                  </div>
                </div>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={!!(honeytokenData.settings?.enable_phantom_endpoints ?? honeytokenData.settings?.trap_phantom_endpoints)}
                  onChange={(e) =>
                    setHoneytokenData({
                      ...honeytokenData,
                      settings: {
                        ...honeytokenData.settings,
                        enable_phantom_endpoints: e.target.checked,
                        trap_phantom_endpoints: e.target.checked,
                      },
                    })
                  }
                  style={{ width: '16px', height: '16px', accentColor: '#ea580c' }}
                />
                <div>
                  <span style={{ fontSize: '13px', fontWeight: 600 }}>Phantom Decoy Endpoints</span>
                  <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    Monitors alluring decoy URLs (e.g. <code>/xmlrpc_backup.php</code>, <code>/wp-json/webcare-honeytoken/v1/auth</code>).
                  </div>
                </div>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={!!honeytokenData.settings?.auto_ban_bot_ip}
                  onChange={(e) =>
                    setHoneytokenData({
                      ...honeytokenData,
                      settings: { ...honeytokenData.settings, auto_ban_bot_ip: e.target.checked },
                    })
                  }
                  style={{ width: '16px', height: '16px', accentColor: '#ea580c' }}
                />
                <div>
                  <span style={{ fontSize: '13px', fontWeight: 600 }}>Instant IP Ban Upon Trigger</span>
                  <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    Instantly writes offending IP into active ban table with zero false-positive tolerance.
                  </div>
                </div>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={honeytokenData.settings?.enable_canary_admin !== false}
                  onChange={(e) =>
                    setHoneytokenData({
                      ...honeytokenData,
                      settings: { ...honeytokenData.settings, enable_canary_admin: e.target.checked },
                    })
                  }
                  style={{ width: '16px', height: '16px', accentColor: '#ea580c' }}
                />
                <div>
                  <span style={{ fontSize: '13px', fontWeight: 600 }}>Ghost Admin Canary User (Pillar 8)</span>
                  <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    Seeds dormant <code>webcare_canary_admin</code> with impossible password hash. Any login attempt triggers an immediate IP ban &amp; critical breach alert.
                  </div>
                </div>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={honeytokenData.settings?.enable_honey_options !== false}
                  onChange={(e) =>
                    setHoneytokenData({
                      ...honeytokenData,
                      settings: { ...honeytokenData.settings, enable_honey_options: e.target.checked },
                    })
                  }
                  style={{ width: '16px', height: '16px', accentColor: '#ea580c' }}
                />
                <div>
                  <span style={{ fontSize: '13px', fontWeight: 600 }}>Database Honey Options (Pillar 8)</span>
                  <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    Plants decoy AWS &amp; Stripe secrets in <code>wp_options</code>. Any unauthorized <code>get_option()</code> or SQL dump exfiltration trips an instant alarm.
                  </div>
                </div>
              </label>
            </div>

            <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: '12px' }}>
              {savedBanner === 'honeytoken' && (
                <span style={{ fontSize: '13px', color: '#10b981', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <CheckCircle2 size={16} /> Bot Trap Settings Saved!
                </span>
              )}
              <button
                type="button"
                className="webcare-btn-primary"
                onClick={handleSaveHoneytokenSettings}
                disabled={savingSettings}
                style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', padding: '8px 16px' }}
              >
                {savingSettings ? <Loader2 size={14} className="webcare-spin" /> : <Check size={14} />}
                <span>Save Bot Trap Settings</span>
              </button>
            </div>
          </div>

          {/* Database Canary & Ghost Admin Tripwire Monitor Card */}
          <div className="webcare-firewall-card" style={{ marginBottom: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <h3 style={{ fontSize: '15px', fontWeight: 700, margin: 0 }}>
                    Database Canary Honey-Tokens &amp; Ghost Admin Sentinel
                  </h3>
                  <span className="webcare-badge-pill" style={{ background: '#ecfdf5', color: '#047857', border: '1px solid #a7f3d0' }}>
                    Active Tripwires
                  </span>
                </div>
                <p style={{ margin: '4px 0 0', fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>
                  Deceptive database tripwires planted deep inside <code>wp_users</code> and <code>wp_options</code> to detect SQL injections, compromised plugins, or database dump reuse before real data is attacked.
                </p>
              </div>

              <button
                type="button"
                className="webcare-btn webcare-btn-secondary"
                onClick={handleReseedCanaries}
                disabled={reseedingCanaries}
                style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '12px' }}
              >
                <RefreshCw size={13} className={reseedingCanaries ? 'webcare-spin' : ''} />
                <span>{reseedingCanaries ? 'Reseeding...' : 'Verify &amp; Reseed Canaries'}</span>
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', marginTop: '16px' }}>
              {/* Tripwire 1: Ghost Admin User */}
              <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--webcare-bg-surface, #f8fafc)', border: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <strong style={{ fontSize: '13px', color: 'var(--webcare-text-heading, #0f172a)' }}>Ghost Admin Canary User</strong>
                  <span
                    className="webcare-badge-pill"
                    style={{
                      background: honeytokenData.canary_admin_active ? '#ecfdf5' : '#fef2f2',
                      color: honeytokenData.canary_admin_active ? '#047857' : '#dc2626',
                      border: `1px solid ${honeytokenData.canary_admin_active ? '#a7f3d0' : '#fecaca'}`,
                    }}
                  >
                    {honeytokenData.canary_admin_active ? 'Seeded & Armed' : 'Pending Seed'}
                  </span>
                </div>
                <div style={{ marginTop: '8px', fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>
                  Username: <code style={{ color: '#4f46e5', fontWeight: 600 }}>{honeytokenData.canary_admin_user || 'webcare_canary_admin'}</code>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                  Role: Administrator &bull; Password: Cryptographically Impossible &bull; Auto-Ban on Auth
                </div>
              </div>

              {/* Tripwire 2: Decoy Database Options */}
              <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--webcare-bg-surface, #f8fafc)', border: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <strong style={{ fontSize: '13px', color: 'var(--webcare-text-heading, #0f172a)' }}>Decoy Database Options</strong>
                  <span
                    className="webcare-badge-pill"
                    style={{
                      background: honeytokenData.honey_options_seeded ? '#ecfdf5' : '#fef2f2',
                      color: honeytokenData.honey_options_seeded ? '#047857' : '#dc2626',
                      border: `1px solid ${honeytokenData.honey_options_seeded ? '#a7f3d0' : '#fecaca'}`,
                    }}
                  >
                    {honeytokenData.honey_options_seeded ? 'Planted (3 Keys)' : 'Pending Seed'}
                  </span>
                </div>
                <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', display: 'flex', flexDirection: 'column', gap: '2px' }}>
                  <code>_webcareproscan_canary_aws_secret</code>
                  <code>_webcareproscan_canary_stripe_secret</code>
                  <code>_webcareproscan_canary_vault_backup</code>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                  Trapped via <code>pre_option_*</code> filters with immediate IP isolation upon unauthorized read.
                </div>
              </div>
            </div>
          </div>

          {/* Caught Bots Ledger */}
          <div className="webcare-waf-table-card" style={{ borderRadius: '8px', overflow: 'hidden' }}>
            <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--webcare-border-table, #e2e8f0)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 700 }}>
                Recent Caught Bots &amp; Automated Probes
              </h4>
              <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                Total Trapped: <strong>{honeytokenData.total_caught || 0}</strong>
              </span>
            </div>

            <table className="webcare-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
              <thead>
                <tr>
                  <th style={{ textAlign: 'left', padding: '12px 16px' }}>Bot IP Address</th>
                  <th style={{ textAlign: 'center', padding: '12px 14px', width: '180px' }}>Trap Triggered</th>
                  <th style={{ textAlign: 'left', padding: '12px 16px' }}>Decoy Target / Endpoint</th>
                  <th style={{ textAlign: 'left', padding: '12px 16px', width: '160px' }}>Timestamp</th>
                  <th style={{ textAlign: 'right', padding: '12px 16px', width: '140px' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {honeytokenData.recent_catches?.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ textAlign: 'center', padding: '40px', color: 'var(--webcare-text-muted, #64748b)' }}>
                      <CheckCircle2 size={28} style={{ color: '#10b981', margin: '0 auto 8px' }} />
                      <div>No automated bots have triggered the honeytoken traps recently. Your site is calm.</div>
                    </td>
                  </tr>
                ) : (
                  honeytokenData.recent_catches?.map((c: any, idx: number) => {
                    const isUnbanning = unbanningIp === c.ip;
                    return (
                      <tr key={idx} className="webcare-waf-ip-row">
                        <td style={{ padding: '12px 16px' }}>
                          <span
                            style={{
                              fontFamily: 'monospace',
                              fontWeight: 600,
                              fontSize: '13px',
                              color: 'var(--webcare-accent-cyan, #0284c7)',
                            }}
                          >
                            {c.ip}
                          </span>
                        </td>

                        <td style={{ textAlign: 'center', padding: '12px 14px' }}>
                          <span
                            className="webcare-badge-pill"
                            style={{
                              background: 'rgba(234, 88, 12, 0.12)',
                              color: '#ea580c',
                              border: '1px solid rgba(234, 88, 12, 0.3)',
                              fontSize: '11px',
                              padding: '2px 8px',
                            }}
                          >
                            {c.trap_type || 'Phantom Trap'}
                          </span>
                        </td>

                        <td style={{ padding: '12px 16px' }}>
                          <span style={{ fontFamily: 'monospace', fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>
                            {c.endpoint || '/wp-login.php'}
                          </span>
                        </td>

                        <td style={{ padding: '12px 16px', fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                          {formatRelativeTime(c.timestamp)}
                        </td>

                        <td style={{ textAlign: 'right', padding: '12px 16px' }}>
                          <button
                            type="button"
                            className="webcare-btn-micro"
                            onClick={() => handleUnbanIp(c.ip)}
                            disabled={isUnbanning}
                            style={{ fontSize: '11px' }}
                          >
                            {isUnbanning ? <Loader2 size={11} className="webcare-spin" /> : 'Unban IP'}
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SUB-TAB 3: Adaptive Rate Limiter */}
      {activeSubTab === 'ratelimit' && (
        <div>
          {/* Rate Limiting Explanation Banner */}
          <div
            className="webcare-firewall-card"
            style={{
              padding: '16px 20px',
              borderRadius: '8px',
              marginBottom: '20px',
              background: 'linear-gradient(135deg, rgba(2, 132, 199, 0.04) 0%, rgba(99, 102, 241, 0.04) 100%)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
              <Zap size={28} style={{ color: '#0284c7', flexShrink: 0, marginTop: '2px' }} />
              <div>
                <h4 style={{ margin: '0 0 6px', fontSize: '15px', fontWeight: 700 }}>
                  Sliding-Window Token-Bucket Smart Throttler
                </h4>
                <p style={{ margin: 0, fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5 }}>
                  Prevents false positives on corporate NATs and shared office networks. Instead of dropping traffic immediately with harsh permanent IP bans, the throttler applies <strong>Tier 1 HTTP 429 Too Many Requests</strong> with standard <code>Retry-After</code> headers. If a client continues rapid-fire requests exceeding 2.5x the threshold, Tier 2 escalation automatically executes a firewall block.
                </p>
              </div>
            </div>
          </div>

          {/* Rate Limiter Sliders Form */}
          <div className="webcare-firewall-card" style={{ marginBottom: '20px' }}>
            <h3 style={{ fontSize: '15px', fontWeight: 700, margin: '0 0 16px' }}>
              Adaptive Rate Limiting Bucket Thresholds
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '24px' }}>
              {/* Bucket 1: Auth */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 600 }}>Auth &amp; Login Requests</span>
                  <span style={{ fontSize: '13px', fontWeight: 700, color: '#dc2626' }}>
                    {rateLimiterData.settings?.auth_limit_per_min || 12} req / min
                  </span>
                </div>
                <input
                  type="range"
                  min="5"
                  max="60"
                  step="1"
                  value={rateLimiterData.settings?.auth_limit_per_min || 12}
                  onChange={(e) =>
                    setRateLimiterData({
                      ...rateLimiterData,
                      settings: { ...rateLimiterData.settings, auth_limit_per_min: parseInt(e.target.value) },
                    })
                  }
                  style={{ width: '100%', accentColor: '#dc2626' }}
                />
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                  Covers wp-login.php, xmlrpc.php, and password resets
                </div>
              </div>

              {/* Bucket 2: Admin AJAX */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 600 }}>Admin-AJAX Endpoints</span>
                  <span style={{ fontSize: '13px', fontWeight: 700, color: '#ea580c' }}>
                    {rateLimiterData.settings?.ajax_limit_per_min || 60} req / min
                  </span>
                </div>
                <input
                  type="range"
                  min="20"
                  max="240"
                  step="10"
                  value={rateLimiterData.settings?.ajax_limit_per_min || 60}
                  onChange={(e) =>
                    setRateLimiterData({
                      ...rateLimiterData,
                      settings: { ...rateLimiterData.settings, ajax_limit_per_min: parseInt(e.target.value) },
                    })
                  }
                  style={{ width: '100%', accentColor: '#ea580c' }}
                />
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                  Covers admin-ajax.php background and heartbeat polls
                </div>
              </div>

              {/* Bucket 3: REST API */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 600 }}>REST API Endpoints</span>
                  <span style={{ fontSize: '13px', fontWeight: 700, color: '#4f46e5' }}>
                    {rateLimiterData.settings?.rest_limit_per_min || 120} req / min
                  </span>
                </div>
                <input
                  type="range"
                  min="30"
                  max="300"
                  step="10"
                  value={rateLimiterData.settings?.rest_limit_per_min || 120}
                  onChange={(e) =>
                    setRateLimiterData({
                      ...rateLimiterData,
                      settings: { ...rateLimiterData.settings, rest_limit_per_min: parseInt(e.target.value) },
                    })
                  }
                  style={{ width: '100%', accentColor: '#4f46e5' }}
                />
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                  Covers /wp-json/ endpoints and headless frontend calls
                </div>
              </div>

              {/* Bucket 4: Global Public Endpoints */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 600 }}>Global Public Endpoints</span>
                  <span style={{ fontSize: '13px', fontWeight: 700, color: '#0284c7' }}>
                    {rateLimiterData.settings?.global_limit_per_min || 240} req / min
                  </span>
                </div>
                <input
                  type="range"
                  min="60"
                  max="600"
                  step="20"
                  value={rateLimiterData.settings?.global_limit_per_min || 240}
                  onChange={(e) =>
                    setRateLimiterData({
                      ...rateLimiterData,
                      settings: { ...rateLimiterData.settings, global_limit_per_min: parseInt(e.target.value) },
                    })
                  }
                  style={{ width: '100%', accentColor: '#0284c7' }}
                />
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                  Covers all frontend pages, archive feeds, and searches
                </div>
              </div>
            </div>

            <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={!!rateLimiterData.settings?.enable_auto_escalation}
                  onChange={(e) =>
                    setRateLimiterData({
                      ...rateLimiterData,
                      settings: { ...rateLimiterData.settings, enable_auto_escalation: e.target.checked },
                    })
                  }
                  style={{ width: '16px', height: '16px', accentColor: '#4f46e5' }}
                />
                <span style={{ fontSize: '13px', fontWeight: 600 }}>
                  Escalate repeated abusers (&gt; 2.5x threshold) to firewall ban
                </span>
              </label>

              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                {savedBanner === 'ratelimit' && (
                  <span style={{ fontSize: '13px', color: '#10b981', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <CheckCircle2 size={16} /> Rate Limits Saved!
                  </span>
                )}
                <button
                  type="button"
                  className="webcare-btn-primary"
                  onClick={handleSaveRateLimiterSettings}
                  disabled={savingSettings}
                  style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', padding: '8px 16px' }}
                >
                  {savingSettings ? <Loader2 size={14} className="webcare-spin" /> : <Check size={14} />}
                  <span>Save Rate Limiting Thresholds</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB 4: Distributed Botnet & Under-Attack Shield (Pillar 4) */}
      {activeSubTab === 'distributed' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Under-Attack Mode Live Command Banner */}
          {distributedData?.under_attack?.is_active ? (
            <div
              className="webcare-firewall-card"
              style={{
                padding: '20px 24px',
                borderRadius: '8px',
                background: '#fef2f2',
                border: '2px solid #ef4444',
                boxShadow: '0 4px 16px rgba(239, 68, 68, 0.15)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
                  <Flame size={32} style={{ color: '#dc2626', flexShrink: 0, marginTop: '2px' }} />
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                      <span style={{ fontSize: '11px', fontWeight: 800, textTransform: 'uppercase', background: '#dc2626', color: '#ffffff', padding: '2px 8px', borderRadius: '4px', letterSpacing: '0.5px' }}>
                        UNDER-ATTACK LOCKDOWN ACTIVE
                      </span>
                      <span style={{ fontSize: '13px', fontWeight: 700, color: '#991b1b' }}>
                        Triggered by: {distributedData.under_attack.attack_type === 'carding_swarm' ? 'WooCommerce Carding Botnet Swarm' : (distributedData.under_attack.attack_type === 'credential_stuffing_swarm' ? 'Distributed Credential Stuffing Swarm' : 'Manual Administrator Lockdown')}
                      </span>
                    </div>
                    <p style={{ margin: 0, fontSize: '13px', color: '#7f1d1d', lineHeight: 1.5 }}>
                      Detected <strong>{distributedData.under_attack.failures} failures</strong> across <strong>{distributedData.under_attack.unique_ips} distinct residential proxy IPs</strong> in 60s. Client-side WebCrypto Proof-of-Work (PoW) verification challenge is actively enforced on checkouts and logins to neutralize headless AI bot swarms.
                    </p>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '11px', fontWeight: 600, color: '#991b1b', textTransform: 'uppercase' }}>Auto-Revert In</div>
                    <div style={{ fontSize: '22px', fontWeight: 800, fontFamily: 'monospace', color: '#dc2626' }}>
                      {formatTimer(distributedData.under_attack.remaining_secs || 0)}
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => handleToggleUnderAttack(false)}
                    disabled={togglingAttack}
                    style={{
                      background: '#dc2626',
                      color: '#ffffff',
                      border: 'none',
                      padding: '10px 18px',
                      borderRadius: '6px',
                      fontWeight: 700,
                      fontSize: '13px',
                      cursor: togglingAttack ? 'not-allowed' : 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                    }}
                  >
                    {togglingAttack ? <Loader2 size={14} className="webcare-spin" /> : <RotateCcw size={14} />}
                    <span>Stand Down / Deactivate</span>
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div
              className="webcare-firewall-card"
              style={{
                padding: '18px 22px',
                borderRadius: '8px',
                background: 'var(--webcare-bg-surface, #f8fafc)',
                border: '1px solid var(--webcare-border-std, #e2e8f0)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
                  <ShieldCheck size={28} style={{ color: '#10b981', flexShrink: 0, marginTop: '2px' }} />
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                      <span style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', background: '#ecfdf5', color: '#059669', border: '1px solid #a7f3d0', padding: '2px 8px', borderRadius: '4px' }}>
                        Posture: Normal / Passive Velocity Guard Active
                      </span>
                    </div>
                    <p style={{ margin: 0, fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5 }}>
                      Aggregating real-time failure velocity across all visitor and residential proxy IPs. If an AI carding swarm (&gt; {distributedData.settings?.checkout_fail_limit || 10} failed checkouts across {distributedData.settings?.checkout_unique_ips_threshold || 6} IPs) or credential-stuffing swarm strikes, Under-Attack Mode engages automatically.
                    </p>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <button
                    type="button"
                    onClick={() => handleToggleUnderAttack(true, 900)}
                    disabled={togglingAttack}
                    style={{
                      background: '#4f46e5',
                      color: '#ffffff',
                      border: 'none',
                      padding: '8px 16px',
                      borderRadius: '6px',
                      fontWeight: 700,
                      fontSize: '12px',
                      cursor: togglingAttack ? 'not-allowed' : 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                    }}
                  >
                    {togglingAttack ? <Loader2 size={14} className="webcare-spin" /> : <Flame size={14} />}
                    <span>Manually Engage Under-Attack Mode (15m)</span>
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Live Velocity Gauges (Sliding 60-Second Window across ALL IPs) */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
            {/* Gauge 1: E-Commerce Carding Velocity */}
            <div className="webcare-firewall-card" style={{ padding: '20px', borderRadius: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                <span style={{ fontSize: '12px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--webcare-text-muted, #64748b)', letterSpacing: '0.5px' }}>
                  WooCommerce Carding Velocity (60s)
                </span>
                <span style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  padding: '2px 8px',
                  borderRadius: '10px',
                  background: (distributedData.live_velocity?.checkout?.pct_failures || 0) > 80 ? '#fef2f2' : '#ecfdf5',
                  color: (distributedData.live_velocity?.checkout?.pct_failures || 0) > 80 ? '#dc2626' : '#059669',
                  border: (distributedData.live_velocity?.checkout?.pct_failures || 0) > 80 ? '1px solid #fecaca' : '1px solid #a7f3d0',
                }}>
                  {(distributedData.live_velocity?.checkout?.pct_failures || 0) > 80 ? 'Critical Swarm' : 'Normal Traffic'}
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '6px' }}>
                <div style={{ fontSize: '28px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  {distributedData.live_velocity?.checkout?.failures_last_min || 0}
                </div>
                <div style={{ fontSize: '13px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  / {distributedData.settings?.checkout_fail_limit || 10} failed checkouts
                </div>
              </div>

              {/* Progress Bar */}
              <div style={{ height: '6px', width: '100%', background: '#e2e8f0', borderRadius: '3px', overflow: 'hidden', marginBottom: '12px' }}>
                <div style={{
                  height: '100%',
                  width: `${Math.min(100, distributedData.live_velocity?.checkout?.pct_failures || 0)}%`,
                  background: (distributedData.live_velocity?.checkout?.pct_failures || 0) > 80 ? '#dc2626' : ((distributedData.live_velocity?.checkout?.pct_failures || 0) > 50 ? '#ea580c' : '#10b981'),
                  borderRadius: '3px',
                  transition: 'width 0.3s ease',
                }} />
              </div>

              <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', display: 'flex', justifyContent: 'space-between' }}>
                <span>Unique Residential IPs in 60s:</span>
                <span style={{ fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  {distributedData.live_velocity?.checkout?.unique_ips || 0} / {distributedData.settings?.checkout_unique_ips_threshold || 6}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '6px' }}>
                Aggregates Stripe/PayPal payment rejects, carding errors, and checkout drops across all visitor IPs.
              </div>
            </div>

            {/* Gauge 2: Distributed Credential Stuffing Velocity */}
            <div className="webcare-firewall-card" style={{ padding: '20px', borderRadius: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                <span style={{ fontSize: '12px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--webcare-text-muted, #64748b)', letterSpacing: '0.5px' }}>
                  Credential Stuffing Velocity (60s)
                </span>
                <span style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  padding: '2px 8px',
                  borderRadius: '10px',
                  background: (distributedData.live_velocity?.auth?.pct_failures || 0) > 80 ? '#fef2f2' : '#ecfdf5',
                  color: (distributedData.live_velocity?.auth?.pct_failures || 0) > 80 ? '#dc2626' : '#059669',
                  border: (distributedData.live_velocity?.auth?.pct_failures || 0) > 80 ? '1px solid #fecaca' : '1px solid #a7f3d0',
                }}>
                  {(distributedData.live_velocity?.auth?.pct_failures || 0) > 80 ? 'Critical Swarm' : 'Normal Traffic'}
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '6px' }}>
                <div style={{ fontSize: '28px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  {distributedData.live_velocity?.auth?.failures_last_min || 0}
                </div>
                <div style={{ fontSize: '13px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  / {distributedData.settings?.login_fail_limit || 20} failed logins
                </div>
              </div>

              {/* Progress Bar */}
              <div style={{ height: '6px', width: '100%', background: '#e2e8f0', borderRadius: '3px', overflow: 'hidden', marginBottom: '12px' }}>
                <div style={{
                  height: '100%',
                  width: `${Math.min(100, distributedData.live_velocity?.auth?.pct_failures || 0)}%`,
                  background: (distributedData.live_velocity?.auth?.pct_failures || 0) > 80 ? '#dc2626' : ((distributedData.live_velocity?.auth?.pct_failures || 0) > 50 ? '#ea580c' : '#10b981'),
                  borderRadius: '3px',
                  transition: 'width 0.3s ease',
                }} />
              </div>

              <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', display: 'flex', justifyContent: 'space-between' }}>
                <span>Unique Residential IPs in 60s:</span>
                <span style={{ fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  {distributedData.live_velocity?.auth?.unique_ips || 0} / {distributedData.settings?.login_unique_ips_threshold || 10}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '6px' }}>
                Aggregates failed login credentials on wp-login.php, XML-RPC, and REST authentication.
              </div>
            </div>
          </div>

          {/* Attack Simulation Laboratory Strip */}
          <div
            className="webcare-firewall-card"
            style={{
              padding: '16px 20px',
              borderRadius: '8px',
              background: 'linear-gradient(135deg, rgba(79, 70, 229, 0.04) 0%, rgba(2, 132, 199, 0.04) 100%)',
              border: '1px solid var(--webcare-border-std, #e2e8f0)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
              <div>
                <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  Distributed Botnet Simulation &amp; Readiness Drills
                </h4>
                <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  Simulate incoming distributed attacks from synthetic residential proxy networks to verify threshold triggering and WebCrypto PoW defense.
                </p>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  onClick={() => handleSimulateAttack('carding')}
                  disabled={simulatingAttack}
                  style={{
                    background: '#ffffff',
                    color: '#c2410c',
                    border: '1px solid #fed7aa',
                    padding: '6px 14px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: simulatingAttack ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                  }}
                >
                  {simulatingAttack ? <Loader2 size={12} className="webcare-spin" /> : <Flame size={12} />}
                  <span>+ Test Carding Swarm (12 IPs)</span>
                </button>

                <button
                  type="button"
                  onClick={() => handleSimulateAttack('login')}
                  disabled={simulatingAttack}
                  style={{
                    background: '#ffffff',
                    color: '#dc2626',
                    border: '1px solid #fecaca',
                    padding: '6px 14px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: simulatingAttack ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                  }}
                >
                  {simulatingAttack ? <Loader2 size={12} className="webcare-spin" /> : <ShieldAlert size={12} />}
                  <span>+ Test Credential Stuffing (22 IPs)</span>
                </button>
              </div>
            </div>
          </div>

          {/* Autonomous Shield Parameters & Thresholds Configuration */}
          <div className="webcare-firewall-card" style={{ padding: '24px', borderRadius: '8px' }}>
            <h3 style={{ fontSize: '15px', fontWeight: 700, margin: '0 0 16px', color: 'var(--webcare-text-primary, #0f172a)' }}>
              Cross-IP Velocity Thresholds &amp; Lockdown Policy
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '24px' }}>
              {/* Checkout Failure Threshold */}
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, marginBottom: '6px' }}>
                  WooCommerce Checkout Failures / 60s
                </label>
                <input
                  type="number"
                  min="3"
                  max="100"
                  value={distributedData.settings?.checkout_fail_limit || 10}
                  onChange={(e) =>
                    setDistributedData({
                      ...distributedData,
                      settings: { ...distributedData.settings, checkout_fail_limit: parseInt(e.target.value) || 10 },
                    })
                  }
                  className="webcare-firewall-input"
                  style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--webcare-border-form, #cbd5e1)' }}
                />
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                  Threshold for carding detection (default: 10 failed checkouts in 60s)
                </div>
              </div>

              {/* Checkout Unique IPs Threshold */}
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, marginBottom: '6px' }}>
                  Checkout Unique Residential IPs / 60s
                </label>
                <input
                  type="number"
                  min="2"
                  max="50"
                  value={distributedData.settings?.checkout_unique_ips_threshold || 6}
                  onChange={(e) =>
                    setDistributedData({
                      ...distributedData,
                      settings: { ...distributedData.settings, checkout_unique_ips_threshold: parseInt(e.target.value) || 6 },
                    })
                  }
                  className="webcare-firewall-input"
                  style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--webcare-border-form, #cbd5e1)' }}
                />
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                  Required diversity of unique IPs to confirm distributed swarm (default: 6 IPs)
                </div>
              </div>

              {/* Login Failures Threshold */}
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, marginBottom: '6px' }}>
                  Failed Logins / 60s
                </label>
                <input
                  type="number"
                  min="5"
                  max="200"
                  value={distributedData.settings?.login_fail_limit || 20}
                  onChange={(e) =>
                    setDistributedData({
                      ...distributedData,
                      settings: { ...distributedData.settings, login_fail_limit: parseInt(e.target.value) || 20 },
                    })
                  }
                  className="webcare-firewall-input"
                  style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--webcare-border-form, #cbd5e1)' }}
                />
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                  Threshold for distributed credential stuffing (default: 20 failed logins in 60s)
                </div>
              </div>

              {/* Login Unique IPs Threshold */}
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, marginBottom: '6px' }}>
                  Login Unique Residential IPs / 60s
                </label>
                <input
                  type="number"
                  min="2"
                  max="100"
                  value={distributedData.settings?.login_unique_ips_threshold || 10}
                  onChange={(e) =>
                    setDistributedData({
                      ...distributedData,
                      settings: { ...distributedData.settings, login_unique_ips_threshold: parseInt(e.target.value) || 10 },
                    })
                  }
                  className="webcare-firewall-input"
                  style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--webcare-border-form, #cbd5e1)' }}
                />
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                  Required diversity of unique IPs (default: 10 distinct IPs)
                </div>
              </div>

              {/* Under-Attack Duration */}
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, marginBottom: '6px' }}>
                  Lockdown Duration (Minutes)
                </label>
                <input
                  type="number"
                  min="2"
                  max="1440"
                  value={Math.round((distributedData.settings?.under_attack_duration || 900) / 60)}
                  onChange={(e) =>
                    setDistributedData({
                      ...distributedData,
                      settings: { ...distributedData.settings, under_attack_duration: (parseInt(e.target.value) || 15) * 60 },
                    })
                  }
                  className="webcare-firewall-input"
                  style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--webcare-border-form, #cbd5e1)' }}
                />
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                  Duration Under-Attack Shield stays active before auto-reverting to normal (default: 15 min)
                </div>
              </div>

              {/* Enforcement Action */}
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, marginBottom: '6px' }}>
                  Under-Attack Enforcement Action
                </label>
                <select
                  value={distributedData.settings?.under_attack_action || 'pow'}
                  onChange={(e) =>
                    setDistributedData({
                      ...distributedData,
                      settings: { ...distributedData.settings, under_attack_action: e.target.value },
                    })
                  }
                  className="webcare-firewall-input"
                  style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--webcare-border-form, #cbd5e1)' }}
                >
                  <option value="pow">WebCrypto Proof-of-Work (PoW) Challenge (Recommended)</option>
                  <option value="throttle">HTTP 429 Graceful Throttle (Retry-After)</option>
                  <option value="block">Strict HTTP 403 Access Denied</option>
                </select>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                  PoW allows legitimate human shoppers to complete checkout while blocking headless bots.
                </div>
              </div>
            </div>

            {/* Toggles Strip */}
            <div style={{ marginTop: '20px', paddingTop: '16px', borderTop: '1px solid var(--webcare-border-std, #e2e8f0)', display: 'flex', gap: '24px', flexWrap: 'wrap' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '13px', fontWeight: 600 }}>
                <input
                  type="checkbox"
                  checked={distributedData.settings?.auto_activate_under_attack ?? true}
                  onChange={(e) =>
                    setDistributedData({
                      ...distributedData,
                      settings: { ...distributedData.settings, auto_activate_under_attack: e.target.checked },
                    })
                  }
                  style={{ width: '16px', height: '16px', accentColor: '#4f46e5' }}
                />
                <span>Automatically engage Under-Attack Shield when swarm threshold is breached</span>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '13px', fontWeight: 600 }}>
                <input
                  type="checkbox"
                  checked={distributedData.settings?.notify_on_attack ?? true}
                  onChange={(e) =>
                    setDistributedData({
                      ...distributedData,
                      settings: { ...distributedData.settings, notify_on_attack: e.target.checked },
                    })
                  }
                  style={{ width: '16px', height: '16px', accentColor: '#4f46e5' }}
                />
                <span>Dispatch urgent out-of-band notification when botnet swarm is mitigated</span>
              </label>
            </div>

            {/* Save Button Row */}
            <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: '12px' }}>
              {savedBanner === 'distributed' && (
                <span style={{ fontSize: '13px', color: '#10b981', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <CheckCircle2 size={16} /> Distributed Velocity Settings Saved!
                </span>
              )}
              <button
                type="button"
                className="webcare-btn-primary"
                onClick={handleSaveDistributedSettings}
                disabled={savingSettings}
                style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', padding: '8px 18px' }}
              >
                {savingSettings ? <Loader2 size={14} className="webcare-spin" /> : <Check size={14} />}
                <span>Save Distributed Shield Settings</span>
              </button>
            </div>
          </div>

          {/* Attack Swarm Forensic Audit History Table */}
          <div className="webcare-firewall-card" style={{ padding: '0', overflow: 'hidden', borderRadius: '8px' }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                Recent Botnet Attack Swarms &amp; Mitigation Log
              </h4>
              <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                {distributedData.attack_history?.length || 0} recorded incidents
              </span>
            </div>

            {distributedData.attack_history && distributedData.attack_history.length > 0 ? (
              <div style={{ overflowX: 'auto' }}>
                <table className="webcare-waf-logs-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                  <thead>
                    <tr style={{ background: 'var(--webcare-bg-surface, #f8fafc)', borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)', textAlign: 'left' }}>
                      <th style={{ padding: '10px 16px' }}>Timestamp</th>
                      <th style={{ padding: '10px 16px' }}>Attack Vector</th>
                      <th style={{ padding: '10px 16px' }}>Swarm Metrics (60s)</th>
                      <th style={{ padding: '10px 16px' }}>Action Enforced</th>
                      <th style={{ padding: '10px 16px' }}>Duration</th>
                      <th style={{ padding: '10px 16px' }}>Trigger</th>
                    </tr>
                  </thead>
                  <tbody>
                    {distributedData.attack_history.map((h: any, idx: number) => (
                      <tr key={h.id || idx} style={{ borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)' }}>
                        <td style={{ padding: '10px 16px', color: 'var(--webcare-text-muted, #64748b)' }}>
                          {h.formatted_time || formatRelativeTime(h.activated_at)}
                        </td>
                        <td style={{ padding: '10px 16px' }}>
                          <span style={{
                            padding: '2px 8px',
                            borderRadius: '4px',
                            fontSize: '11px',
                            fontWeight: 700,
                            background: h.attack_type === 'carding_swarm' ? '#fff7ed' : '#fef2f2',
                            color: h.attack_type === 'carding_swarm' ? '#c2410c' : '#dc2626',
                            border: h.attack_type === 'carding_swarm' ? '1px solid #fed7aa' : '1px solid #fecaca',
                          }}>
                            {h.attack_type === 'carding_swarm' ? 'Carding Swarm' : (h.attack_type === 'credential_stuffing_swarm' ? 'Credential Stuffing' : 'Manual Lockdown')}
                          </span>
                        </td>
                        <td style={{ padding: '10px 16px', fontFamily: 'monospace' }}>
                          <strong>{h.failures || 0} failures</strong> / {h.unique_ips || 0} unique IPs
                        </td>
                        <td style={{ padding: '10px 16px' }}>
                          <span style={{
                            padding: '2px 6px',
                            borderRadius: '4px',
                            fontSize: '10px',
                            fontWeight: 700,
                            background: '#eef2ff',
                            color: '#4f46e5',
                          }}>
                            {String(h.action || 'POW').toUpperCase()}
                          </span>
                        </td>
                        <td style={{ padding: '10px 16px', color: 'var(--webcare-text-muted, #64748b)' }}>
                          {Math.round((h.duration || 900) / 60)} min
                        </td>
                        <td style={{ padding: '10px 16px', color: 'var(--webcare-text-muted, #64748b)' }}>
                          {h.trigger === 'auto' ? 'Automated Heuristic' : 'Admin Manual'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div style={{ padding: '32px', textAlign: 'center', color: '#059669' }}>
                <CheckCircle2 size={32} style={{ margin: '0 auto 8px auto' }} />
                <div style={{ fontWeight: 700, fontSize: '14px' }}>No Distributed Botnet Attacks Recorded</div>
                <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: '#64748b' }}>
                  The cross-IP sliding-window monitor is passively tracking all visitor traffic for botnet swarms.
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
