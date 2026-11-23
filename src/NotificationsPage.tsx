import { useState, useEffect, useMemo } from '@wordpress/element';
import {
  Bell,
  Mail,
  MessageSquare,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  CheckCircle2,
  XCircle,
  Search,
  Filter,
  Save,
  RotateCcw,
  RefreshCw,
  Send,
  Zap,
  Sliders,
  Settings,
  Lock,
  ExternalLink,
  ChevronRight,
  Database,
  FileCode,
  Globe,
  Bot,
  Layers,
  Cpu,
  GitBranch,
  Radio,
  Key,
  Calendar,
  Check,
  AlertCircle
} from 'lucide-react';

interface NotificationChannelState {
  email: boolean;
  webhook: boolean;
}

interface NotificationCatalogItem {
  category: string;
  category_label: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'warning' | 'info';
}

interface NotificationsSettingsResponse {
  success: boolean;
  notification_master_enabled: boolean;
  notification_events: Record<string, NotificationChannelState>;
  catalog: Record<string, NotificationCatalogItem>;
  alert_emails: string;
  webhooks_configured: {
    slack: boolean;
    discord: boolean;
    clickup: boolean;
    asana: boolean;
    generic: boolean;
  };
}

interface NotificationsPageProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  onNavigateToSettings?: () => void;
}

const CATEGORY_TABS = [
  { id: 'all', label: 'All Security Events', icon: Bell },
  { id: 'scans', label: 'Core Scans & Threats', icon: ShieldAlert },
  { id: 'self_defense', label: 'Plugin Self-Defense', icon: Lock },
  { id: 'supply_chain', label: 'Supply-Chain & SBOM', icon: GitBranch },
  { id: 'behavioral', label: 'Behavioral & Traps', icon: Radio },
  { id: 'cloudflare_waf', label: 'Cloudflare & WAF', icon: Globe },
  { id: 'auth', label: 'Auth & 2FA Access', icon: Key },
  { id: 'fim', label: 'File Integrity (FIM)', icon: FileCode },
  { id: 'vulnerabilities', label: 'Vulnerabilities & CVE', icon: Layers },
  { id: 'backups_vault', label: 'Backups & Vault', icon: Database },
  { id: 'devsecops_ai', label: 'DevSecOps & AI', icon: Bot },
];

export const NotificationsPage = ({ apiRequest, onNavigateToSettings }: NotificationsPageProps) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [masterEnabled, setMasterEnabled] = useState<boolean>(true);
  const [events, setEvents] = useState<Record<string, NotificationChannelState>>({});
  const [catalog, setCatalog] = useState<Record<string, NotificationCatalogItem>>({});
  const [alertEmails, setAlertEmails] = useState<string>('');
  const [webhooksConfigured, setWebhooksConfigured] = useState({
    slack: false,
    discord: false,
    clickup: false,
    asana: false,
    generic: false,
  });

  const [activeTab, setActiveTab] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [testingEvent, setTestingEvent] = useState<string | null>(null);
  const [saveSuccessNotice, setSaveSuccessNotice] = useState<boolean>(false);
  const [bannerMessage, setBannerMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Load initial settings
  const loadNotificationSettings = async () => {
    setLoading(true);
    try {
      const res: NotificationsSettingsResponse = await apiRequest({
        path: '/webcare-pro-security/v1/notifications/settings',
        method: 'GET',
      });
      if (res && res.success) {
        setMasterEnabled(res.notification_master_enabled);
        setEvents(res.notification_events || {});
        setCatalog(res.catalog || {});
        setAlertEmails(res.alert_emails || '');
        if (res.webhooks_configured) {
          setWebhooksConfigured(res.webhooks_configured);
        }
      }
    } catch (err: any) {
      setBannerMessage({
        type: 'error',
        text: err?.message || 'Failed to fetch notification settings.',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadNotificationSettings();
  }, []);

  // Save modified settings
  const handleSaveSettings = async () => {
    setSaving(true);
    setBannerMessage(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/notifications/settings',
        method: 'POST',
        data: {
          notification_master_enabled: masterEnabled,
          notification_events: events,
          alert_emails: alertEmails,
        },
      });
      if (res && res.success) {
        setSaveSuccessNotice(true);
        setBannerMessage({
          type: 'success',
          text: 'Notification preferences saved and synchronized successfully.',
        });
        setTimeout(() => setSaveSuccessNotice(false), 4000);
      }
    } catch (err: any) {
      setBannerMessage({
        type: 'error',
        text: err?.message || 'Failed to save notification settings.',
      });
    } finally {
      setSaving(false);
    }
  };

  // Toggle specific channel for an event
  const handleToggleChannel = (eventKey: string, channel: 'email' | 'webhook') => {
    setEvents((prev) => {
      const current = prev[eventKey] || { email: false, webhook: false };
      return {
        ...prev,
        [eventKey]: {
          ...current,
          [channel]: !current[channel],
        },
      };
    });
  };

  // Test notification trigger
  const handleTestEvent = async (eventKey: string) => {
    setTestingEvent(eventKey);
    setBannerMessage(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/notifications/test-event',
        method: 'POST',
        data: { event_key: eventKey },
      });
      if (res && res.success) {
        setBannerMessage({
          type: 'success',
          text: res.message || `Test notification dispatched for event: ${eventKey}`,
        });
      } else {
        setBannerMessage({
          type: 'error',
          text: res?.message || 'Failed to dispatch test notification.',
        });
      }
    } catch (err: any) {
      setBannerMessage({
        type: 'error',
        text: err?.message || 'Error occurred while testing event notification.',
      });
    } finally {
      setTestingEvent(null);
    }
  };

  // Preset Configurations
  const applyPreset = (preset: 'all_on' | 'devsecops' | 'default_minimal' | 'all_off') => {
    setEvents((prev) => {
      const updated: Record<string, NotificationChannelState> = {};
      Object.keys(catalog).forEach((key) => {
        const item = catalog[key];
        if (preset === 'all_on') {
          updated[key] = { email: true, webhook: true };
        } else if (preset === 'all_off') {
          updated[key] = { email: false, webhook: false };
        } else if (preset === 'default_minimal') {
          // By default: Enable ONLY Critical/High Threats Detected
          const isTargetEvent = key === 'scan_threats_found';
          updated[key] = {
            email: isTargetEvent,
            webhook: isTargetEvent,
          };
        } else if (preset === 'devsecops') {
          // Webhooks on for all warnings & criticals, email for high/critical
          const isDanger = item.severity === 'critical' || item.severity === 'high';
          updated[key] = {
            email: isDanger,
            webhook: true,
          };
        }
      });
      return updated;
    });

    setBannerMessage({
      type: 'success',
      text: preset === 'default_minimal' 
        ? 'Applied default preset: only "Plugin Deactivated" and "Critical / High Threats Detected" are enabled. Click "Save Notification Settings" to apply.'
        : `Applied "${preset.replace('_', ' ').toUpperCase()}" preset. Remember to click "Save Notification Settings" to apply changes.`,
    });
  };

  // Computed summary metrics
  const stats = useMemo(() => {
    const totalEvents = Object.keys(catalog).length;
    let emailActive = 0;
    let webhookActive = 0;

    Object.keys(events).forEach((key) => {
      if (events[key]?.email) emailActive++;
      if (events[key]?.webhook) webhookActive++;
    });

    const activeWebhookCount = Object.values(webhooksConfigured).filter(Boolean).length;

    return { totalEvents, emailActive, webhookActive, activeWebhookCount };
  }, [catalog, events, webhooksConfigured]);

  // Filtered event list
  const filteredEvents = useMemo(() => {
    return Object.entries(catalog).filter(([key, item]) => {
      // Category filter
      if (activeTab !== 'all' && item.category !== activeTab) {
        return false;
      }

      // Severity filter
      if (severityFilter !== 'all' && item.severity !== severityFilter) {
        return false;
      }

      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesTitle = item.title.toLowerCase().includes(q);
        const matchesDesc = item.description.toLowerCase().includes(q);
        const matchesKey = key.toLowerCase().includes(q);
        const matchesCat = item.category_label.toLowerCase().includes(q);
        return matchesTitle || matchesDesc || matchesKey || matchesCat;
      }

      return true;
    });
  }, [catalog, activeTab, severityFilter, searchQuery]);

  return (
    <div className="webcare-settings-page" style={{ padding: '0 0 60px 0' }}>
      {/* 1. Header Banner */}
      <div
        className="webcare-page-hero"
        style={{
          background: 'var(--webcare-surface-card)',
          borderRadius: '16px',
          border: '1px solid var(--webcare-border)',
          padding: '28px 32px',
          marginBottom: '24px',
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.04)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div
              style={{
                width: '52px',
                height: '52px',
                borderRadius: '14px',
                background: 'linear-gradient(135deg, #4f46e5 0%, #4338ca 100%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#ffffff',
                boxShadow: '0 8px 16px rgba(79, 70, 229, 0.25)',
              }}
            >
              <Bell size={26} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <h1 style={{ margin: 0, fontSize: '22px', fontWeight: 800, color: 'var(--webcare-text-heading)' }}>
                  Notification Center & Alert Engine
                </h1>
                <span
                  style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    padding: '3px 8px',
                    borderRadius: '6px',
                    background: masterEnabled ? '#ecfdf5' : '#fef2f2',
                    color: masterEnabled ? '#059669' : '#dc2626',
                    border: `1px solid ${masterEnabled ? '#a7f3d0' : '#fecaca'}`,
                  }}
                >
                  {masterEnabled ? 'All Channels Active' : 'Notifications Paused'}
                </span>
              </div>
              <p style={{ margin: '6px 0 0 0', fontSize: '13.5px', color: 'var(--webcare-text-secondary)' }}>
                Granular dispatch matrix for security scans, tampering detection, brute-force defenses, FIM, and DevSecOps webhooks.
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            {onNavigateToSettings && (
              <button
                type="button"
                onClick={onNavigateToSettings}
                className="webcare-btn-secondary"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '9px 16px',
                  fontSize: '13px',
                  fontWeight: 600,
                }}
              >
                <Settings size={15} />
                <span>Configure Webhooks & SMTP</span>
              </button>
            )}

            <button
              type="button"
              onClick={handleSaveSettings}
              disabled={saving}
              className="webcare-btn-primary"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '9px 20px',
                fontSize: '13px',
                fontWeight: 700,
                background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                color: '#ffffff',
                border: 'none',
                borderRadius: '8px',
                boxShadow: '0 4px 12px rgba(16, 185, 129, 0.3)',
                cursor: saving ? 'not-allowed' : 'pointer',
              }}
            >
              {saving ? <RefreshCw size={15} className="webcare-spin" /> : <Save size={15} />}
              <span>{saving ? 'Saving...' : 'Save Notification Settings'}</span>
            </button>
          </div>
        </div>

        {/* Status bar pills */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '16px',
            marginTop: '24px',
            paddingTop: '20px',
            borderTop: '1px solid var(--webcare-border)',
          }}
        >
          {/* Master Switch */}
          <div
            onClick={() => setMasterEnabled(!masterEnabled)}
            style={{
              padding: '14px 18px',
              borderRadius: '12px',
              background: masterEnabled ? 'rgba(16, 185, 129, 0.08)' : 'rgba(239, 68, 68, 0.08)',
              border: `1px solid ${masterEnabled ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-muted)', textTransform: 'uppercase' }}>
                Master Alert Switch
              </div>
              <div style={{ fontSize: '14px', fontWeight: 800, color: masterEnabled ? '#059669' : '#dc2626', marginTop: '2px' }}>
                {masterEnabled ? 'Notifications Enabled' : 'All Alerts Muted'}
              </div>
            </div>
            <div
              style={{
                width: '38px',
                height: '22px',
                borderRadius: '11px',
                background: masterEnabled ? '#10b981' : '#cbd5e1',
                position: 'relative',
                transition: 'all 0.2s ease',
              }}
            >
              <div
                style={{
                  width: '16px',
                  height: '16px',
                  borderRadius: '50%',
                  background: '#ffffff',
                  position: 'absolute',
                  top: '3px',
                  left: masterEnabled ? '19px' : '3px',
                  transition: 'all 0.2s ease',
                }}
              />
            </div>
          </div>

          {/* Email Channel Pill */}
          <div
            style={{
              padding: '14px 18px',
              borderRadius: '12px',
              background: 'var(--webcare-surface-elevated)',
              border: '1px solid var(--webcare-border)',
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
            }}
          >
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '8px',
                background: 'rgba(2, 132, 199, 0.1)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#0284c7',
              }}
            >
              <Mail size={18} />
            </div>
            <div>
              <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-muted)', textTransform: 'uppercase' }}>
                Active Email Alerts
              </div>
              <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--webcare-text-heading)' }}>
                {stats.emailActive} of {stats.totalEvents} Events
              </div>
            </div>
          </div>

          {/* Webhook Channel Pill */}
          <div
            style={{
              padding: '14px 18px',
              borderRadius: '12px',
              background: 'var(--webcare-surface-elevated)',
              border: '1px solid var(--webcare-border)',
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
            }}
          >
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '8px',
                background: 'rgba(99, 102, 241, 0.1)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#6366f1',
              }}
            >
              <MessageSquare size={18} />
            </div>
            <div>
              <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-muted)', textTransform: 'uppercase' }}>
                Active Webhook Triggers
              </div>
              <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--webcare-text-heading)' }}>
                {stats.webhookActive} of {stats.totalEvents} Events
              </div>
            </div>
          </div>

          {/* Integrated Webhooks Pill */}
          <div
            style={{
              padding: '14px 18px',
              borderRadius: '12px',
              background: 'var(--webcare-surface-elevated)',
              border: '1px solid var(--webcare-border)',
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
            }}
          >
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '8px',
                background: 'rgba(16, 185, 129, 0.1)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#10b981',
              }}
            >
              <Zap size={18} />
            </div>
            <div>
              <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-muted)', textTransform: 'uppercase' }}>
                Connected Endpoints
              </div>
              <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--webcare-text-heading)' }}>
                {stats.activeWebhookCount} Platform(s)
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 2. Banner Feedback */}
      {bannerMessage && (
        <div
          style={{
            padding: '14px 20px',
            borderRadius: '10px',
            marginBottom: '20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: bannerMessage.type === 'success' ? '#ecfdf5' : '#fef2f2',
            border: `1px solid ${bannerMessage.type === 'success' ? '#a7f3d0' : '#fecaca'}`,
            color: bannerMessage.type === 'success' ? '#065f46' : '#991b1b',
            boxShadow: '0 2px 6px rgba(0,0,0,0.03)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13.5px', fontWeight: 600 }}>
            {bannerMessage.type === 'success' ? <CheckCircle2 size={18} /> : <AlertTriangle size={18} />}
            <span>{bannerMessage.text}</span>
          </div>
          <button
            type="button"
            onClick={() => setBannerMessage(null)}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit' }}
          >
            &times;
          </button>
        </div>
      )}

      {/* 3. Controls & Filter Bar */}
      <div
        style={{
          background: 'var(--webcare-surface-card)',
          borderRadius: '14px',
          border: '1px solid var(--webcare-border)',
          padding: '18px 24px',
          marginBottom: '24px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
        }}
      >
        {/* Search & Severity Filters */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flex: 1, minWidth: '320px' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <Search
              size={16}
              style={{
                position: 'absolute',
                left: '12px',
                top: '50%',
                transform: 'translateY(-50%)',
                color: 'var(--webcare-text-muted)',
              }}
            />
            <input
              type="text"
              placeholder="Search security events (e.g. 2fa, cloudflare, fim, backup)..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="webcare-input"
              style={{
                width: '100%',
                paddingLeft: '38px',
                height: '40px',
                fontSize: '13.5px',
                borderRadius: '8px',
              }}
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="webcare-input"
            style={{ width: '170px', height: '40px', fontSize: '13px' }}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical Only</option>
            <option value="high">High Only</option>
            <option value="warning">Warning Only</option>
            <option value="info">Informational</option>
          </select>
        </div>

        {/* Quick Presets Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-muted)', marginRight: '4px' }}>
            QUICK PRESETS:
          </span>
          <button
            type="button"
            onClick={() => applyPreset('default_minimal')}
            className="webcare-btn-secondary"
            style={{ fontSize: '12px', padding: '6px 12px', borderColor: '#4f46e5', color: '#4f46e5', fontWeight: 700 }}
            title="By default: enable only 'Plugin Deactivated' and 'Critical / High Threats Detected'"
          >
            ⭐ Default (Deactivate & Threats Only)
          </button>
          <button
            type="button"
            onClick={() => applyPreset('devsecops')}
            className="webcare-btn-secondary"
            style={{ fontSize: '12px', padding: '6px 12px' }}
            title="Enable webhooks for all events and emails for critical & high events"
          >
            DevSecOps Complete
          </button>
          <button
            type="button"
            onClick={() => applyPreset('all_on')}
            className="webcare-btn-secondary"
            style={{ fontSize: '12px', padding: '6px 12px' }}
          >
            Enable All
          </button>
          <button
            type="button"
            onClick={() => applyPreset('all_off')}
            className="webcare-btn-secondary"
            style={{ fontSize: '12px', padding: '6px 12px' }}
          >
            Disable All
          </button>
        </div>
      </div>

      {/* 4. Category Tabs */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          overflowX: 'auto',
          paddingBottom: '8px',
          marginBottom: '20px',
        }}
      >
        {CATEGORY_TABS.map((tab) => {
          const IconComponent = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '10px 16px',
                borderRadius: '10px',
                fontSize: '13px',
                fontWeight: 600,
                cursor: 'pointer',
                whiteSpace: 'nowrap',
                transition: 'all 0.15s ease',
                background: isActive ? 'var(--webcare-surface-card)' : 'transparent',
                color: isActive ? '#4f46e5' : 'var(--webcare-text-secondary)',
                border: isActive ? '1px solid #c7d2fe' : '1px solid transparent',
                boxShadow: isActive ? '0 2px 8px rgba(79, 70, 229, 0.1)' : 'none',
              }}
            >
              <IconComponent size={15} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* 5. Notification Events Matrix Table */}
      <div
        style={{
          background: 'var(--webcare-surface-card)',
          borderRadius: '16px',
          border: '1px solid var(--webcare-border)',
          overflow: 'hidden',
          boxShadow: '0 4px 16px rgba(0, 0, 0, 0.03)',
        }}
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 140px 140px 130px',
            padding: '14px 24px',
            background: 'var(--webcare-surface-elevated)',
            borderBottom: '1px solid var(--webcare-border)',
            fontSize: '12px',
            fontWeight: 700,
            textTransform: 'uppercase',
            letterSpacing: '0.6px',
            color: 'var(--webcare-text-muted)',
          }}
        >
          <div>Security Event & Description</div>
          <div style={{ textAlign: 'center' }}>Email Alert</div>
          <div style={{ textAlign: 'center' }}>DevSecOps Webhook</div>
          <div style={{ textAlign: 'right' }}>Instant Test</div>
        </div>

        {loading ? (
          <div style={{ padding: '60px', textAlign: 'center', color: 'var(--webcare-text-muted)' }}>
            <RefreshCw size={28} className="webcare-spin" style={{ margin: '0 auto 12px auto' }} />
            <p style={{ margin: 0, fontSize: '14px', fontWeight: 600 }}>Loading notification events catalog...</p>
          </div>
        ) : filteredEvents.length === 0 ? (
          <div style={{ padding: '60px', textAlign: 'center', color: 'var(--webcare-text-muted)' }}>
            <Bell size={32} style={{ margin: '0 auto 12px auto', opacity: 0.5 }} />
            <p style={{ margin: 0, fontSize: '15px', fontWeight: 600 }}>No security events match your current filter.</p>
            <p style={{ margin: '6px 0 0 0', fontSize: '13px' }}>Try clearing the search query or selecting "All Security Events".</p>
          </div>
        ) : (
          <div>
            {filteredEvents.map(([eventKey, item], index) => {
              const currentCfg = events[eventKey] || { email: false, webhook: false };
              const isTesting = testingEvent === eventKey;

              const severityColors: Record<string, { bg: string; text: string; border: string }> = {
                critical: { bg: '#fef2f2', text: '#dc2626', border: '#fecaca' },
                high:     { bg: '#fff7ed', text: '#ea580c', border: '#fed7aa' },
                warning:  { bg: '#fffbeb', text: '#d97706', border: '#fde68a' },
                info:     { bg: '#eff6ff', text: '#2563eb', border: '#bfdbfe' },
              };
              const sev = severityColors[item.severity] || severityColors.info;

              return (
                <div
                  key={eventKey}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '1fr 140px 140px 130px',
                    alignItems: 'center',
                    padding: '18px 24px',
                    borderBottom: index < filteredEvents.length - 1 ? '1px solid var(--webcare-border)' : 'none',
                    background: index % 2 === 1 ? 'var(--webcare-surface-elevated)' : 'transparent',
                    transition: 'background 0.15s ease',
                  }}
                >
                  {/* Event Details */}
                  <div style={{ paddingRight: '20px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                      <span
                        style={{
                          fontSize: '10px',
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          padding: '2px 7px',
                          borderRadius: '4px',
                          background: sev.bg,
                          color: sev.text,
                          border: `1px solid ${sev.border}`,
                        }}
                      >
                        {item.severity}
                      </span>
                      <span style={{ fontSize: '14.5px', fontWeight: 700, color: 'var(--webcare-text-heading)' }}>
                        {item.title}
                      </span>
                      <span
                        style={{
                          fontSize: '11px',
                          fontFamily: 'monospace',
                          color: 'var(--webcare-text-muted)',
                          background: 'rgba(0,0,0,0.03)',
                          padding: '2px 6px',
                          borderRadius: '4px',
                        }}
                      >
                        {eventKey}
                      </span>
                    </div>
                    <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary)', lineHeight: 1.5 }}>
                      {item.description}
                    </p>
                  </div>

                  {/* Email Channel Toggle */}
                  <div style={{ display: 'flex', justifyContent: 'center' }}>
                    <div
                      onClick={() => handleToggleChannel(eventKey, 'email')}
                      style={{
                        width: '42px',
                        height: '24px',
                        borderRadius: '12px',
                        background: currentCfg.email ? '#4f46e5' : '#e2e8f0',
                        position: 'relative',
                        cursor: 'pointer',
                        transition: 'all 0.2s ease',
                        boxShadow: currentCfg.email ? '0 0 10px rgba(79, 70, 229, 0.4)' : 'none',
                      }}
                      title={`Toggle email alert for ${item.title}`}
                    >
                      <div
                        style={{
                          width: '18px',
                          height: '18px',
                          borderRadius: '50%',
                          background: '#ffffff',
                          position: 'absolute',
                          top: '3px',
                          left: currentCfg.email ? '21px' : '3px',
                          transition: 'left 0.2s ease',
                          boxShadow: '0 1px 3px rgba(0,0,0,0.2)',
                        }}
                      />
                    </div>
                  </div>

                  {/* Webhook Channel Toggle */}
                  <div style={{ display: 'flex', justifyContent: 'center' }}>
                    <div
                      onClick={() => handleToggleChannel(eventKey, 'webhook')}
                      style={{
                        width: '42px',
                        height: '24px',
                        borderRadius: '12px',
                        background: currentCfg.webhook ? '#10b981' : '#e2e8f0',
                        position: 'relative',
                        cursor: 'pointer',
                        transition: 'all 0.2s ease',
                        boxShadow: currentCfg.webhook ? '0 0 10px rgba(16, 185, 129, 0.4)' : 'none',
                      }}
                      title={`Toggle webhook dispatch for ${item.title}`}
                    >
                      <div
                        style={{
                          width: '18px',
                          height: '18px',
                          borderRadius: '50%',
                          background: '#ffffff',
                          position: 'absolute',
                          top: '3px',
                          left: currentCfg.webhook ? '21px' : '3px',
                          transition: 'left 0.2s ease',
                          boxShadow: '0 1px 3px rgba(0,0,0,0.2)',
                        }}
                      />
                    </div>
                  </div>

                  {/* Instant Test Trigger */}
                  <div style={{ textAlign: 'right' }}>
                    <button
                      type="button"
                      onClick={() => handleTestEvent(eventKey)}
                      disabled={isTesting || (!currentCfg.email && !currentCfg.webhook)}
                      className="webcare-btn-secondary"
                      style={{
                        padding: '6px 12px',
                        fontSize: '12px',
                        fontWeight: 600,
                        opacity: !currentCfg.email && !currentCfg.webhook ? 0.4 : 1,
                        cursor: !currentCfg.email && !currentCfg.webhook ? 'not-allowed' : 'pointer',
                      }}
                      title={
                        !currentCfg.email && !currentCfg.webhook
                          ? 'Enable at least one delivery channel (Email or Webhook) to test'
                          : `Send test notification for ${item.title}`
                      }
                    >
                      {isTesting ? (
                        <RefreshCw size={13} className="webcare-spin" />
                      ) : (
                        <Send size={13} style={{ marginRight: '5px' }} />
                      )}
                      <span>{isTesting ? 'Sending...' : 'Test'}</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Matrix Footer */}
        <div
          style={{
            padding: '16px 24px',
            background: 'var(--webcare-surface-elevated)',
            borderTop: '1px solid var(--webcare-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '13px',
            color: 'var(--webcare-text-secondary)',
          }}
        >
          <div>
            Showing <strong>{filteredEvents.length}</strong> of <strong>{Object.keys(catalog).length}</strong> configurable security events.
          </div>
          <button
            type="button"
            onClick={handleSaveSettings}
            disabled={saving}
            className="webcare-btn-primary"
            style={{
              padding: '8px 18px',
              fontSize: '13px',
              fontWeight: 700,
              background: '#4f46e5',
              color: '#ffffff',
              border: 'none',
              borderRadius: '8px',
            }}
          >
            {saving ? 'Saving Changes...' : 'Save Notification Matrix'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default NotificationsPage;
