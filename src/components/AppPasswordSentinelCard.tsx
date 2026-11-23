import { useState, useEffect } from '@wordpress/element';
import {
  ShieldAlert,
  ShieldCheck,
  Shield,
  Key,
  Globe,
  Trash2,
  AlertTriangle,
  RefreshCw,
  Plus,
  CheckCircle2,
  Lock,
  Unlock,
  Users,
  Clock,
  ExternalLink,
  ShieldX,
  Info
} from 'lucide-react';
import { ConfirmDialog } from './ConfirmDialog';

interface AppPasswordItem {
  user_id: number;
  user_login: string;
  display_name: string;
  user_email: string;
  user_roles: string[];
  is_admin: boolean;
  uuid: string;
  app_id: string;
  name: string;
  created: number;
  created_human: string;
  created_date: string;
  last_used: number | null;
  last_used_human: string;
  last_used_date: string | null;
  last_ip: string | null;
  is_stale: boolean;
}

interface SentinelSettings {
  disabled_globally: boolean;
  admin_only: boolean;
  require_step_up_2fa: boolean;
  allowed_callback_domains: string[];
  canonical_hosts: string[];
  core_supports_app_pass: boolean;
  stats: {
    total_active: number;
    stale_count: number;
    admin_count: number;
    non_admin_count: number;
  };
}

interface AppPasswordSentinelCardProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
}

export const AppPasswordSentinelCard = ({ apiRequest }: AppPasswordSentinelCardProps) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [savingSettings, setSavingSettings] = useState<boolean>(false);
  const [passwords, setPasswords] = useState<AppPasswordItem[]>([]);
  const [settings, setSettings] = useState<SentinelSettings | null>(null);
  const [newDomain, setNewDomain] = useState<string>('');
  const [domainError, setDomainError] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Modal confirm state
  const [confirmDialog, setConfirmDialog] = useState<{
    isOpen: boolean;
    title: string;
    message: string;
    confirmLabel?: string;
    variant?: 'danger' | 'warning' | 'primary';
    onConfirm: () => void;
  }>({
    isOpen: false,
    title: '',
    message: '',
    onConfirm: () => {},
  });

  const fetchData = async (isManualRefresh = false) => {
    if (isManualRefresh) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }

    try {
      const response = await apiRequest({
        path: '/webcare-pro-security/v1/auth/app-passwords',
        method: 'GET',
      });

      if (response && response.success) {
        setPasswords(response.passwords || []);
        setSettings(response.settings || null);
      }
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        text: err?.message || 'Failed to load Application Passwords sentinel data.',
      });
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleToggleSetting = async (key: 'disabled_globally' | 'admin_only' | 'require_step_up_2fa', currentValue: boolean) => {
    if (!settings) return;

    const newValue = !currentValue;
    setSavingSettings(true);
    setStatusMessage(null);

    try {
      const response = await apiRequest({
        path: '/webcare-pro-security/v1/auth/app-passwords/settings',
        method: 'POST',
        data: {
          [key]: newValue,
        },
      });

      if (response && response.success) {
        setSettings(response.settings);
        setStatusMessage({
          type: 'success',
          text: response.message || 'Security policy updated successfully.',
        });
      }
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        text: err?.message || 'Failed to update security policy.',
      });
    } finally {
      setSavingSettings(false);
    }
  };

  const handleAddDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain.trim() || !settings) return;

    let domain = newDomain.trim().toLowerCase();
    // Strip protocol and path if entered
    domain = domain.replace(/^https?:\/\//i, '').split('/')[0].trim();

    if (!domain) {
      setDomainError('Please enter a valid domain name.');
      return;
    }

    if (settings.allowed_callback_domains.includes(domain)) {
      setDomainError('This domain is already in the approved whitelist.');
      return;
    }

    const updatedDomains = [...settings.allowed_callback_domains, domain];
    setSavingSettings(true);
    setDomainError(null);
    setStatusMessage(null);

    try {
      const response = await apiRequest({
        path: '/webcare-pro-security/v1/auth/app-passwords/settings',
        method: 'POST',
        data: {
          allowed_callback_domains: updatedDomains,
        },
      });

      if (response && response.success) {
        setSettings(response.settings);
        setNewDomain('');
        setStatusMessage({
          type: 'success',
          text: `Domain "${domain}" added to approved callback whitelist.`,
        });
      }
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        text: err?.message || 'Failed to add approved callback domain.',
      });
    } finally {
      setSavingSettings(false);
    }
  };

  const handleRemoveDomain = async (domainToRemove: string) => {
    if (!settings) return;

    const updatedDomains = settings.allowed_callback_domains.filter((d) => d !== domainToRemove);
    setSavingSettings(true);
    setStatusMessage(null);

    try {
      const response = await apiRequest({
        path: '/webcare-pro-security/v1/auth/app-passwords/settings',
        method: 'POST',
        data: {
          allowed_callback_domains: updatedDomains,
        },
      });

      if (response && response.success) {
        setSettings(response.settings);
        setStatusMessage({
          type: 'success',
          text: `Domain "${domainToRemove}" removed from whitelist.`,
        });
      }
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        text: err?.message || 'Failed to remove callback domain.',
      });
    } finally {
      setSavingSettings(false);
    }
  };

  const handleRevokePassword = (item: AppPasswordItem) => {
    setConfirmDialog({
      isOpen: true,
      title: 'Revoke Application Password',
      message: `Are you sure you want to permanently revoke Application Password "${item.name}" for user "${item.user_login}"? Any external application or script using this credential will immediately lose REST API access.`,
      confirmLabel: 'Revoke Password',
      variant: 'danger',
      onConfirm: async () => {
        setConfirmDialog((prev) => ({ ...prev, isOpen: false }));
        setRefreshing(true);
        setStatusMessage(null);

        try {
          const response = await apiRequest({
            path: '/webcare-pro-security/v1/auth/app-passwords/revoke',
            method: 'POST',
            data: {
              user_id: item.user_id,
              uuid: item.uuid,
            },
          });

          if (response && response.success) {
            setPasswords(response.passwords || []);
            setSettings(response.settings || null);
            setStatusMessage({
              type: 'success',
              text: response.message || `Application Password "${item.name}" revoked successfully.`,
            });
          }
        } catch (err: any) {
          setStatusMessage({
            type: 'error',
            text: err?.message || 'Failed to revoke application password.',
          });
        } finally {
          setRefreshing(false);
        }
      },
    });
  };

  const handleRevokeAllForUser = (userId: number, userLogin: string) => {
    setConfirmDialog({
      isOpen: true,
      title: `Revoke All Passwords for ${userLogin}`,
      message: `Are you sure you want to revoke ALL Application Passwords for user "${userLogin}"? All authorized REST API sessions for this account will be terminated immediately.`,
      confirmLabel: 'Revoke All Passwords',
      variant: 'danger',
      onConfirm: async () => {
        setConfirmDialog((prev) => ({ ...prev, isOpen: false }));
        setRefreshing(true);
        setStatusMessage(null);

        try {
          const response = await apiRequest({
            path: '/webcare-pro-security/v1/auth/app-passwords/revoke-all',
            method: 'POST',
            data: {
              user_id: userId,
            },
          });

          if (response && response.success) {
            setPasswords(response.passwords || []);
            setSettings(response.settings || null);
            setStatusMessage({
              type: 'success',
              text: response.message || `All Application Passwords for "${userLogin}" have been revoked.`,
            });
          }
        } catch (err: any) {
          setStatusMessage({
            type: 'error',
            text: err?.message || 'Failed to revoke user application passwords.',
          });
        } finally {
          setRefreshing(false);
        }
      },
    });
  };

  if (loading && !settings) {
    return (
      <div className="webcare-card" style={{ padding: '32px', textAlign: 'center' }}>
        <RefreshCw size={24} className="webcare-spin" style={{ margin: '0 auto 12px auto', color: '#4f46e5' }} />
        <p style={{ color: 'var(--webcare-text-secondary, #64748b)', margin: 0, fontSize: '14px' }}>
          Loading Application Passwords &amp; Phishing Sentinel status...
        </p>
      </div>
    );
  }

  const isGloballyDisabled = settings?.disabled_globally || false;
  const isAdminOnly = settings?.admin_only || false;
  const isStepUp2Fa = settings?.require_step_up_2fa ?? true;
  const totalActive = settings?.stats?.total_active || 0;
  const staleCount = settings?.stats?.stale_count || 0;
  const nonAdminCount = settings?.stats?.non_admin_count || 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner / Feedback */}
      {statusMessage && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '14px 18px',
            borderRadius: '8px',
            fontSize: '13px',
            fontWeight: 500,
            background: statusMessage.type === 'success' ? 'var(--webcare-badge-clean-bg, #ecfdf5)' : 'var(--webcare-badge-danger-bg, #fef2f2)',
            color: statusMessage.type === 'success' ? 'var(--webcare-badge-clean-text, #047857)' : 'var(--webcare-badge-danger-text, #dc2626)',
            border: `1px solid ${statusMessage.type === 'success' ? 'var(--webcare-badge-clean-border, #a7f3d0)' : 'var(--webcare-badge-danger-border, #fecaca)'}`,
          }}
        >
          {statusMessage.type === 'success' ? <CheckCircle2 size={18} /> : <AlertTriangle size={18} />}
          <span>{statusMessage.text}</span>
          <button
            type="button"
            onClick={() => setStatusMessage(null)}
            style={{
              marginLeft: 'auto',
              background: 'transparent',
              border: 'none',
              cursor: 'pointer',
              color: 'inherit',
              fontSize: '16px',
              padding: '0 4px',
            }}
          >
            &times;
          </button>
        </div>
      )}

      {/* Hero Overview Card */}
      <div className="webcare-card" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '16px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
            <div
              style={{
                width: '44px',
                height: '44px',
                borderRadius: '10px',
                background: 'linear-gradient(135deg, #4f46e5 0%, #4338ca 100%)',
                color: '#ffffff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
                boxShadow: '0 4px 12px rgba(79, 70, 229, 0.25)',
              }}
            >
              <Key size={22} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'var(--webcare-text-heading, #0f172a)' }}>
                  REST Application Passwords &amp; Phishing Sentinel
                </h3>
                {isGloballyDisabled ? (
                  <span className="webcare-badge-pill" style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fecaca' }}>
                    <ShieldX size={12} style={{ marginRight: '4px', display: 'inline' }} /> Site-Wide Disabled
                  </span>
                ) : (
                  <span className="webcare-badge-pill" style={{ background: '#ecfdf5', color: '#047857', border: '1px solid #a7f3d0' }}>
                    <ShieldCheck size={12} style={{ marginRight: '4px', display: 'inline' }} /> Phishing Trap Armor Active
                  </span>
                )}
                {isAdminOnly && !isGloballyDisabled && (
                  <span className="webcare-badge-pill" style={{ background: '#eef2ff', color: '#4f46e5', border: '1px solid #c7d2fe' }}>
                    <Lock size={12} style={{ marginRight: '4px', display: 'inline' }} /> Administrators Only
                  </span>
                )}
                {isStepUp2Fa && !isGloballyDisabled && (
                  <span className="webcare-badge-pill" style={{ background: '#ecfdf5', color: '#047857', border: '1px solid #a7f3d0' }}>
                    <ShieldCheck size={12} style={{ marginRight: '4px', display: 'inline' }} /> Step-Up 2FA Enforced
                  </span>
                )}
              </div>
              <p style={{ margin: '6px 0 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5, maxWidth: '820px' }}>
                WordPress Application Passwords authenticate directly against the REST API and <strong>completely bypass Two-Factor Authentication (2FA)</strong>.
                WebCare Pro Security Sentinel protects your site from 1-click token phishing traps (<code>/wp-admin/authorize-application.php</code> consent hijacks),
                enforces strict callback destination whitelisting, and audits stale or abandoned credentials.
              </p>
            </div>
          </div>

          <button
            type="button"
            className="webcare-btn webcare-btn-secondary"
            onClick={() => fetchData(true)}
            disabled={refreshing}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
          >
            <RefreshCw size={14} className={refreshing ? 'webcare-spin' : ''} />
            <span>{refreshing ? 'Refreshing...' : 'Refresh Status'}</span>
          </button>
        </div>

        {/* Telemetry Grid */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '16px',
            marginTop: '24px',
            paddingTop: '20px',
            borderTop: '1px solid var(--webcare-border-subtle, #e2e8f0)',
          }}
        >
          <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--webcare-bg-surface, #f8fafc)', border: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
            <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>Active Credentials</div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--webcare-text-heading, #0f172a)', marginTop: '4px' }}>
              {totalActive}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
              Across {new Set(passwords.map((p) => p.user_id)).size} user account(s)
            </div>
          </div>

          <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--webcare-bg-surface, #f8fafc)', border: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
            <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>Stale / Abandoned</div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: staleCount > 0 ? '#d97706' : 'var(--webcare-text-heading, #0f172a)', marginTop: '4px' }}>
              {staleCount}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
              {staleCount > 0 ? 'Unused >90 days or never used' : 'All tokens actively maintained'}
            </div>
          </div>

          <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--webcare-bg-surface, #f8fafc)', border: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
            <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>Non-Admin Accounts</div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: nonAdminCount > 0 ? '#ea580c' : 'var(--webcare-text-heading, #0f172a)', marginTop: '4px' }}>
              {nonAdminCount}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
              {nonAdminCount > 0 ? 'Credentials on low-privilege users' : 'Clean: restricted to Admins'}
            </div>
          </div>

          <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--webcare-bg-surface, #f8fafc)', border: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
            <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>Callback Trap Defense</div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: '#10b981', marginTop: '4px' }}>
              Strict
            </div>
            <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
              External success_url blocked by default
            </div>
          </div>
        </div>
      </div>

      {/* Security Policies & Whitelist Controls Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '24px' }}>
        {/* Card 1: Core Policy Toggles */}
        <div className="webcare-card" style={{ padding: '24px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
              <Shield size={18} style={{ color: '#4f46e5' }} />
              <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 600, color: 'var(--webcare-text-heading, #0f172a)' }}>
                Application Passwords Security Policies
              </h4>
            </div>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5 }}>
              Configure site-wide availability and access boundaries for WordPress REST API credentials.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginTop: '20px' }}>
              {/* Toggle 1: Admin Only */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  justifyContent: 'space-between',
                  gap: '12px',
                  padding: '14px',
                  borderRadius: '8px',
                  background: 'var(--webcare-bg-surface, #f8fafc)',
                  border: '1px solid var(--webcare-border-subtle, #e2e8f0)',
                }}
              >
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-heading, #0f172a)' }}>
                    Restrict to Administrators Only
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '4px', lineHeight: 1.4 }}>
                    Blocks Subscribers, Customers, Authors, and Editors from minting or using Application Passwords.
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => handleToggleSetting('admin_only', isAdminOnly)}
                  disabled={savingSettings || isGloballyDisabled}
                  style={{
                    padding: '6px 14px',
                    borderRadius: '6px',
                    border: '1px solid',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: isGloballyDisabled ? 'not-allowed' : 'pointer',
                    background: isAdminOnly ? 'var(--webcare-primary, #4f46e5)' : 'var(--webcare-bg-surface, #ffffff)',
                    color: isAdminOnly ? '#ffffff' : 'var(--webcare-text-primary, #0f172a)',
                    borderColor: isAdminOnly ? 'var(--webcare-primary, #4f46e5)' : 'var(--webcare-border-strong, #cbd5e1)',
                    opacity: isGloballyDisabled ? 0.5 : 1,
                    transition: 'all 0.15s ease-in-out',
                  }}
                >
                  {isAdminOnly ? 'Enabled' : 'Disabled'}
                </button>
              </div>

              {/* Toggle 2: Step-Up 2FA & Identity Verification */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  justifyContent: 'space-between',
                  gap: '12px',
                  padding: '14px',
                  borderRadius: '8px',
                  background: 'var(--webcare-bg-surface, #f8fafc)',
                  border: '1px solid var(--webcare-border-subtle, #e2e8f0)',
                }}
              >
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-heading, #0f172a)' }}>
                    Enforce Step-Up 2FA / Identity Verification
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '4px', lineHeight: 1.4 }}>
                    Requires fresh TOTP verification (or current password re-entry) on <code>/wp-admin/authorize-application.php</code> before minting REST tokens, blocking 1-click consent traps and 2FA bypasses.
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => handleToggleSetting('require_step_up_2fa', isStepUp2Fa)}
                  disabled={savingSettings || isGloballyDisabled}
                  style={{
                    padding: '6px 14px',
                    borderRadius: '6px',
                    border: '1px solid',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: isGloballyDisabled ? 'not-allowed' : 'pointer',
                    background: isStepUp2Fa ? 'var(--webcare-primary, #4f46e5)' : 'var(--webcare-bg-surface, #ffffff)',
                    color: isStepUp2Fa ? '#ffffff' : 'var(--webcare-text-primary, #0f172a)',
                    borderColor: isStepUp2Fa ? 'var(--webcare-primary, #4f46e5)' : 'var(--webcare-border-strong, #cbd5e1)',
                    opacity: isGloballyDisabled ? 0.5 : 1,
                    transition: 'all 0.15s ease-in-out',
                  }}
                >
                  {isStepUp2Fa ? 'Enforced' : 'Off'}
                </button>
              </div>

              {/* Toggle 3: Site-Wide Kill Switch */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  justifyContent: 'space-between',
                  gap: '12px',
                  padding: '14px',
                  borderRadius: '8px',
                  background: isGloballyDisabled ? '#fef2f2' : 'var(--webcare-bg-surface, #f8fafc)',
                  border: `1px solid ${isGloballyDisabled ? '#fecaca' : 'var(--webcare-border-subtle, #e2e8f0)'}`,
                }}
              >
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: isGloballyDisabled ? '#b91c1c' : 'var(--webcare-text-heading, #0f172a)' }}>
                    Disable Application Passwords Site-Wide
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '4px', lineHeight: 1.4 }}>
                    Emergency kill-switch. Completely deactivates the WordPress Application Passwords subsystem across all profiles and REST endpoints.
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => handleToggleSetting('disabled_globally', isGloballyDisabled)}
                  disabled={savingSettings}
                  style={{
                    padding: '6px 14px',
                    borderRadius: '6px',
                    border: '1px solid',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    background: isGloballyDisabled ? '#dc2626' : 'var(--webcare-bg-surface, #ffffff)',
                    color: isGloballyDisabled ? '#ffffff' : 'var(--webcare-text-primary, #0f172a)',
                    borderColor: isGloballyDisabled ? '#dc2626' : 'var(--webcare-border-strong, #cbd5e1)',
                    transition: 'all 0.15s ease-in-out',
                  }}
                >
                  {isGloballyDisabled ? 'Kill-Switch Active' : 'Off (Allowed)'}
                </button>
              </div>
            </div>
          </div>

          <div style={{ marginTop: '16px', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
            <Info size={14} />
            <span>Changes take effect immediately at the WordPress filter level without touching core files.</span>
          </div>
        </div>

        {/* Card 2: Approved Callback Domain Whitelist */}
        <div className="webcare-card" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
            <Globe size={18} style={{ color: '#0284c7' }} />
            <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 600, color: 'var(--webcare-text-heading, #0f172a)' }}>
              Approved Callback Destination Whitelist
            </h4>
          </div>
          <p style={{ margin: 0, fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5 }}>
            To prevent 1-click token phishing, any application requesting authorization via <code>authorize-application.php</code> must redirect to a local or approved domain.
          </p>

          {/* Canonical Hosts */}
          <div style={{ marginTop: '16px' }}>
            <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', marginBottom: '6px' }}>
              Default Trusted Canonical Hosts (Always Allowed)
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
              {(settings?.canonical_hosts || ['localhost', '127.0.0.1']).map((host) => (
                <span
                  key={host}
                  style={{
                    padding: '3px 8px',
                    borderRadius: '4px',
                    fontSize: '11px',
                    fontFamily: 'monospace',
                    background: 'var(--webcare-bg-surface, #f1f5f9)',
                    color: 'var(--webcare-text-secondary, #475569)',
                    border: '1px solid var(--webcare-border-subtle, #e2e8f0)',
                  }}
                >
                  {host}
                </span>
              ))}
            </div>
          </div>

          {/* Custom Approved Domains */}
          <div style={{ marginTop: '16px' }}>
            <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', marginBottom: '6px' }}>
              External Whitelisted Domains (e.g. Zapier, Staging, Mobile Apps)
            </div>

            {(!settings?.allowed_callback_domains || settings.allowed_callback_domains.length === 0) ? (
              <div
                style={{
                  padding: '12px',
                  borderRadius: '6px',
                  background: 'var(--webcare-bg-surface, #f8fafc)',
                  border: '1px dashed var(--webcare-border-subtle, #e2e8f0)',
                  fontSize: '12px',
                  color: 'var(--webcare-text-muted, #64748b)',
                }}
              >
                No external callback domains whitelisted. All external <code>success_url</code> redirects will be blocked as phishing traps.
              </div>
            ) : (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '12px' }}>
                {settings.allowed_callback_domains.map((dom) => (
                  <span
                    key={dom}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px',
                      padding: '4px 10px',
                      borderRadius: '6px',
                      fontSize: '12px',
                      fontWeight: 500,
                      background: 'var(--webcare-bg-surface, #f1f5f9)',
                      border: '1px solid var(--webcare-border-subtle, #e2e8f0)',
                      color: 'var(--webcare-text-primary, #0f172a)',
                    }}
                  >
                    <code>{dom}</code>
                    <button
                      type="button"
                      onClick={() => handleRemoveDomain(dom)}
                      title="Remove domain"
                      style={{
                        background: 'transparent',
                        border: 'none',
                        cursor: 'pointer',
                        padding: '0 2px',
                        color: '#dc2626',
                        display: 'flex',
                        alignItems: 'center',
                      }}
                    >
                      &times;
                    </button>
                  </span>
                ))}
              </div>
            )}

            {/* Add Domain Form */}
            <form onSubmit={handleAddDomain} style={{ display: 'flex', gap: '8px', marginTop: '12px' }}>
              <input
                type="text"
                placeholder="e.g. zapier.com or *.trusted-app.io"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                className="webcare-input"
                style={{ flex: 1, padding: '7px 12px', fontSize: '13px' }}
              />
              <button
                type="submit"
                className="webcare-btn webcare-btn-secondary"
                disabled={savingSettings || !newDomain.trim()}
                style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
              >
                <Plus size={14} />
                <span>Add Domain</span>
              </button>
            </form>
            {domainError && (
              <div style={{ color: '#dc2626', fontSize: '12px', marginTop: '4px' }}>
                {domainError}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Active Application Passwords Table Card */}
      <div className="webcare-card" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h4 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: 'var(--webcare-text-heading, #0f172a)' }}>
              Active Application Passwords ({passwords.length})
            </h4>
            <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)' }}>
              All REST API credentials currently minted on this WordPress installation.
            </p>
          </div>
        </div>

        {passwords.length === 0 ? (
          <div
            style={{
              padding: '36px 20px',
              textAlign: 'center',
              borderRadius: '8px',
              background: 'var(--webcare-bg-surface, #f8fafc)',
              border: '1px solid var(--webcare-border-subtle, #e2e8f0)',
            }}
          >
            <CheckCircle2 size={32} style={{ color: '#10b981', margin: '0 auto 10px auto' }} />
            <h5 style={{ margin: 0, fontSize: '15px', fontWeight: 600, color: 'var(--webcare-text-heading, #0f172a)' }}>
              No Active Application Passwords Found
            </h5>
            <p style={{ margin: '6px auto 0 auto', maxWidth: '480px', fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)' }}>
              There are currently 0 active REST credentials across all accounts. Your site has zero exposure to Application Password token hijacking.
            </p>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="webcare-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
              <thead>
                <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
                  <th style={{ padding: '10px 14px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)' }}>User Account</th>
                  <th style={{ padding: '10px 14px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)' }}>Application Name &amp; UUID</th>
                  <th style={{ padding: '10px 14px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)' }}>Created</th>
                  <th style={{ padding: '10px 14px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)' }}>Last Used &amp; IP</th>
                  <th style={{ padding: '10px 14px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)' }}>Status</th>
                  <th style={{ padding: '10px 14px', textAlign: 'right', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {passwords.map((item) => (
                  <tr
                    key={item.uuid}
                    style={{
                      borderBottom: '1px solid var(--webcare-border-subtle, #e2e8f0)',
                      background: item.is_stale ? 'rgba(245, 158, 11, 0.03)' : 'transparent',
                    }}
                  >
                    {/* User */}
                    <td style={{ padding: '12px 14px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <div>
                          <div style={{ fontWeight: 600, color: 'var(--webcare-text-heading, #0f172a)' }}>
                            {item.display_name || item.user_login}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                            @{item.user_login} ({item.user_roles.join(', ') || 'user'})
                          </div>
                        </div>
                        {item.is_admin ? (
                          <span className="webcare-badge-pill" style={{ background: '#eef2ff', color: '#4f46e5', border: '1px solid #c7d2fe', fontSize: '10px', padding: '1px 6px' }}>
                            Admin
                          </span>
                        ) : (
                          <span className="webcare-badge-pill" style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fecaca', fontSize: '10px', padding: '1px 6px' }}>
                            Non-Admin
                          </span>
                        )}
                      </div>
                    </td>

                    {/* App Name & UUID */}
                    <td style={{ padding: '12px 14px' }}>
                      <div style={{ fontWeight: 600, color: 'var(--webcare-text-heading, #0f172a)' }}>
                        {item.name}
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', fontFamily: 'monospace' }}>
                        {item.uuid}
                      </div>
                    </td>

                    {/* Created */}
                    <td style={{ padding: '12px 14px', whiteSpace: 'nowrap' }}>
                      <div style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>
                        {item.created_human}
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                        {item.created_date}
                      </div>
                    </td>

                    {/* Last Used & IP */}
                    <td style={{ padding: '12px 14px', whiteSpace: 'nowrap' }}>
                      <div style={{ color: item.last_used ? 'var(--webcare-text-primary, #0f172a)' : '#d97706', fontWeight: item.last_used ? 400 : 600 }}>
                        {item.last_used_human}
                      </div>
                      {item.last_ip && (
                        <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', fontFamily: 'monospace' }}>
                          IP: {item.last_ip}
                        </div>
                      )}
                    </td>

                    {/* Status */}
                    <td style={{ padding: '12px 14px' }}>
                      {item.is_stale ? (
                        <span
                          className="webcare-badge-pill"
                          style={{
                            background: 'var(--webcare-badge-warning-bg, #fffbeb)',
                            color: 'var(--webcare-badge-warning-text, #d97706)',
                            border: '1px solid var(--webcare-badge-warning-border, #fde68a)',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                          }}
                        >
                          <Clock size={11} /> Stale
                        </span>
                      ) : (
                        <span
                          className="webcare-badge-pill"
                          style={{
                            background: 'var(--webcare-badge-clean-bg, #ecfdf5)',
                            color: 'var(--webcare-badge-clean-text, #047857)',
                            border: '1px solid var(--webcare-badge-clean-border, #a7f3d0)',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                          }}
                        >
                          <CheckCircle2 size={11} /> Active
                        </span>
                      )}
                    </td>

                    {/* Action */}
                    <td style={{ padding: '12px 14px', textAlign: 'right' }}>
                      <button
                        type="button"
                        onClick={() => handleRevokePassword(item)}
                        title="Revoke Application Password"
                        className="webcare-btn webcare-btn-danger"
                        style={{
                          padding: '5px 10px',
                          fontSize: '12px',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                        }}
                      >
                        <Trash2 size={12} />
                        <span>Revoke</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Confirmation Dialog */}
      <ConfirmDialog
        isOpen={confirmDialog.isOpen}
        title={confirmDialog.title}
        message={confirmDialog.message}
        confirmLabel={confirmDialog.confirmLabel}
        variant={confirmDialog.variant}
        onConfirm={confirmDialog.onConfirm}
        onCancel={() => setConfirmDialog((prev) => ({ ...prev, isOpen: false }))}
      />
    </div>
  );
};
