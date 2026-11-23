import { useState, useEffect } from '@wordpress/element';
import { showConfirm } from '../utils/dialog';
import {
  Fingerprint,
  ShieldCheck,
  ShieldAlert,
  Shield,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Zap,
  Globe,
  Clock,
  UserCheck,
  UserX,
  LogOut,
  Laptop,
  Smartphone,
  RotateCcw,
  Search,
  Check,
  Loader2,
  Lock,
  Unlock,
  AlertCircle,
  Eye,
  Key,
  Flame,
  ArrowUpRight,
  Sliders,
  Settings,
  Mail,
  UserPlus
} from 'lucide-react';
import { formatRelativeTime } from '../timeUtils';

interface IdentityForensicsCardProps {
  apiRequest: (options: any) => Promise<any>;
  initialSubTab?: 'sessions' | 'breach';
  onSubTabChange?: (sub: 'sessions' | 'breach') => void;
}

export const IdentityForensicsCard = ({ apiRequest, initialSubTab = 'sessions', onSubTabChange }: IdentityForensicsCardProps) => {
  const getStartingTab = (): 'sessions' | 'breach' => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const sub = urlParams.get('subtab');
      if (sub && ['sessions', 'breach'].includes(sub)) {
        return sub as any;
      }
    } catch (e) {}
    return initialSubTab || 'sessions';
  };

  const [activeSubTab, setActiveSubTab] = useState<'sessions' | 'breach'>(getStartingTab);

  useEffect(() => {
    if (initialSubTab && initialSubTab !== activeSubTab) {
      setActiveSubTab(initialSubTab);
    }
  }, [initialSubTab]);

  const handleSubTabSwitch = (sub: 'sessions' | 'breach') => {
    setActiveSubTab(sub);
    if (onSubTabChange) {
      onSubTabChange(sub);
    } else {
      try {
        const url = new URL(window.location.href);
        url.searchParams.set('subtab', sub);
        window.history.pushState({ subtab: sub }, '', url.toString());
      } catch (e) {}
    }
  };
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Identity State
  const [sessionsReport, setSessionsReport] = useState<any>({
    total_sessions: 0,
    high_risk_sessions: 0,
    sessions: [],
    travel_alerts: [],
    settings: {
      enabled: true,
      impossible_travel_enabled: true,
      impossible_travel_hours: 2,
      auto_revoke_impossible_travel: false,
      detect_ua_hijack: true,
    },
  });

  const [hibpSummary, setHibpSummary] = useState<any>({
    stats: { total_checks: 0, breached_blocked: 0, last_check_time: null },
    audit_report: null,
  });

  // Action states
  const [revokingSession, setRevokingSession] = useState<string | null>(null);
  const [revokingAllUser, setRevokingAllUser] = useState<number | null>(null);
  const [savingSettings, setSavingSettings] = useState<boolean>(false);
  const [auditingUsers, setAuditingUsers] = useState<boolean>(false);
  const [forcingResetUid, setForcingResetUid] = useState<number | null>(null);

  // Filter state
  const [searchFilter, setSearchFilter] = useState<string>('');

  const showNotification = (type: 'success' | 'error', text: string) => {
    setNotification({ type, text });
    setTimeout(() => setNotification(null), 4500);
  };

  // Fetch telemetry
  const fetchTelemetry = async (silent = false) => {
    if (!silent) setLoading(true);
    setRefreshing(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/identity/status',
        method: 'GET',
      });
      if (res?.success) {
        if (res.sessions_report) setSessionsReport(res.sessions_report);
        if (res.hibp_summary) setHibpSummary(res.hibp_summary);
      }
    } catch (err: any) {
      console.error('Failed to load identity forensics:', err);
      showNotification('error', 'Failed to retrieve identity telemetry from server.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchTelemetry();
  }, []);

  // Run HIBP Privileged User Audit
  const handleRunBreachAudit = async () => {
    setAuditingUsers(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/identity/audit-users',
        method: 'POST',
      });
      if (res?.success && res.report) {
        setHibpSummary((prev: any) => ({ ...prev, audit_report: res.report }));
        showNotification('success', `Audited ${res.report.total_audited} privileged accounts.`);
      } else {
        showNotification('error', 'Failed to audit user accounts.');
      }
    } catch (err: any) {
      showNotification('error', err.message || 'Error running audit.');
    } finally {
      setAuditingUsers(false);
    }
  };

  // Force Password Reset
  const handleForcePasswordReset = async (userId: number, login: string) => {
    const confirmed = await showConfirm({
      title: 'Force Password Reset',
      message: `Force an immediate password reset for "${login}"? All active sessions will be terminated and a reset link will be emailed.`,
      confirmLabel: 'Force Reset',
      variant: 'warning',
    });
    if (!confirmed) {
      return;
    }
    setForcingResetUid(userId);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/identity/force-reset',
        method: 'POST',
        data: { user_id: userId },
      });
      if (res?.success) {
        showNotification('success', res.message || `Password reset link dispatched to ${login}.`);
        await fetchTelemetry(true);
      } else {
        showNotification('error', res?.message || 'Failed to force reset.');
      }
    } catch (err: any) {
      showNotification('error', err.message || 'Error dispatching reset.');
    } finally {
      setForcingResetUid(null);
    }
  };

  // Dismiss Travel Alert
  const handleDismissTravelAlert = async (alertId: string) => {
    try {
      await apiRequest({
        path: '/webcare-pro-security/v1/identity/dismiss-travel-alert',
        method: 'POST',
        data: { alert_id: alertId },
      });
      await fetchTelemetry(true);
    } catch (e) {
      // ignore
    }
  };

  // Save Settings
  const handleSaveSettings = async () => {
    setSavingSettings(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/identity/settings',
        method: 'POST',
        data: sessionsReport.settings,
      });
      if (res?.success) {
        showNotification('success', 'Zero-Trust identity settings saved successfully.');
        await fetchTelemetry(true);
      } else {
        showNotification('error', res?.message || 'Failed to save settings.');
      }
    } catch (err: any) {
      showNotification('error', err.message || 'Error saving settings.');
    } finally {
      setSavingSettings(false);
    }
  };

  // Filtered sessions
  const filteredSessions = (sessionsReport.sessions || []).filter((s: any) => {
    if (!searchFilter) return true;
    const q = searchFilter.toLowerCase();
    return (
      (s.user_login || '').toLowerCase().includes(q) ||
      (s.ip || '').toLowerCase().includes(q) ||
      (s.country || '').toLowerCase().includes(q)
    );
  });

  return (
    <div className="webcare-identity-forensics-container">
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
                  background: 'linear-gradient(135deg, #0284c7 0%, #4f46e5 100%)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#ffffff',
                }}
              >
                <Fingerprint size={20} />
              </div>
              <div>
                <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'inherit' }}>
                  Zero-Trust Identity &amp; Session Forensics
                </h2>
                <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  Pillar 4: Real-Time Impossible Travel Telemetry, Anti-Cookie Hijack &amp; HIBP Leak Shield
                </span>
              </div>
            </div>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)', maxWidth: '780px', lineHeight: 1.5 }}>
              Moves WordPress security beyond basic 2FA and brute-force lockouts. Detects stolen session cookies and cross-continent impossible travel in real time, and enforces zero-plaintext cryptographic breach verification.
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
              <span>{refreshing ? 'Updating...' : 'Refresh Forensics'}</span>
            </button>
          </div>
        </div>

        {/* Top KPI Cards */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
            gap: '14px',
            marginTop: '20px',
          }}
        >
          {/* Card 1: Active Privileged Sessions */}
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
                ACTIVE ADMIN SESSIONS
              </span>
              <Laptop size={18} style={{ color: '#0284c7' }} />
            </div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: 'inherit' }}>
              {sessionsReport.total_sessions || 0}{' '}
              <span style={{ fontSize: '13px', fontWeight: 500, color: 'var(--webcare-text-muted, #64748b)' }}>
                ({sessionsReport.high_risk_sessions || 0} high risk)
              </span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
              Monitored with User-Agent &amp; IP telemetry
            </div>
          </div>

          {/* Card 2: Impossible Travel Alerts */}
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
                IMPOSSIBLE TRAVEL ALERTS
              </span>
              <Globe size={18} style={{ color: '#ea580c' }} />
            </div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: 'inherit' }}>
              {sessionsReport.travel_alerts?.length || 0}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
              Concurrent cross-country logins flagged
            </div>
          </div>

          {/* Card 3: HIBP Breach Shield */}
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
                LEAKED PASSWORDS BLOCKED
              </span>
              <ShieldCheck size={18} style={{ color: '#10b981' }} />
            </div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: 'inherit' }}>
              {hibpSummary.stats?.breached_blocked || 0}{' '}
              <span style={{ fontSize: '13px', fontWeight: 500, color: 'var(--webcare-text-muted, #64748b)' }}>
                ({hibpSummary.stats?.total_checks || 0} checked)
              </span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
              K-Anonymity SHA-1 privacy verified
            </div>
          </div>
        </div>
      </div>

      {/* Sub-Tabs Bar */}
      <div className="webcare-tabs-bar" style={{ marginBottom: '20px' }}>
        <button
          type="button"
          className={`webcare-tab-link ${activeSubTab === 'sessions' ? 'is-active' : ''}`}
          onClick={() => handleSubTabSwitch('sessions')}
        >
          <Laptop size={15} />
          Active Sessions &amp; Impossible Travel ({sessionsReport.total_sessions || 0})
        </button>

        <button
          type="button"
          className={`webcare-tab-link ${activeSubTab === 'breach' ? 'is-active' : ''}`}
          onClick={() => handleSubTabSwitch('breach')}
        >
          <Key size={15} />
          Credential Leak Armor &amp; Admin Hygiene
        </button>
      </div>

      {/* SUB-TAB 1: Active Sessions & Impossible Travel */}
      {activeSubTab === 'sessions' && (
        <div>
          {/* Impossible Travel Alerts Banner (if present) */}
          {sessionsReport.travel_alerts?.length > 0 && (
            <div
              className="webcare-firewall-card"
              style={{
                marginBottom: '20px',
                borderLeft: '4px solid #ea580c',
                background: 'rgba(234, 88, 12, 0.05)',
              }}
            >
              <h4 style={{ margin: '0 0 10px', fontSize: '14px', fontWeight: 700, color: '#ea580c', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <AlertTriangle size={16} />
                Suspicious Impossible Travel Incidents Flagged ({sessionsReport.travel_alerts.length})
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {sessionsReport.travel_alerts.map((a: any) => (
                  <div
                    key={a.id}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: '10px',
                      padding: '8px 12px',
                      borderRadius: '6px',
                      background: 'var(--webcare-bg-surface, #f8fafc)',
                      border: '1px solid var(--webcare-border-table, #e2e8f0)',
                      fontSize: '12px',
                    }}
                  >
                    <div>
                      <strong>{a.user_login}</strong> logged in from <strong>{a.new_country}</strong> ({a.new_ip}) within{' '}
                      <strong>{a.delta_minutes} mins</strong> of active session in <strong>{a.prev_country}</strong> ({a.prev_ip}).
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <button
                        type="button"
                        className="webcare-btn-micro"
                        style={{ color: '#ea580c' }}
                        onClick={() => handleRevokeAllSessions(a.user_id)}
                      >
                        Revoke All User Sessions
                      </button>
                      <button
                        type="button"
                        className="webcare-btn-micro"
                        onClick={() => handleDismissTravelAlert(a.id)}
                      >
                        Dismiss
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Search Strip */}
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
                  placeholder="Filter sessions by user, IP, country..."
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

            <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
              Total Privileged Sessions: <strong>{sessionsReport.total_sessions || 0}</strong>
            </div>
          </div>

          {/* Sessions Table */}
          <div className="webcare-waf-table-card" style={{ borderRadius: '8px', overflow: 'hidden' }}>
            <table className="webcare-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
              <thead>
                <tr>
                  <th style={{ textAlign: 'left', padding: '12px 16px' }}>User &amp; Role</th>
                  <th style={{ textAlign: 'left', padding: '12px 14px' }}>IP &amp; Geolocation</th>
                  <th style={{ textAlign: 'left', padding: '12px 14px' }}>Device / User Agent</th>
                  <th style={{ textAlign: 'center', padding: '12px 14px', width: '120px' }}>Risk Score</th>
                  <th style={{ textAlign: 'left', padding: '12px 14px', width: '140px' }}>Activity</th>
                  <th style={{ textAlign: 'right', padding: '12px 16px', width: '160px' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', padding: '40px', color: 'var(--webcare-text-muted, #64748b)' }}>
                      <Loader2 size={24} className="webcare-spin" style={{ margin: '0 auto 8px' }} />
                      <div>Analyzing active session tokens and forensic signatures...</div>
                    </td>
                  </tr>
                ) : filteredSessions.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', padding: '40px', color: 'var(--webcare-text-muted, #64748b)' }}>
                      <ShieldCheck size={28} style={{ color: '#10b981', margin: '0 auto 8px' }} />
                      <div>No active sessions matching filter.</div>
                    </td>
                  </tr>
                ) : (
                  filteredSessions.map((s: any, idx: number) => {
                    const isRevoking = revokingSession === s.verifier;
                    return (
                      <tr key={idx} className="webcare-waf-ip-row">
                        <td style={{ padding: '12px 16px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ fontWeight: 600, color: 'inherit' }}>{s.user_login}</span>
                            <span
                              className="webcare-badge-pill"
                              style={{
                                fontSize: '10px',
                                padding: '1px 6px',
                                background: s.role === 'administrator' ? 'rgba(79, 70, 229, 0.1)' : 'rgba(2, 132, 199, 0.1)',
                                color: s.role === 'administrator' ? '#4f46e5' : '#0284c7',
                              }}
                            >
                              {s.role}
                            </span>
                            {s.is_current && (
                              <span
                                className="webcare-badge-pill"
                                style={{
                                  fontSize: '10px',
                                  padding: '1px 6px',
                                  background: 'rgba(16, 185, 129, 0.15)',
                                  color: '#059669',
                                  border: '1px solid rgba(16, 185, 129, 0.3)',
                                }}
                              >
                                Current Device
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
                            {s.user_email}
                          </div>
                        </td>

                        <td style={{ padding: '12px 14px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span style={{ fontFamily: 'monospace', fontWeight: 600, fontSize: '12px' }}>
                              {s.ip}
                            </span>
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
                            {s.country} {s.city !== 'Unknown' ? `(${s.city})` : ''}
                          </div>
                        </td>

                        <td style={{ padding: '12px 14px', maxWidth: '240px' }}>
                          <div
                            style={{
                              fontSize: '12px',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                            title={s.user_agent}
                          >
                            {s.user_agent}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                            Token: <code>{s.session_id}</code>
                          </div>
                        </td>

                        <td style={{ textAlign: 'center', padding: '12px 14px' }}>
                          <span
                            className="webcare-badge-pill"
                            style={{
                              fontSize: '11px',
                              fontWeight: 700,
                              padding: '2px 8px',
                              background:
                                s.risk_score >= 50
                                  ? 'rgba(239, 68, 68, 0.15)'
                                  : s.risk_score >= 25
                                  ? 'rgba(245, 158, 11, 0.15)'
                                  : 'rgba(16, 185, 129, 0.15)',
                              color:
                                s.risk_score >= 50
                                  ? '#dc2626'
                                  : s.risk_score >= 25
                                  ? '#b45309'
                                  : '#059669',
                            }}
                          >
                            {s.risk_score}% Risk
                          </span>
                        </td>

                        <td style={{ padding: '12px 14px', fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                          <div>Login: {formatRelativeTime(s.login_time_gmt || s.login_time)}</div>
                          <div style={{ fontSize: '11px' }}>Active: {formatRelativeTime(s.last_seen_gmt || s.last_seen)}</div>
                        </td>

                        <td style={{ textAlign: 'right', padding: '12px 16px' }}>
                          {s.is_current ? (
                            <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>This Device</span>
                          ) : (
                            <button
                              type="button"
                              className="webcare-btn-micro"
                              onClick={() => handleRevokeSession(s.user_id, s.verifier)}
                              disabled={isRevoking}
                              style={{ color: '#dc2626', fontSize: '11px' }}
                            >
                              {isRevoking ? <Loader2 size={11} className="webcare-spin" /> : 'Revoke Session'}
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Forensics Settings Strip */}
          <div className="webcare-firewall-card" style={{ marginTop: '20px' }}>
            <h3 style={{ fontSize: '15px', fontWeight: 700, margin: '0 0 14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Settings size={16} />
              Zero-Trust Session Forensics Settings
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '16px' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={!!sessionsReport.settings?.impossible_travel_enabled}
                  onChange={(e) =>
                    setSessionsReport({
                      ...sessionsReport,
                      settings: { ...sessionsReport.settings, impossible_travel_enabled: e.target.checked },
                    })
                  }
                  style={{ width: '16px', height: '16px', accentColor: '#0284c7' }}
                />
                <div>
                  <span style={{ fontSize: '13px', fontWeight: 600 }}>Impossible Travel Detection</span>
                  <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    Flag logins occurring from different countries within short time delta.
                  </div>
                </div>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={!!sessionsReport.settings?.auto_revoke_impossible_travel}
                  onChange={(e) =>
                    setSessionsReport({
                      ...sessionsReport,
                      settings: { ...sessionsReport.settings, auto_revoke_impossible_travel: e.target.checked },
                    })
                  }
                  style={{ width: '16px', height: '16px', accentColor: '#0284c7' }}
                />
                <div>
                  <span style={{ fontSize: '13px', fontWeight: 600 }}>Auto-Revoke Impossible Travel Sessions</span>
                  <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    Automatically terminate incoming sessions if location changes impossibly fast.
                  </div>
                </div>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={!!sessionsReport.settings?.detect_ua_hijack}
                  onChange={(e) =>
                    setSessionsReport({
                      ...sessionsReport,
                      settings: { ...sessionsReport.settings, detect_ua_hijack: e.target.checked },
                    })
                  }
                  style={{ width: '16px', height: '16px', accentColor: '#0284c7' }}
                />
                <div>
                  <span style={{ fontSize: '13px', fontWeight: 600 }}>User-Agent Anti-Hijack Guard</span>
                  <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    Immediately destroys sessions if browser user-agent changes mid-session.
                  </div>
                </div>
              </label>
            </div>

            <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'flex-end' }}>
              <button
                type="button"
                className="webcare-btn-primary"
                onClick={handleSaveSettings}
                disabled={savingSettings}
                style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', padding: '8px 16px' }}
              >
                {savingSettings ? <Loader2 size={14} className="webcare-spin" /> : <Check size={14} />}
                <span>Save Session Settings</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB 2: Credential Leak Armor & Admin Hygiene */}
      {activeSubTab === 'breach' && (
        <div>
          {/* HaveIBeenPwned Real-time Strip */}
          <div
            className="webcare-firewall-card"
            style={{
              padding: '16px 20px',
              borderRadius: '8px',
              marginBottom: '20px',
              background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.04) 0%, rgba(79, 70, 229, 0.04) 100%)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
              <ShieldCheck size={28} style={{ color: '#10b981', flexShrink: 0, marginTop: '2px' }} />
              <div>
                <h4 style={{ margin: '0 0 6px', fontSize: '15px', fontWeight: 700 }}>
                  Cryptographic K-Anonymity Credential Leak Armor
                </h4>
                <p style={{ margin: 0, fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5 }}>
                  WebCare Pro Security & Firewall inspects all password creation and update vectors against HaveIBeenPwned's multi-billion compromised password database using <strong>k-Anonymity SHA-1 prefixes</strong>. Plaintext passwords never leave your server and full hashes are never exposed. Compromised passwords that appear in public data dumps are rejected before saving.
                </p>
              </div>
            </div>
          </div>

          {/* Admin Accounts Hygiene Scanner */}
          <div className="webcare-waf-table-card" style={{ borderRadius: '8px', overflow: 'hidden' }}>
            <div
              style={{
                padding: '14px 18px',
                borderBottom: '1px solid var(--webcare-border-table, #e2e8f0)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '12px',
              }}
            >
              <div>
                <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 700 }}>
                  Privileged Administrator &amp; Editor Account Hygiene
                </h4>
                <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  Audits usernames, 2FA status, and stale access on privileged accounts
                </span>
              </div>

              <button
                type="button"
                className="webcare-btn-primary"
                onClick={handleRunBreachAudit}
                disabled={auditingUsers}
                style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', padding: '6px 14px' }}
              >
                {auditingUsers ? <Loader2 size={13} className="webcare-spin" /> : <RefreshCw size={13} />}
                <span>{auditingUsers ? 'Auditing...' : 'Run Account Hygiene Audit'}</span>
              </button>
            </div>

            <table className="webcare-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
              <thead>
                <tr>
                  <th style={{ textAlign: 'left', padding: '12px 16px' }}>Account</th>
                  <th style={{ textAlign: 'center', padding: '12px 14px', width: '120px' }}>2FA Status</th>
                  <th style={{ textAlign: 'center', padding: '12px 14px', width: '120px' }}>Risk Score</th>
                  <th style={{ textAlign: 'left', padding: '12px 16px' }}>Hygiene Warnings</th>
                  <th style={{ textAlign: 'right', padding: '12px 16px', width: '180px' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {!hibpSummary.audit_report?.accounts || hibpSummary.audit_report.accounts.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ textAlign: 'center', padding: '40px', color: 'var(--webcare-text-muted, #64748b)' }}>
                      <Key size={28} style={{ margin: '0 auto 8px', opacity: 0.5 }} />
                      <div>Click "Run Account Hygiene Audit" to evaluate privileged administrators.</div>
                    </td>
                  </tr>
                ) : (
                  hibpSummary.audit_report.accounts.map((a: any) => {
                    const isForcing = forcingResetUid === a.user_id;
                    return (
                      <tr key={a.user_id} className="webcare-waf-ip-row">
                        <td style={{ padding: '12px 16px' }}>
                          <span style={{ fontWeight: 600 }}>{a.user_login}</span>
                          <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>{a.user_email}</div>
                        </td>

                        <td style={{ textAlign: 'center', padding: '12px 14px' }}>
                          {a.two_fa_active ? (
                            <span
                              className="webcare-badge-pill"
                              style={{
                                fontSize: '11px',
                                padding: '2px 8px',
                                background: 'rgba(16, 185, 129, 0.15)',
                                color: '#059669',
                              }}
                            >
                              2FA Active
                            </span>
                          ) : (
                            <span
                              className="webcare-badge-pill"
                              style={{
                                fontSize: '11px',
                                padding: '2px 8px',
                                background: 'rgba(239, 68, 68, 0.15)',
                                color: '#dc2626',
                              }}
                            >
                              No 2FA
                            </span>
                          )}
                        </td>

                        <td style={{ textAlign: 'center', padding: '12px 14px' }}>
                          <span
                            className="webcare-badge-pill"
                            style={{
                              fontSize: '11px',
                              fontWeight: 700,
                              padding: '2px 8px',
                              background:
                                a.risk_score >= 50
                                  ? 'rgba(239, 68, 68, 0.15)'
                                  : a.risk_score >= 25
                                  ? 'rgba(245, 158, 11, 0.15)'
                                  : 'rgba(16, 185, 129, 0.15)',
                              color:
                                a.risk_score >= 50
                                  ? '#dc2626'
                                  : a.risk_score >= 25
                                  ? '#b45309'
                                  : '#059669',
                            }}
                          >
                            {a.risk_score}%
                          </span>
                        </td>

                        <td style={{ padding: '12px 16px' }}>
                          {a.warnings?.length === 0 ? (
                            <span style={{ fontSize: '12px', color: '#10b981' }}>Clean credential hygiene</span>
                          ) : (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                              {a.warnings.map((w: string, widx: number) => (
                                <div key={widx} style={{ fontSize: '11px', color: '#b45309' }}>
                                  • {w}
                                </div>
                              ))}
                            </div>
                          )}
                        </td>

                        <td style={{ textAlign: 'right', padding: '12px 16px' }}>
                          <button
                            type="button"
                            className="webcare-btn-micro"
                            onClick={() => handleForcePasswordReset(a.user_id, a.user_login)}
                            disabled={isForcing}
                            style={{ fontSize: '11px', color: '#dc2626' }}
                          >
                            {isForcing ? <Loader2 size={11} className="webcare-spin" /> : 'Force Password Reset'}
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
    </div>
  );
};

export default IdentityForensicsCard;
