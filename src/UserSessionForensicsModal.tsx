import { useState, useEffect, useMemo } from '@wordpress/element';
import {
  Laptop,
  Smartphone,
  Tablet,
  Globe,
  Clock,
  Shield,
  ShieldCheck,
  Lock,
  Copy,
  Check,
  X,
  RefreshCw,
  Loader2,
  Monitor,
  Maximize2,
  Calendar,
  KeyRound,
  CheckCircle2,
  Eye,
  Info,
  AlertTriangle,
  History,
  Filter,
  CheckCircle
} from 'lucide-react';

export interface LoginHistoryRecord {
  id: number;
  login_time: string;
  login_time_human: string;
  logout_time: string | null;
  last_seen: string | null;
  duration_seconds: number;
  duration_formatted: string;
  is_active: boolean;
  ip: string;
  browser: string;
  browser_version: string;
  platform: string;
  device_type: 'Desktop' | 'Mobile' | 'Tablet' | string;
  screen_resolution: string;
  viewport?: string;
  timezone?: string;
  country?: string;
  country_code?: string;
  user_agent: string;
  auth_method: string;
}

export interface UserForensicsData {
  success: boolean;
  user: {
    id: number;
    login: string;
    display_name: string;
    email: string;
    avatar_url: string;
    roles: string[];
    registered?: string;
  };
  last_login_time: string;
  total_active_seconds: number;
  total_active_formatted: string;
  active_sessions_count: number;
  history: LoginHistoryRecord[];
}

export interface UserSessionForensicsModalProps {
  isOpen: boolean;
  userId: number | null;
  username?: string;
  onClose: () => void;
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  inline?: boolean;
}

const DEFAULT_AVATAR_URI = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%2394a3b8'%3E%3Cpath d='M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z'/%3E%3C/svg%3E";

export const UserSessionForensicsModal = ({
  isOpen,
  userId,
  username,
  onClose,
  apiRequest,
  inline = false,
}: UserSessionForensicsModalProps) => {
  const [loading, setLoading] = useState<boolean>(false);
  const [data, setData] = useState<UserForensicsData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedIp, setCopiedIp] = useState<string | null>(null);
  const [copiedUa, setCopiedUa] = useState<number | null>(null);
  const [expandedUa, setExpandedUa] = useState<number | null>(null);
  const [recordLimit, setRecordLimit] = useState<number>(0); // 0 = All / Unlimited
  const [selectedIpFilter, setSelectedIpFilter] = useState<string>('all');
  const [activeTab, setActiveTab] = useState<'timeline' | 'ip_directory'>('timeline');

  const fetchUserHistory = async (targetId: number, limit: number = recordLimit) => {
    try {
      setLoading(true);
      setError(null);
      const limitParam = limit === 0 ? '0' : String(limit);
      const res = await apiRequest({
        path: `/auth/user-history?user_id=${targetId}&limit=${limitParam}`,
        method: 'GET',
      });

      if (res && res.success) {
        setData(res);
      } else {
        setError(res?.message || 'Failed to retrieve forensic user login telemetry.');
      }
    } catch (err: any) {
      setError(err?.message || 'An error occurred while loading forensic login history.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen && userId) {
      fetchUserHistory(userId, recordLimit);
    } else if (!isOpen) {
      setData(null);
      setError(null);
      setSelectedIpFilter('all');
    }
  }, [isOpen, userId, recordLimit]);

  // Handle Escape key to close
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Compute unique IP stats and IP change detection
  const ipAnalytics = useMemo(() => {
    const history = data?.history || [];
    const ipMap: Record<string, {
      ip: string;
      count: number;
      firstSeen: string;
      lastSeen: string;
      devices: Set<string>;
      locations: string[];
      hasActive: boolean;
    }> = {};

    let totalIpChanges = 0;

    for (let i = 0; i < history.length; i++) {
      const rec = history[i];
      const prevRec = i < history.length - 1 ? history[i + 1] : null;

      // In chronological order, if rec.ip differs from the previous session (history[i+1]), that's an IP shift
      if (prevRec && rec.ip !== prevRec.ip) {
        totalIpChanges++;
      }

      if (!ipMap[rec.ip]) {
        ipMap[rec.ip] = {
          ip: rec.ip,
          count: 0,
          firstSeen: rec.login_time,
          lastSeen: rec.login_time,
          devices: new Set(),
          locations: [],
          hasActive: false,
        };
      }

      ipMap[rec.ip].count++;
      ipMap[rec.ip].devices.add(`${rec.browser} / ${rec.platform}`);
      if (rec.is_active) {
        ipMap[rec.ip].hasActive = true;
      }
      // Update firstSeen since list is descending
      ipMap[rec.ip].firstSeen = rec.login_time;
    }

    const uniqueList = Object.values(ipMap).sort((a, b) => b.count - a.count);

    return {
      uniqueList,
      totalUniqueIps: uniqueList.length,
      totalIpChanges,
    };
  }, [data?.history]);

  // Filtered history if an IP filter is chosen
  const filteredHistory = useMemo(() => {
    const history = data?.history || [];
    if (selectedIpFilter === 'all') return history;
    return history.filter(item => item.ip === selectedIpFilter);
  }, [data?.history, selectedIpFilter]);

  if (!isOpen) return null;

  const handleCopy = (text: string, type: 'ip' | 'ua', id?: number) => {
    navigator.clipboard.writeText(text);
    if (type === 'ip') {
      setCopiedIp(text);
      setTimeout(() => setCopiedIp(null), 2000);
    } else if (id !== undefined) {
      setCopiedUa(id);
      setTimeout(() => setCopiedUa(null), 2000);
    }
  };

  const getDeviceIcon = (deviceType: string) => {
    const lower = (deviceType || '').toLowerCase();
    if (lower === 'mobile') {
      return <Smartphone size={16} color="#38bdf8" />;
    }
    if (lower === 'tablet') {
      return <Tablet size={16} color="#a855f7" />;
    }
    return <Laptop size={16} color="#0284c7" />;
  };

  const content = (
    <div className={`webcare-usf-window ${inline ? 'webcare-usf-window-inline' : ''}`}>
      {/* Modal Header */}
        <div className="webcare-usf-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div style={{ position: 'relative' }}>
              <img
                src={data?.user?.avatar_url || DEFAULT_AVATAR_URI}
                alt={data?.user?.login || username || 'User'}
                className="webcare-usf-avatar"
              />
              <span
                title="Monitored User Account"
                style={{
                  position: 'absolute',
                  bottom: '-2px',
                  right: '-2px',
                  width: '14px',
                  height: '14px',
                  backgroundColor: '#10b981',
                  borderRadius: '50%',
                  border: '2px solid var(--webcare-bg-panel, #ffffff)'
                }}
              />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <h3 className="webcare-usf-title">
                  {data?.user?.login || username || 'User Forensics'}
                </h3>
                {data?.user?.display_name && data.user.display_name !== data.user.login && (
                  <span style={{ fontSize: '13px', color: 'var(--webcare-text-muted, #64748b)' }}>({data.user.display_name})</span>
                )}
                {data?.user?.roles?.map((role) => (
                  <span
                    key={role}
                    style={{
                      fontSize: '11px',
                      fontWeight: 600,
                      padding: '2px 8px',
                      borderRadius: '12px',
                      background: 'rgba(56, 189, 248, 0.15)',
                      color: '#0284c7',
                      border: '1px solid rgba(56, 189, 248, 0.3)',
                      textTransform: 'uppercase'
                    }}
                  >
                    {role}
                  </span>
                ))}
              </div>
              <div className="webcare-usf-subtitle">
                {data?.user?.email || 'Loading account details...'} &bull; User ID: #{userId}
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                fontSize: '11.5px',
                fontWeight: 600,
                padding: '4px 10px',
                borderRadius: '8px',
                background: 'rgba(16, 185, 129, 0.12)',
                color: '#047857',
                border: '1px solid rgba(16, 185, 129, 0.25)'
              }}
            >
              <Lock size={13} />
              AES-256-GCM AEAD Encrypted Storage
            </span>
            <button
              type="button"
              className="webcare-usf-btn-refresh"
              onClick={() => userId && fetchUserHistory(userId)}
              disabled={loading}
              title="Refresh User History"
            >
              <RefreshCw size={14} className={loading ? 'webcare-spin-icon' : ''} />
              Refresh
            </button>
            <button
              type="button"
              className="webcare-usf-btn-close"
              onClick={onClose}
              title={inline ? "Collapse Forensics" : "Close (Esc)"}
            >
              <X size={20} />
            </button>
          </div>
        </div>

        {/* Modal Scrollable Body */}
        <div style={{ padding: '24px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Zero Plaintext Notice Banner */}
          <div className="webcare-usf-notice-banner">
            <ShieldCheck size={22} color="#0284c7" style={{ flexShrink: 0 }} />
            <div>
              <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>Zero Plaintext Persistence Guarantee:</strong> All IP addresses, User-Agents, screen resolutions, and device fingerprints are stored strictly encrypted at rest in the database using <strong>AES-256-GCM authenticated encryption</strong>. Plaintext data is never written to disk or logs and is decrypted solely on-the-fly for your administrative session.
            </div>
          </div>

          {loading && !data && (
            <div style={{ textAlign: 'center', padding: '60px 20px', color: 'var(--webcare-text-muted, #64748b)' }}>
              <Loader2 size={32} className="webcare-spin-icon" style={{ margin: '0 auto 12px auto', color: '#0284c7' }} />
              <p style={{ margin: 0, fontSize: '14px' }}>Decrypting user login records &amp; device forensics...</p>
            </div>
          )}

          {error && (
            <div
              style={{
                padding: '14px 18px',
                borderRadius: '10px',
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                color: '#dc2626',
                fontSize: '13px'
              }}
            >
              {error}
            </div>
          )}

          {data && (
            <>
              {/* Forensics KPI Summary Cards */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                  gap: '16px'
                }}
              >
                {/* 1. Total Logged-In Time / Duration */}
                <div className="webcare-usf-kpi-card">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <span className="webcare-usf-kpi-label">
                      Active Session Duration
                    </span>
                    <Clock size={16} color="#0284c7" />
                  </div>
                  <div className="webcare-usf-kpi-value" style={{ color: '#0284c7' }}>
                    {data.total_active_formatted || '0s'}
                  </div>
                  <span className="webcare-usf-kpi-sub">
                    Current active session uptime
                  </span>
                </div>

                {/* 2. Last Logged-In Time */}
                <div className="webcare-usf-kpi-card">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <span className="webcare-usf-kpi-label">
                      Last Logged In Time
                    </span>
                    <Calendar size={16} color="#10b981" />
                  </div>
                  <div className="webcare-usf-kpi-value">
                    {data.last_login_time ? data.last_login_time.split(' ')[1] : 'N/A'}
                  </div>
                  <span className="webcare-usf-kpi-sub">
                    {data.last_login_time ? data.last_login_time.split(' ')[0] : 'N/A'}
                  </span>
                </div>

                {/* 3. Concurrent Active Devices */}
                <div className="webcare-usf-kpi-card">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <span className="webcare-usf-kpi-label">
                      Active Devices / Sessions
                    </span>
                    <Laptop size={16} color="#d97706" />
                  </div>
                  <div className="webcare-usf-kpi-value" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {data.active_sessions_count}
                    {data.active_sessions_count === 2 ? (
                      <span style={{ fontSize: '11px', fontWeight: 600, padding: '2px 8px', borderRadius: '10px', background: 'rgba(56, 189, 248, 0.15)', color: '#0284c7', border: '1px solid rgba(56, 189, 248, 0.3)' }}>
                        Dual Device (Desktop + Mobile)
                      </span>
                    ) : data.active_sessions_count > 2 ? (
                      <span style={{ fontSize: '11px', fontWeight: 600, padding: '2px 8px', borderRadius: '10px', background: 'rgba(251, 191, 36, 0.15)', color: '#d97706', border: '1px solid rgba(251, 191, 36, 0.3)' }}>
                        Multiple Active ({data.active_sessions_count})
                      </span>
                    ) : (
                      <span style={{ fontSize: '11px', fontWeight: 600, padding: '2px 8px', borderRadius: '10px', background: 'rgba(52, 211, 153, 0.15)', color: '#047857', border: '1px solid rgba(52, 211, 153, 0.3)' }}>
                        Single Device
                      </span>
                    )}
                  </div>
                  <span className="webcare-usf-kpi-sub">
                    Concurrent administrator sessions
                  </span>
                </div>

                {/* 4. Latest Detected IP */}
                <div className="webcare-usf-kpi-card">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <span className="webcare-usf-kpi-label">
                      Latest IP Address
                    </span>
                    <Globe size={16} color="#7c3aed" />
                  </div>
                  <div className="webcare-usf-kpi-value" style={{ fontSize: '15px', fontFamily: 'monospace', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    {data.history?.[0]?.ip || 'Unknown'}
                    {data.history?.[0]?.ip && (
                      <button
                        type="button"
                        onClick={() => handleCopy(data.history[0].ip, 'ip')}
                        style={{ background: 'none', border: 'none', color: copiedIp === data.history[0].ip ? '#10b981' : 'var(--webcare-text-muted, #64748b)', cursor: 'pointer', padding: '2px' }}
                        title="Copy IP"
                      >
                        {copiedIp === data.history[0].ip ? <Check size={14} /> : <Copy size={14} />}
                      </button>
                    )}
                  </div>
                  <span className="webcare-usf-kpi-sub">
                    {data.history?.[0]?.browser} &bull; {data.history?.[0]?.platform}
                  </span>
                </div>

                {/* 5. IP Volatility & Unique IPs */}
                <div className="webcare-usf-kpi-card">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <span className="webcare-usf-kpi-label">
                      Unique IPs &amp; Shifts
                    </span>
                    <ShieldCheck size={16} color="#10b981" />
                  </div>
                  <div className="webcare-usf-kpi-value" style={{ fontSize: '18px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span>{ipAnalytics.totalUniqueIps} {ipAnalytics.totalUniqueIps === 1 ? 'IP' : 'IPs'}</span>
                    {ipAnalytics.totalIpChanges > 0 ? (
                      <span style={{ fontSize: '11px', fontWeight: 600, padding: '2px 8px', borderRadius: '10px', background: 'rgba(245, 158, 11, 0.15)', color: '#d97706', border: '1px solid rgba(245, 158, 11, 0.3)' }}>
                        {ipAnalytics.totalIpChanges} IP {ipAnalytics.totalIpChanges === 1 ? 'Shift' : 'Shifts'}
                      </span>
                    ) : (
                      <span style={{ fontSize: '11px', fontWeight: 600, padding: '2px 8px', borderRadius: '10px', background: 'rgba(52, 211, 153, 0.15)', color: '#047857', border: '1px solid rgba(52, 211, 153, 0.3)' }}>
                        Stable IP
                      </span>
                    )}
                  </div>
                  <span className="webcare-usf-kpi-sub">
                    Across {data.history?.length || 0} retrieved sessions
                  </span>
                </div>
              </div>

              {/* Forensics Navigation Toolbar & Limit Selector */}
              <div className="webcare-usf-toolbar">
                {/* View Tabs */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <button
                    type="button"
                    onClick={() => setActiveTab('timeline')}
                    style={{
                      padding: '7px 14px',
                      borderRadius: '8px',
                      fontSize: '12.5px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px',
                      transition: 'all 0.15s ease',
                      background: activeTab === 'timeline' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
                      color: activeTab === 'timeline' ? '#0284c7' : 'var(--webcare-text-muted, #64748b)',
                      border: activeTab === 'timeline' ? '1px solid rgba(56, 189, 248, 0.35)' : '1px solid transparent'
                    }}
                  >
                    <History size={14} />
                    Session Timeline ({filteredHistory.length})
                  </button>

                  <button
                    type="button"
                    onClick={() => setActiveTab('ip_directory')}
                    style={{
                      padding: '7px 14px',
                      borderRadius: '8px',
                      fontSize: '12.5px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px',
                      transition: 'all 0.15s ease',
                      background: activeTab === 'ip_directory' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
                      color: activeTab === 'ip_directory' ? '#0284c7' : 'var(--webcare-text-muted, #64748b)',
                      border: activeTab === 'ip_directory' ? '1px solid rgba(56, 189, 248, 0.35)' : '1px solid transparent'
                    }}
                  >
                    <Globe size={14} />
                    IP Address Directory ({ipAnalytics.totalUniqueIps})
                  </button>
                </div>

                {/* Controls: Filter by specific IP & Limit selector */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
                  {/* IP Filter Dropdown */}
                  {ipAnalytics.uniqueList.length > 1 && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Filter size={13} color="var(--webcare-text-muted, #64748b)" />
                      <label style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>Filter IP:</label>
                      <select
                        value={selectedIpFilter}
                        onChange={(e) => setSelectedIpFilter(e.target.value)}
                        className="webcare-usf-select"
                      >
                        <option value="all">All IPs ({ipAnalytics.totalUniqueIps})</option>
                        {ipAnalytics.uniqueList.map(item => (
                          <option key={item.ip} value={item.ip}>
                            {item.ip} ({item.count} sessions)
                          </option>
                        ))}
                      </select>
                    </div>
                  )}

                  {/* Limit Selector */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <label style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>Show Records:</label>
                    <select
                      value={recordLimit}
                      onChange={(e) => setRecordLimit(Number(e.target.value))}
                      className="webcare-usf-select"
                    >
                      <option value={10}>Last 10 Logins</option>
                      <option value={25}>Last 25 Logins</option>
                      <option value={50}>Last 50 Logins</option>
                      <option value={100}>Last 100 Logins</option>
                      <option value={0}>All Unlimited IPs &amp; Sessions</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* View 1: Timeline Mode */}
              {activeTab === 'timeline' && (
                <div className="webcare-usf-panel">
                  <div className="webcare-usf-panel-header">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <Shield size={18} color="#0284c7" />
                      <h4 className="webcare-usf-panel-title">
                        {recordLimit === 0 ? 'All Historical' : `Last ${recordLimit}`} Logins &amp; IP Shift Forensics
                      </h4>
                      <span className="webcare-usf-count-badge">
                        {filteredHistory.length} Decrypted Records
                      </span>
                    </div>
                    <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                      Ordered chronologically (Newest first)
                    </span>
                  </div>

                  {filteredHistory.length === 0 ? (
                    <div style={{ padding: '40px 20px', textAlign: 'center', color: '#94a3b8' }}>
                      No historical login records match the current filter.
                    </div>
                  ) : (
                    <div
                      className="webcare-forensics-scrollbar"
                      style={{
                        display: 'flex',
                        flexDirection: 'column',
                        maxHeight: '520px',
                        overflowY: 'auto',
                        scrollbarWidth: 'thin',
                        scrollbarColor: '#334155 #0f172a'
                      }}
                    >
                      {filteredHistory.map((record, index) => {
                        const isExpanded = expandedUa === record.id;
                        // Determine if IP shifted from previous chronologic session (history[index + 1])
                        const prevSession = index < filteredHistory.length - 1 ? filteredHistory[index + 1] : null;
                        const hasIpChanged = prevSession && prevSession.ip !== record.ip;

                        return (
                          <div
                            key={record.id || index}
                            className="webcare-usf-session-row"
                            style={{
                              borderBottom: index < filteredHistory.length - 1 ? '1px solid var(--webcare-border, #e2e8f0)' : 'none',
                              background: record.is_active ? 'rgba(56, 189, 248, 0.04)' : 'transparent',
                            }}
                          >
                            {/* Row 1: Badges, IP, Duration, Time */}
                            <div
                              style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                alignItems: 'center',
                                flexWrap: 'wrap',
                                gap: '12px',
                                marginBottom: '10px'
                              }}
                            >
                              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                                {record.is_active ? (
                                  <span
                                    style={{
                                      fontSize: '11px',
                                      fontWeight: 700,
                                      padding: '3px 9px',
                                      borderRadius: '12px',
                                      background: 'rgba(16, 185, 129, 0.15)',
                                      color: '#047857',
                                      border: '1px solid rgba(16, 185, 129, 0.3)',
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '5px'
                                    }}
                                  >
                                    <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10b981' }} />
                                    Active Session
                                  </span>
                                ) : (
                                  <span
                                    style={{
                                      fontSize: '11px',
                                      fontWeight: 600,
                                      padding: '3px 9px',
                                      borderRadius: '12px',
                                      background: 'var(--webcare-bg-elevated, #f1f5f9)',
                                      color: 'var(--webcare-text-muted, #64748b)',
                                      border: '1px solid var(--webcare-border, #e2e8f0)'
                                    }}
                                  >
                                    Logged Out / Closed
                                  </span>
                                )}

                                {/* IP with Copy */}
                                <div
                                  className="webcare-usf-ip-pill"
                                  style={{
                                    border: hasIpChanged ? '1px solid rgba(245, 158, 11, 0.5)' : undefined
                                  }}
                                >
                                  <Globe size={13} color={hasIpChanged ? '#d97706' : '#0284c7'} />
                                  <code style={{ fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)', fontWeight: 600 }}>
                                    {record.ip}
                                  </code>
                                  <button
                                    type="button"
                                    onClick={() => handleCopy(record.ip, 'ip')}
                                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedIp === record.ip ? '#10b981' : 'var(--webcare-text-muted, #64748b)', padding: '0 2px' }}
                                    title="Copy IP Address"
                                  >
                                    {copiedIp === record.ip ? <Check size={13} /> : <Copy size={13} />}
                                  </button>
                                </div>

                                {/* IP Changed Alert Badge */}
                                {hasIpChanged && (
                                  <span
                                    title={`Client IP address changed from ${prevSession?.ip}`}
                                    style={{
                                      fontSize: '11px',
                                      fontWeight: 600,
                                      padding: '3px 9px',
                                      borderRadius: '12px',
                                      background: 'rgba(245, 158, 11, 0.15)',
                                      color: '#d97706',
                                      border: '1px solid rgba(245, 158, 11, 0.35)',
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '5px'
                                    }}
                                  >
                                    <AlertTriangle size={12} color="#d97706" />
                                    IP Changed (from {prevSession?.ip})
                                  </span>
                                )}

                                {/* Auth Method / Network Shift Badge */}
                                <span
                                  style={{
                                    fontSize: '11px',
                                    fontWeight: record.auth_method.includes('Network Shift') ? 600 : 500,
                                    color: record.auth_method.includes('Network Shift') ? '#d97706' : 'var(--webcare-text-secondary, #475569)',
                                    background: record.auth_method.includes('Network Shift') ? 'rgba(245, 158, 11, 0.12)' : 'var(--webcare-bg-elevated, #f1f5f9)',
                                    padding: '3px 8px',
                                    borderRadius: '6px',
                                    border: record.auth_method.includes('Network Shift') ? '1px solid rgba(245, 158, 11, 0.3)' : '1px solid var(--webcare-border, #e2e8f0)',
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '5px'
                                  }}
                                >
                                  {record.auth_method.includes('Network Shift') ? (
                                    <AlertTriangle size={12} color="#d97706" />
                                  ) : (
                                    <KeyRound size={12} color="#d97706" />
                                  )}
                                  {record.auth_method}
                                </span>
                              </div>

                              {/* Session Total Duration & Login Timestamp */}
                              <div style={{ display: 'flex', alignItems: 'center', gap: '14px', fontSize: '12.5px' }}>
                                <div
                                  title="Total Logged-In Duration"
                                  style={{
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '5px',
                                    color: '#0284c7',
                                    fontWeight: 600,
                                    background: 'rgba(56, 189, 248, 0.1)',
                                    padding: '3px 10px',
                                    borderRadius: '6px',
                                    border: '1px solid rgba(56, 189, 248, 0.25)'
                                  }}
                                >
                                  <Clock size={13} />
                                  Duration: {record.duration_formatted}
                                </div>

                                <div style={{ color: 'var(--webcare-text-muted, #64748b)' }}>
                                  Logged in: <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>{record.login_time}</strong>{' '}
                                  <span style={{ color: 'var(--webcare-text-muted, #64748b)' }}>({record.login_time_human})</span>
                                </div>
                              </div>
                            </div>

                            {/* Row 2: Device, Browser, Screen Size, Viewport, Timezone */}
                            <div className="webcare-usf-meta-box">
                              {/* Browser & OS */}
                              <div>
                                <span style={{ color: 'var(--webcare-text-muted, #64748b)', fontSize: '11px', display: 'block', textTransform: 'uppercase', fontWeight: 600 }}>
                                  Browser &amp; OS
                                </span>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px', color: 'var(--webcare-text-primary, #0f172a)', fontWeight: 500 }}>
                                  {getDeviceIcon(record.device_type)}
                                  <span>{record.browser} {record.browser_version} on {record.platform}</span>
                                </div>
                              </div>

                              {/* Screen Resolution */}
                              <div>
                                <span style={{ color: 'var(--webcare-text-muted, #64748b)', fontSize: '11px', display: 'block', textTransform: 'uppercase', fontWeight: 600 }}>
                                  Screen Resolution
                                </span>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px', color: 'var(--webcare-text-primary, #0f172a)', fontWeight: 500 }}>
                                  <Monitor size={14} color="#10b981" />
                                  <span>{record.screen_resolution || 'Standard Desktop'}</span>
                                </div>
                              </div>

                              {/* Viewport Size */}
                              <div>
                                <span style={{ color: 'var(--webcare-text-muted, #64748b)', fontSize: '11px', display: 'block', textTransform: 'uppercase', fontWeight: 600 }}>
                                  Browser Viewport
                                </span>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px', color: 'var(--webcare-text-primary, #0f172a)', fontWeight: 500 }}>
                                  <Maximize2 size={14} color="#7c3aed" />
                                  <span>{record.viewport || 'Full Display'}</span>
                                </div>
                              </div>

                              {/* Client Timezone & Device Type */}
                              <div>
                                <span style={{ color: 'var(--webcare-text-muted, #64748b)', fontSize: '11px', display: 'block', textTransform: 'uppercase', fontWeight: 600 }}>
                                  Timezone &amp; Device
                                </span>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px', color: 'var(--webcare-text-primary, #0f172a)', fontWeight: 500 }}>
                                  <Clock size={14} color="#d97706" />
                                  <span>{record.timezone || 'UTC'} ({record.device_type})</span>
                                </div>
                              </div>

                              {/* Origin Country (Cloudflare Header) */}
                              <div>
                                <span style={{ color: 'var(--webcare-text-muted, #64748b)', fontSize: '11px', display: 'block', textTransform: 'uppercase', fontWeight: 600 }}>
                                  Country
                                </span>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px', color: 'var(--webcare-text-primary, #0f172a)', fontWeight: 500 }}>
                                  <Globe size={14} color="#0284c7" />
                                  <span>{record.country || 'Unknown'}</span>
                                </div>
                              </div>
                            </div>

                            {/* Row 3: Collapsible User-Agent */}
                            <div style={{ marginTop: '10px' }}>
                              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                <button
                                  type="button"
                                  onClick={() => setExpandedUa(isExpanded ? null : record.id)}
                                  style={{
                                    background: 'none',
                                    border: 'none',
                                    color: '#0284c7',
                                    cursor: 'pointer',
                                    fontSize: '11.5px',
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '4px',
                                    padding: 0
                                  }}
                                >
                                  <Eye size={12} />
                                  {isExpanded ? 'Hide User-Agent String' : 'Inspect Full User-Agent String'}
                                </button>

                                <button
                                  type="button"
                                  onClick={() => handleCopy(record.user_agent, 'ua', record.id)}
                                  style={{
                                    background: 'none',
                                    border: 'none',
                                    color: copiedUa === record.id ? '#10b981' : 'var(--webcare-text-muted, #64748b)',
                                    cursor: 'pointer',
                                    fontSize: '11.5px',
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '4px'
                                  }}
                                >
                                  {copiedUa === record.id ? <Check size={12} /> : <Copy size={12} />}
                                  {copiedUa === record.id ? 'Copied UA!' : 'Copy User-Agent'}
                                </button>
                              </div>

                              {isExpanded && (
                                <pre
                                  style={{
                                    marginTop: '8px',
                                    background: 'var(--webcare-bg-deep, #f8fafc)',
                                    padding: '10px 14px',
                                    borderRadius: '6px',
                                    border: '1px solid var(--webcare-border, #e2e8f0)',
                                    color: 'var(--webcare-text-secondary, #475569)',
                                    fontSize: '11.5px',
                                    fontFamily: 'monospace',
                                    whiteSpace: 'pre-wrap',
                                    wordBreak: 'break-all',
                                    lineHeight: 1.5,
                                    margin: '8px 0 0 0'
                                  }}
                                >
                                  {record.user_agent || 'Unknown User-Agent'}
                                </pre>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* View 2: IP Address Directory */}
              {activeTab === 'ip_directory' && (
                <div className="webcare-usf-panel">
                  <div className="webcare-usf-panel-header">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <Globe size={18} color="#0284c7" />
                      <h4 className="webcare-usf-panel-title">
                        All Distinct IP Addresses Connected to this Account
                      </h4>
                      <span className="webcare-usf-count-badge">
                        {ipAnalytics.uniqueList.length} Unique IPs
                      </span>
                    </div>
                    <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                      Aggregated across complete forensics history
                    </span>
                  </div>

                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
                      <thead>
                        <tr className="webcare-usf-table-head">
                          <th style={{ padding: '12px 18px', fontWeight: 600 }}>IP Address</th>
                          <th style={{ padding: '12px 18px', fontWeight: 600 }}>Total Sessions</th>
                          <th style={{ padding: '12px 18px', fontWeight: 600 }}>First Connection</th>
                          <th style={{ padding: '12px 18px', fontWeight: 600 }}>Most Recent Access</th>
                          <th style={{ padding: '12px 18px', fontWeight: 600 }}>Associated Browsers &amp; Platforms</th>
                          <th style={{ padding: '12px 18px', fontWeight: 600, textAlign: 'right' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {ipAnalytics.uniqueList.map((item, idx) => (
                          <tr
                            key={item.ip}
                            style={{
                              borderBottom: idx < ipAnalytics.uniqueList.length - 1 ? '1px solid var(--webcare-border, #e2e8f0)' : 'none',
                              background: item.hasActive ? 'rgba(16, 185, 129, 0.05)' : (idx % 2 === 0 ? 'transparent' : 'rgba(79, 70, 229, 0.02)')
                            }}
                          >
                            <td style={{ padding: '14px 18px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <Globe size={14} color="#0284c7" />
                                <code style={{ fontSize: '13px', fontWeight: 700, color: '#0284c7' }}>{item.ip}</code>
                                {item.hasActive && (
                                  <span style={{ fontSize: '10px', background: 'rgba(16, 185, 129, 0.15)', color: '#047857', padding: '1px 6px', borderRadius: '8px', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
                                    Active Now
                                  </span>
                                )}
                              </div>
                            </td>
                            <td style={{ padding: '14px 18px', color: 'var(--webcare-text-primary, #0f172a)', fontWeight: 600 }}>
                              {item.count} {item.count === 1 ? 'session' : 'sessions'}
                            </td>
                            <td style={{ padding: '14px 18px', color: 'var(--webcare-text-muted, #64748b)', fontSize: '12.5px' }}>
                              {item.firstSeen}
                            </td>
                            <td style={{ padding: '14px 18px', color: 'var(--webcare-text-secondary, #475569)', fontSize: '12.5px' }}>
                              {item.lastSeen}
                            </td>
                            <td style={{ padding: '14px 18px', color: 'var(--webcare-text-muted, #64748b)', fontSize: '12px' }}>
                              {Array.from(item.devices).join(' • ')}
                            </td>
                            <td style={{ padding: '14px 18px', textAlign: 'right' }}>
                              <div style={{ display: 'inline-flex', gap: '8px' }}>
                                <button
                                  type="button"
                                  onClick={() => handleCopy(item.ip, 'ip')}
                                  style={{
                                    background: 'var(--webcare-bg-elevated, #f1f5f9)',
                                    color: copiedIp === item.ip ? '#10b981' : 'var(--webcare-text-muted, #64748b)',
                                    border: '1px solid var(--webcare-border, #e2e8f0)',
                                    padding: '5px 10px',
                                    borderRadius: '6px',
                                    cursor: 'pointer',
                                    fontSize: '11.5px',
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '4px'
                                  }}
                                  title="Copy IP"
                                >
                                  {copiedIp === item.ip ? <Check size={12} /> : <Copy size={12} />}
                                  {copiedIp === item.ip ? 'Copied' : 'Copy'}
                                </button>
                                <button
                                  type="button"
                                  onClick={() => {
                                    setSelectedIpFilter(item.ip);
                                    setActiveTab('timeline');
                                  }}
                                  style={{
                                    background: 'rgba(56, 189, 248, 0.15)',
                                    color: '#0284c7',
                                    border: '1px solid rgba(56, 189, 248, 0.3)',
                                    padding: '5px 10px',
                                    borderRadius: '6px',
                                    cursor: 'pointer',
                                    fontSize: '11.5px',
                                    fontWeight: 600
                                  }}
                                >
                                  View Logins
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Modal Footer */}
        <div className="webcare-usf-footer">
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Info size={14} color="#0284c7" /> Direct 1-on-1 Forensics &bull; Mir Alamin (WebCare Pro)
          </div>
          <button
            type="button"
            className="webcare-usf-btn-action"
            onClick={onClose}
          >
            {inline ? 'Close Forensics' : 'Close Forensics Inspector'}
          </button>
        </div>
    </div>
  );

  if (inline) {
    return (
      <div className="webcare-usf-inline-container" style={{ width: '100%', marginTop: '12px', animation: 'webcareFadeIn 0.2s ease-out' }}>
        {content}
      </div>
    );
  }

  return (
    <div
      className="webcare-usf-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      {content}
    </div>
  );
};

export default UserSessionForensicsModal;
