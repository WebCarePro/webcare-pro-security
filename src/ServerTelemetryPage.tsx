import React, { useState, useEffect } from 'react';
import {
  Server,
  HardDrive,
  Terminal,
  Activity,
  Cloud,
  Copy,
  Check,
  ShieldCheck,
  Key,
  RefreshCw,
  Lock,
  Database,
  Folder,
  Package,
  Layers,
  Archive,
  FileCode,
  Shield,
  Loader2
} from 'lucide-react';

export interface ServerTelemetryPageProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  onNavigateToDashboard?: () => void;
  onNavigateToFirewall?: (subTab?: string) => void;
  onNavigateToSettings?: (subTab?: string) => void;
}

export const ServerTelemetryPage: React.FC<ServerTelemetryPageProps> = ({
  apiRequest,
  onNavigateToDashboard,
  onNavigateToFirewall,
  onNavigateToSettings,
}) => {
  const [fwStatus, setFwStatus] = useState<any>(null);
  const [cfStatus, setCfStatus] = useState<any>(null);
  const [serverInfo, setServerInfo] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [copiedIp, setCopiedIp] = useState<string | null>(null);
  const [showDevTelemetry, setShowDevTelemetry] = useState<boolean>(false);

  const copyToClipboard = (text: string, label: string) => {
    if (!text) return;
    try {
      navigator.clipboard.writeText(text);
      setCopiedIp(label);
      setTimeout(() => setCopiedIp(null), 2500);
    } catch {
      // fallback
    }
  };

  const loadData = async (isManualRefresh = false) => {
    if (isManualRefresh) setRefreshing(true);
    else setLoading(true);

    try {
      const [firewallRes, serverRes, cloudflareRes] = await Promise.all([
        apiRequest({ path: '/webcare-pro-security/v1/firewall/status' }).catch(() => null),
        apiRequest({ path: `/webcare-pro-security/v1/server-info${isManualRefresh ? '?refresh=1' : ''}` }).catch(() => null),
        apiRequest({ path: '/webcare-pro-security/v1/cloudflare/status' }).catch(() => null),
      ]);

      if (firewallRes) setFwStatus(firewallRes);
      if (serverRes?.info) setServerInfo(serverRes.info);
      if (cloudflareRes) setCfStatus(cloudflareRes);
    } catch (err) {
      console.error('Failed to load server telemetry data', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const telemetry = fwStatus?.server_telemetry;
  const edgeAdvisor = fwStatus?.edge_advisor;
  const environment = fwStatus?.environment;

  const isApiConnected = !!(cfStatus?.configured || (edgeAdvisor?.api_configured && (cfStatus?.zone_name || edgeAdvisor?.zone_name)));
  const apiError = cfStatus?.error || null;
  const activePlan = cfStatus?.plan || edgeAdvisor?.plan || 'Free';
  const activeZone = cfStatus?.zone_name || edgeAdvisor?.zone_name || '';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
      {/* Page Header Card */}
      <div className="webcare-server-header-card">
        <div>
          <div style={{ marginBottom: '8px', display: 'flex', gap: '10px', alignItems: 'center' }}>
            <button
              type="button"
              className="webcare-server-back-btn"
              onClick={() => onNavigateToDashboard ? onNavigateToDashboard() : (window.location.href = 'admin.php?page=webcare-pro-security')}
            >
              ← Back to Scanner Dashboard
            </button>
            <button
              type="button"
              className="webcare-server-back-btn"
              style={{ color: '#0284c7' }}
              onClick={() => onNavigateToFirewall ? onNavigateToFirewall('rules') : (window.location.href = 'admin.php?page=webcare-pro-firewall')}
            >
              <Shield size={13} style={{ display: 'inline', verticalAlign: '-2px', marginRight: '4px' }} />
              Firewall &amp; WAF Rules →
            </button>
          </div>
          <h2 className="webcare-server-title">
            <Server size={22} color="#0284c7" /> Server &amp; Host Infrastructure Telemetry
          </h2>
          <p className="webcare-server-subtitle">
            Live operating system telemetry, web server engine, PHP runtime limits, host routing, container allocations, and security permissions.
          </p>
        </div>
        <button
          type="button"
          className="webcare-btn webcare-server-refresh-btn"
          onClick={() => loadData(true)}
          disabled={refreshing || loading}
        >
          <RefreshCw size={15} className={refreshing ? 'webcare-spin-icon' : ''} />
          {refreshing ? 'Refreshing...' : 'Refresh Telemetry'}
        </button>
      </div>

      {loading && !serverInfo && !telemetry ? (
        <div style={{ padding: '60px', textAlign: 'center', color: '#64748b' }}>
          <Loader2 size={40} className="webcare-spin" style={{ margin: '0 auto 16px auto', color: '#0284c7' }} />
          <div style={{ fontSize: '15px', fontWeight: 600 }}>Gathering live host telemetry and environment diagnostics...</div>
        </div>
      ) : (
        <>
          {/* =========================================================================
              SECTION 1: SERVER & HOST INFRASTRUCTURE TELEMETRY COCKPIT
              ========================================================================= */}
          {telemetry && (
            <div className="webcare-firewall-telemetry-cockpit">
              <div className="webcare-telemetry-header">
                <div className="webcare-telemetry-header-left">
                  <div className="webcare-telemetry-header-icon">
                    <Server size={18} />
                  </div>
                  <div>
                    <h3 className="webcare-telemetry-title">Host Infrastructure &amp; Runtime Telemetry</h3>
                    <p className="webcare-telemetry-subtitle">
                      Live operating system, web server engine, PHP runtime limits, host routing, and container allocations.
                    </p>
                  </div>
                </div>
                <div className="webcare-telemetry-header-right">
                  <button
                    type="button"
                    className="webcare-telemetry-dev-toggle-btn"
                    onClick={() => setShowDevTelemetry(!showDevTelemetry)}
                  >
                    <Terminal size={14} />
                    {showDevTelemetry ? 'Hide Dev Diagnostics' : 'Dev Diagnostics & Tuning'}
                  </button>
                </div>
              </div>

              <div className="webcare-telemetry-grid">
                {/* Card 1: Linux OS & Kernel Uname */}
                <div className="webcare-telemetry-card">
                  <div className="webcare-telemetry-card-top">
                    <div className="webcare-telemetry-card-label">
                      <Terminal size={14} className="webcare-telemetry-card-icon" />
                      Linux OS &amp; Uname
                    </div>
                    <span className="webcare-telemetry-badge webcare-badge-neutral">
                      {telemetry.php_arch}
                    </span>
                  </div>
                  <div className="webcare-telemetry-card-main">
                    {telemetry.distro_name || 'Linux'}
                  </div>
                  <div className="webcare-telemetry-card-sub">
                    <span className="webcare-telemetry-sub-tag">uname:</span> {telemetry.linux_uname}
                  </div>
                </div>

                {/* Card 2: Server Software */}
                <div className="webcare-telemetry-card">
                  <div className="webcare-telemetry-card-top">
                    <div className="webcare-telemetry-card-label">
                      <Server size={14} className="webcare-telemetry-card-icon" />
                      Server Software
                    </div>
                    <span className="webcare-telemetry-badge webcare-badge-info">
                      {telemetry.server_software_type}
                    </span>
                  </div>
                  <div className="webcare-telemetry-card-main">
                    {telemetry.server_software || 'Web Server'}
                  </div>
                  <div className="webcare-telemetry-card-sub">
                    <span className="webcare-telemetry-sub-tag">SAPI Interface:</span> {telemetry.php_sapi}
                  </div>
                </div>

                {/* Card 3: PHP RAM Available */}
                <div className="webcare-telemetry-card">
                  <div className="webcare-telemetry-card-top">
                    <div className="webcare-telemetry-card-label">
                      <Activity size={14} className="webcare-telemetry-card-icon" />
                      PHP RAM Limit
                    </div>
                    <span className={`webcare-telemetry-badge ${telemetry.php_ram_percent > 80 ? 'webcare-badge-warning' : 'webcare-badge-info'}`}>
                      {telemetry.php_ram_used} / {telemetry.php_ram_limit}
                    </span>
                  </div>
                  <div className="webcare-telemetry-card-main">
                    {telemetry.php_ram_free} Free
                  </div>
                  {/* RAM Usage Progress Bar */}
                  <div className="webcare-telemetry-meter-bg">
                    <div
                      className="webcare-telemetry-meter-bar"
                      style={{
                        width: `${Math.min(100, Math.max(4, telemetry.php_ram_percent))}%`,
                        backgroundColor: telemetry.php_ram_percent > 85 ? '#ef4444' : telemetry.php_ram_percent > 65 ? '#f59e0b' : '#10b981'
                      }}
                    />
                  </div>
                  <div className="webcare-telemetry-card-sub">
                    Peak: {telemetry.php_ram_peak} ({telemetry.php_ram_percent}%)
                    {telemetry.account_ram_limit && (
                      <span> • {telemetry.account_ram_limit}</span>
                    )}
                  </div>
                </div>

                {/* Card 4: Real Origin Server IP */}
                <div className="webcare-telemetry-card">
                  <div className="webcare-telemetry-card-top">
                    <div className="webcare-telemetry-card-label">
                      <HardDrive size={14} className="webcare-telemetry-card-icon" />
                      Real Server IP
                    </div>
                    <span className={`webcare-telemetry-badge ${telemetry.is_server_ip_private ? 'webcare-badge-warning' : 'webcare-badge-info'}`}>
                      {telemetry.is_server_ip_private ? 'Private Subnet' : 'Public Origin'}
                    </span>
                  </div>
                  <div className="webcare-telemetry-card-main webcare-ip-row" style={{ flexWrap: 'wrap' }}>
                    <code>{telemetry.real_server_ipv4 || telemetry.real_server_ip}</code>
                    <button
                      type="button"
                      className="webcare-telemetry-copy-btn"
                      title="Copy Server IPv4"
                      onClick={() => copyToClipboard(telemetry.real_server_ipv4 || telemetry.real_server_ip, 'server_ip')}
                    >
                      {copiedIp === 'server_ip' ? <Check size={13} color="#16a34a" /> : <Copy size={13} />}
                    </button>
                    {telemetry.real_server_ipv6 && (
                      <div className="webcare-ip-row" style={{ width: '100%', marginTop: '4px' }}>
                        <code style={{ fontSize: '11.5px', color: '#0284c7' }} title="Server Origin IPv6">
                          {telemetry.real_server_ipv6}
                        </code>
                        <button
                          type="button"
                          className="webcare-telemetry-copy-btn"
                          title="Copy Server IPv6"
                          onClick={() => copyToClipboard(telemetry.real_server_ipv6, 'server_ipv6')}
                        >
                          {copiedIp === 'server_ipv6' ? <Check size={13} color="#16a34a" /> : <Copy size={13} />}
                        </button>
                      </div>
                    )}
                  </div>
                  <div className="webcare-telemetry-card-sub">
                    Direct origin host address {telemetry.is_server_ip_private ? '(Internal NAT/Docker)' : '(Direct Server Binding)'}
                  </div>
                </div>

                {/* Card 5: Website CDN IP */}
                <div className="webcare-telemetry-card">
                  <div className="webcare-telemetry-card-top">
                    <div className="webcare-telemetry-card-label">
                      <Cloud size={14} className="webcare-telemetry-card-icon" />
                      Website CDN IP
                    </div>
                    <span className={`webcare-telemetry-badge ${telemetry.cdn_available ? 'webcare-badge-success' : 'webcare-badge-neutral'}`}>
                      {telemetry.cdn_provider}
                    </span>
                  </div>
                  <div className="webcare-telemetry-card-main webcare-ip-row" style={{ flexWrap: 'wrap' }}>
                    <code>{telemetry.cdn_ipv4 || telemetry.cdn_ip}</code>
                    {telemetry.cdn_available && !['Direct Connection', 'Local Dev (No CDN)', 'N/A'].includes(telemetry.cdn_ipv4 || telemetry.cdn_ip) && (
                      <button
                        type="button"
                        className="webcare-telemetry-copy-btn"
                        title="Copy CDN Edge IPv4"
                        onClick={() => copyToClipboard(telemetry.cdn_ipv4 || telemetry.cdn_ip, 'cdn_ip')}
                      >
                        {copiedIp === 'cdn_ip' ? <Check size={13} color="#16a34a" /> : <Copy size={13} />}
                      </button>
                    )}
                    {telemetry.cdn_ipv6 && (
                      <div className="webcare-ip-row" style={{ width: '100%', marginTop: '4px' }}>
                        <code style={{ fontSize: '11.5px', color: '#0284c7' }} title="CDN Edge IPv6">
                          {telemetry.cdn_ipv6}
                        </code>
                        <button
                          type="button"
                          className="webcare-telemetry-copy-btn"
                          title="Copy CDN Edge IPv6"
                          onClick={() => copyToClipboard(telemetry.cdn_ipv6, 'cdn_ipv6')}
                        >
                          {copiedIp === 'cdn_ipv6' ? <Check size={13} color="#16a34a" /> : <Copy size={13} />}
                        </button>
                      </div>
                    )}
                  </div>
                  <div className="webcare-telemetry-card-sub">
                    {telemetry.cdn_available
                      ? 'Traffic safely routed through Edge Anycast Proxy'
                      : telemetry.cdn_ip === 'Local Dev (No CDN)'
                      ? 'Local development environment (No edge proxy)'
                      : 'Direct origin connection without edge proxy'}
                  </div>
                </div>
              </div>

              {/* Collapsible Developer Diagnostics Drawer */}
              {showDevTelemetry && (
                <div className="webcare-telemetry-dev-drawer">
                  <div className="webcare-telemetry-dev-drawer-title">
                    <Terminal size={15} />
                    <span>Developer Environment &amp; Process Diagnostics</span>
                  </div>
                  <div className="webcare-telemetry-dev-grid">
                    <div className="webcare-telemetry-dev-item">
                      <span className="webcare-telemetry-dev-label">Hosting Environment:</span>
                      <span className="webcare-telemetry-dev-val"><code>{telemetry.hosting_env_label || 'Web Hosting'}</code></span>
                    </div>
                    <div className="webcare-telemetry-dev-item">
                      <span className="webcare-telemetry-dev-label">Full Kernel Uname:</span>
                      <span className="webcare-telemetry-dev-val"><code>{telemetry.linux_uname_full}</code></span>
                    </div>
                    <div className="webcare-telemetry-dev-item">
                      <span className="webcare-telemetry-dev-label">Process User (POSIX):</span>
                      <span className="webcare-telemetry-dev-val"><code>{telemetry.php_user}</code></span>
                    </div>
                    <div className="webcare-telemetry-dev-item">
                      <span className="webcare-telemetry-dev-label">Max Execution Time:</span>
                      <span className="webcare-telemetry-dev-val"><code>{telemetry.max_execution_time}</code></span>
                    </div>
                    <div className="webcare-telemetry-dev-item">
                      <span className="webcare-telemetry-dev-label">Upload / Post Limits:</span>
                      <span className="webcare-telemetry-dev-val"><code>{telemetry.upload_max_filesize} upload / {telemetry.post_max_size} post</code></span>
                    </div>
                    <div className="webcare-telemetry-dev-item">
                      <span className="webcare-telemetry-dev-label">Firewall Hook Mode:</span>
                      <span className="webcare-telemetry-dev-val"><code>{telemetry.waf_hook_mode}</code></span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* =========================================================================
              SECTION 2: COEXISTENCE & CLOUD INTELLIGENCE NOTIFICATION STRIP
              ========================================================================= */}
          <div className="webcare-firewall-arch-strip">
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <ShieldCheck size={20} color={environment?.has_coexisting_waf ? '#16a34a' : '#0284c7'} />
              <div style={{ fontSize: '13px' }}>
                <strong>Active Shield Architecture:</strong>{' '}
                {environment?.has_cloudflare && (
                  <span style={{ background: '#fef3c7', color: '#92400e', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600, marginRight: '6px' }}>
                    Cloudflare Edge Connected
                  </span>
                )}
                {environment?.has_wordfence && (
                  <span style={{ background: '#dbeafe', color: '#1e40af', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600, marginRight: '6px' }}>
                    Wordfence Active (Complementary Mode Engaged)
                  </span>
                )}
                {environment?.has_sucuri && (
                  <span style={{ background: '#ede9fe', color: '#5b21b6', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600, marginRight: '6px' }}>
                    Sucuri WAF Coexisting
                  </span>
                )}
                {!environment?.has_coexisting_waf && (
                  <span style={{ color: '#0369a1', fontWeight: 600 }}>
                    WebCare WAF Lite operating as Primary Application Gatekeeper.
                  </span>
                )}
              </div>
            </div>

            <div style={{ fontSize: '12px' }}>
              Detected Real Client IP: <code style={{ fontWeight: 600 }}>{fwStatus?.client_ip || '127.0.0.1'}</code>
            </div>
          </div>

          {/* =========================================================================
              SECTION 3: SYSADMIN EDGE OFFLOAD & HOSTING RESOURCE OPTIMIZATION ADVISORY
              ========================================================================= */}
          {edgeAdvisor && (
            <div className={`webcare-firewall-edge-banner ${edgeAdvisor.has_cloudflare ? 'is-proxied' : 'is-shared'}`}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px', maxWidth: '840px' }}>
                <div
                  style={{
                    width: '42px',
                    height: '42px',
                    borderRadius: '10px',
                    background: edgeAdvisor.has_cloudflare ? '#16a34a' : '#ea580c',
                    color: '#fff',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                    marginTop: '2px',
                    boxShadow: edgeAdvisor.has_cloudflare
                      ? '0 2px 8px rgba(22, 163, 74, 0.25)'
                      : '0 2px 8px rgba(234, 88, 12, 0.25)',
                  }}
                >
                  <Cloud size={24} />
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <strong className={`webcare-firewall-edge-title ${edgeAdvisor.has_cloudflare ? 'is-proxied' : 'is-shared'}`}>
                      {edgeAdvisor.has_cloudflare
                        ? (isApiConnected ? 'Cloudflare Anycast Edge Shield & API: Active' : 'Cloudflare Anycast Edge Shield: Active (DNS Proxied)')
                        : 'Origin Resource Shield: Offload Perimeter Defense to Cloudflare Free Edge'}
                    </strong>
                    <span
                      style={{
                        fontSize: '11px',
                        fontWeight: 700,
                        textTransform: 'uppercase',
                        padding: '2px 8px',
                        borderRadius: '999px',
                        background: edgeAdvisor.has_cloudflare ? '#dcfce7' : '#ffedd5',
                        color: edgeAdvisor.has_cloudflare ? '#15803d' : '#c2410c',
                        border: edgeAdvisor.has_cloudflare ? '1px solid #86efac' : '1px solid #fdba74',
                      }}
                    >
                      {edgeAdvisor.has_cloudflare ? 'Edge Proxied' : 'Recommended Architecture'}
                    </span>
                    {isApiConnected ? (
                      <span
                        style={{
                          fontSize: '11px',
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          padding: '2px 8px',
                          borderRadius: '999px',
                          background: '#ecfdf5',
                          color: '#047857',
                          border: '1px solid #a7f3d0',
                        }}
                      >
                        ✓ API Connected ({activePlan} Plan)
                      </span>
                    ) : apiError ? (
                      <span
                        style={{
                          fontSize: '11px',
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          padding: '2px 8px',
                          borderRadius: '999px',
                          background: '#fef2f2',
                          color: '#dc2626',
                          border: '1px solid #fecaca',
                        }}
                        title={apiError}
                      >
                        ⚠️ API Verification Failed
                      </span>
                    ) : (
                      <span
                        style={{
                          fontSize: '11px',
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          padding: '2px 8px',
                          borderRadius: '999px',
                          background: '#fff7ed',
                          color: '#c2410c',
                          border: '1px solid #fed7aa',
                        }}
                      >
                        API Not Connected
                      </span>
                    )}
                  </div>
                  <p className="webcare-firewall-edge-desc">
                    {isApiConnected
                      ? `Cloudflare API is connected to ${activeZone ? `Zone: ${activeZone}` : 'your zone'} (${activePlan} Plan). 1-Click Edge Rulesets, Rate Limiting, IP auto-bans, and Cache Purging are ready to manage.`
                      : apiError
                        ? `Cloudflare credentials are saved, but API connection could not be verified: "${apiError}". Please check your API Token and Zone ID in Settings.`
                        : (edgeAdvisor.has_cloudflare
                          ? 'Your site traffic is routed through Cloudflare DNS proxy (Orange Cloud). Connect your Cloudflare API Token to enable 1-Click Edge WAF rulesets, Rate Limiting, and automated IP ban sync.'
                          : `Detected Web Server: ${edgeAdvisor.server_software}. Executing PHP-FPM workers for high-volume exploit scanners and automated bot floods consumes valuable server CPU, memory, and database connections. Offloading perimeter inspection to Cloudflare Free Edge drops hostile traffic globally before it reaches your server, preserving 100% of your origin resources and PHP workers for real visitors and customers.`
                        )}
                  </p>
                  <div style={{ marginTop: '5px', fontSize: '11px', opacity: 0.85 }}>
                    💡 <em>Senior Linux SysAdmin Advisory (Mir Alamin, WebCare Pro):</em> Cloudflare Free Edge terminates volumetric bots and crawler noise at the network boundary with 0ms origin overhead, keeping your server's PHP-FPM workers and MySQL connections 100% free to serve legitimate visitors, customers, and checkout requests.
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                {isApiConnected ? (
                  <>
                    <button
                      type="button"
                      className="webcare-btn"
                      onClick={() => onNavigateToFirewall ? onNavigateToFirewall('cloudflare') : (window.location.href = 'admin.php?page=webcare-pro-firewall&tab=cloudflare')}
                      style={{
                        background: '#15803d',
                        color: '#fff',
                        border: 'none',
                        padding: '8px 16px',
                        borderRadius: '8px',
                        fontWeight: 600,
                        fontSize: '13px',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        cursor: 'pointer',
                        boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      <Cloud size={14} />
                      View Edge WAF Rules &amp; Slots
                    </button>
                    <button
                      type="button"
                      className="webcare-btn"
                      onClick={() => onNavigateToSettings ? onNavigateToSettings('cloudflare') : (window.location.href = 'admin.php?page=webcare-pro-settings&tab=cloudflare')}
                      style={{
                        background: '#fff',
                        color: '#475569',
                        border: '1px solid #cbd5e1',
                        padding: '8px 14px',
                        borderRadius: '8px',
                        fontWeight: 600,
                        fontSize: '12px',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '5px',
                        cursor: 'pointer',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      <Key size={13} /> Manage API Settings ↗
                    </button>
                  </>
                ) : (
                  <button
                    type="button"
                    className="webcare-btn"
                    onClick={() => onNavigateToSettings ? onNavigateToSettings('cloudflare') : (window.location.href = 'admin.php?page=webcare-pro-settings&tab=cloudflare')}
                    style={{
                      background: 'linear-gradient(135deg, #f97316 0%, #ea580c 100%)',
                      color: '#fff',
                      border: 'none',
                      padding: '8px 18px',
                      borderRadius: '8px',
                      fontWeight: 600,
                      fontSize: '13px',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px',
                      cursor: 'pointer',
                      boxShadow: '0 2px 6px rgba(234, 88, 12, 0.3)',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    <Cloud size={14} />
                    Connect Cloudflare API in Settings ↗
                  </button>
                )}
              </div>
            </div>
          )}

          {/* =========================================================================
              SECTION 4: TECHNICAL ENVIRONMENT AUDITS & DEEP STORAGE INVENTORY
              ========================================================================= */}
          {serverInfo && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '20px' }}>
              {/* PHP Configuration Card */}
              <div className="webcare-server-card">
                <div className="webcare-server-card-header">
                  <h3 className="webcare-server-card-title">
                    <Server size={18} color="#0284c7" /> PHP Runtime &amp; Configuration
                  </h3>
                  <span className="webcare-badge webcare-server-badge-cyan">
                    v{serverInfo.php.version}
                  </span>
                </div>
                <div style={{ padding: '20px' }}>
                  <div className="webcare-server-info-row">
                    <span>PHP SAPI Interface:</span>
                    <strong>{serverInfo.php.sapi}</strong>
                  </div>
                  <div className="webcare-server-info-row">
                    <span>Memory Limit (php.ini):</span>
                    <strong>{serverInfo.php.memory_limit}</strong>
                  </div>
                  <div className="webcare-server-info-row">
                    <span>Current Memory Usage:</span>
                    <strong>{serverInfo.php.memory_usage_mb} MB</strong>
                  </div>
                  <div className="webcare-server-info-row">
                    <span>Max Execution Time:</span>
                    <strong>{serverInfo.php.max_execution_time}s</strong>
                  </div>
                  <div className="webcare-server-info-row">
                    <span>Upload Max Filesize:</span>
                    <strong>{serverInfo.php.upload_max_filesize}</strong>
                  </div>
                  <div className="webcare-server-info-row">
                    <span>Post Max Size:</span>
                    <strong>{serverInfo.php.post_max_size}</strong>
                  </div>
                  <div className="webcare-server-info-row">
                    <span>Display Errors:</span>
                    <strong style={{ color: serverInfo.php.display_errors === 'On' ? '#ef4444' : '#10b981' }}>
                      {serverInfo.php.display_errors}
                    </strong>
                  </div>
                </div>
              </div>

              {/* Database Server Card */}
              <div className="webcare-server-card">
                <div className="webcare-server-card-header">
                  <h3 className="webcare-server-card-title">
                    <Database size={18} color="#0284c7" /> Database Server Engine
                  </h3>
                  <span className="webcare-badge webcare-server-badge-cyan">
                    MySQL v{serverInfo.database.version}
                  </span>
                </div>
                <div style={{ padding: '20px' }}>
                  <div className="webcare-server-info-row">
                    <span>Database Host:</span>
                    <strong>{serverInfo.database.host}</strong>
                  </div>
                  <div className="webcare-server-info-row">
                    <span>Database Name:</span>
                    <strong>{serverInfo.database.name}</strong>
                  </div>
                  <div className="webcare-server-info-row">
                    <span>Table Prefix:</span>
                    <code>{serverInfo.database.table_prefix}</code>
                  </div>
                  <div className="webcare-server-info-row">
                    <span>Charset &amp; Collate:</span>
                    <strong>{serverInfo.database.charset} ({serverInfo.database.collate})</strong>
                  </div>
                  <div className="webcare-server-info-row">
                    <span>Total Database Size:</span>
                    <strong style={{ color: '#0284c7' }}>{serverInfo.database.size_mb} MB</strong>
                  </div>
                </div>
              </div>

              {/* Web Server & OS Card */}
              <div className="webcare-server-card">
                <div className="webcare-server-card-header">
                  <h3 className="webcare-server-card-title">
                    <HardDrive size={18} color="#0284c7" /> Web Server &amp; Host Specs
                  </h3>
                </div>
                <div style={{ padding: '20px' }}>
                  <div className="webcare-server-info-row">
                    <span>Server Software:</span>
                    <strong>{serverInfo.server.software}</strong>
                  </div>
                  <div className="webcare-server-info-row">
                    <span>Operating System:</span>
                    <strong>{serverInfo.server.os}</strong>
                  </div>
                  <div className="webcare-server-info-row">
                    <span>Server Architecture:</span>
                    <strong>{serverInfo.server.arch}</strong>
                  </div>
                  <div className="webcare-server-info-row">
                    <span>Server IP Address:</span>
                    <strong>{serverInfo.server.ip || (serverInfo.server as any).server_ip || 'Unavailable'}</strong>
                  </div>
                  <div className="webcare-server-info-row">
                    <span>WordPress Version:</span>
                    <strong>v{serverInfo.wordpress.version}</strong>
                  </div>
                  <div className="webcare-server-info-row">
                    <span>SSL Active:</span>
                    <strong style={{ color: (serverInfo.wordpress.ssl || (serverInfo.wordpress as any).ssl_active) ? '#10b981' : '#ef4444' }}>
                      {(serverInfo.wordpress.ssl || (serverInfo.wordpress as any).ssl_active) ? 'Yes (HTTPS Active)' : 'No (Insecure HTTP)'}
                    </strong>
                  </div>
                </div>
              </div>

              {/* File Permissions Security Card */}
              <div className="webcare-server-card">
                <div className="webcare-server-card-header">
                  <h3 className="webcare-server-card-title">
                    <Lock size={18} color="#0284c7" /> Critical File Permissions
                  </h3>
                </div>
                <div style={{ padding: '20px' }}>
                  {Object.entries(serverInfo.permissions).map(([path, perm]) => (
                    <div key={path} className="webcare-server-info-row">
                      <span><code>{path}</code>:</span>
                      <div>
                        <strong style={{ fontFamily: 'monospace', marginRight: '8px' }}>{perm as string}</strong>
                        {perm === '0777' ? (
                          <span className="webcare-badge webcare-badge-critical">Insecure 0777</span>
                        ) : perm === '0644' || perm === '0755' ? (
                          <span className="webcare-badge webcare-server-badge-green">Secure</span>
                        ) : (
                          <span className="webcare-badge webcare-badge-low">Permitted</span>
                        )}
                      </div>
                    </div>
                  ))}
                  <div style={{ marginTop: '16px', fontSize: '12px', color: '#94a3b8' }}>
                    Tip: Core files such as <code>wp-config.php</code> should ideally have permissions <code>0640</code> or <code>0644</code>. Directory permissions should not exceed <code>0755</code>.
                  </div>
                </div>
              </div>

              {/* Security PHP Extensions Card */}
              <div className="webcare-server-card" style={{ gridColumn: '1 / -1' }}>
                <div className="webcare-server-card-header">
                  <h3 className="webcare-server-card-title">
                    <ShieldCheck size={18} color="#0284c7" /> Critical PHP Security &amp; Cryptographic Extensions
                  </h3>
                </div>
                <div style={{ padding: '20px' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px' }}>
                    {Object.entries(serverInfo.php.extensions).map(([ext, enabled]) => (
                      <div
                        key={ext}
                        className="webcare-server-tile"
                      >
                        <span style={{ fontWeight: 600, fontSize: '13px' }}>{ext}</span>
                        {enabled ? (
                          <span className="webcare-badge webcare-server-badge-green">
                            Enabled
                          </span>
                        ) : (
                          <span className="webcare-badge webcare-badge-high">
                            Missing
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Filesystem & Directory Storage Breakdown Card */}
              {serverInfo.filesystem && (
                <div className="webcare-server-card" style={{ gridColumn: '1 / -1' }}>
                  <div className="webcare-server-card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <h3 className="webcare-server-card-title">
                      <Folder size={18} color="#0284c7" /> Filesystem &amp; Directory Storage Breakdown
                    </h3>
                  </div>
                  <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
                    {/* Section 1: Main WP Folders Storage */}
                    <div>
                      <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '12px' }}>
                        WordPress Core Storage Distribution
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
                        {/* Core WP Size */}
                        <div className="webcare-server-storage-box">
                          <div className="webcare-server-storage-title" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <HardDrive size={14} color="#0284c7" /> WordPress Core
                          </div>
                          <div className="webcare-server-storage-box-val">
                            {serverInfo.filesystem.core_size_mb} <span className="webcare-server-storage-unit">MB</span>
                          </div>
                          <div className="webcare-server-storage-desc">wp-admin, wp-includes &amp; root files</div>
                        </div>

                        {/* wp-content/plugins */}
                        <div className="webcare-server-storage-box">
                          <div className="webcare-server-storage-title" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <Package size={14} color="#d97706" /> wp-content/plugins
                          </div>
                          <div className="webcare-server-storage-box-val">
                            {serverInfo.filesystem.plugins_size_mb} <span className="webcare-server-storage-unit">MB</span>
                          </div>
                          <div className="webcare-server-storage-desc">Installed Plugin Extensions</div>
                        </div>

                        {/* wp-content/themes */}
                        <div className="webcare-server-storage-box">
                          <div className="webcare-server-storage-title" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <Layers size={14} color="#8b5cf6" /> wp-content/themes
                          </div>
                          <div className="webcare-server-storage-box-val">
                            {serverInfo.filesystem.themes_size_mb} <span className="webcare-server-storage-unit">MB</span>
                          </div>
                          <div className="webcare-server-storage-desc">Active &amp; Inactive Site Themes</div>
                        </div>

                        {/* wp-content/uploads */}
                        <div className="webcare-server-storage-box">
                          <div className="webcare-server-storage-title" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <Archive size={14} color="#ec4899" /> wp-content/uploads
                          </div>
                          <div className="webcare-server-storage-box-val">
                            {serverInfo.filesystem.uploads_size_mb} <span className="webcare-server-storage-unit">MB</span>
                          </div>
                          <div className="webcare-server-storage-desc">Media Library &amp; Uploaded Files</div>
                        </div>
                      </div>
                    </div>

                    {/* Section 2: File Count by Extension */}
                    <div style={{ borderTop: '1px solid var(--webcare-border)', paddingTop: '16px' }}>
                      <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <FileCode size={15} color="#64748b" /> File Inventory by Extension
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px', marginBottom: '16px' }}>
                        {/* PHP */}
                        <div className="webcare-server-ext-box webcare-server-ext-box-php">
                          <div>
                            <div className="webcare-server-ext-box-label">Total PHP Files (.php)</div>
                            <div className="webcare-server-ext-box-value">
                              {serverInfo.filesystem.php_files.toLocaleString()}
                            </div>
                          </div>
                          <span className="webcare-server-ext-box-tag">
                            PHP
                          </span>
                        </div>

                        {/* JS */}
                        <div className="webcare-server-ext-box webcare-server-ext-box-js">
                          <div>
                            <div className="webcare-server-ext-box-label">Total JavaScript Files (.js)</div>
                            <div className="webcare-server-ext-box-value">
                              {serverInfo.filesystem.js_files.toLocaleString()}
                            </div>
                          </div>
                          <span className="webcare-server-ext-box-tag">
                            JS
                          </span>
                        </div>

                        {/* CSS */}
                        <div className="webcare-server-ext-box webcare-server-ext-box-css">
                          <div>
                            <div className="webcare-server-ext-box-label">Total Stylesheets (.css)</div>
                            <div className="webcare-server-ext-box-value">
                              {serverInfo.filesystem.css_files.toLocaleString()}
                            </div>
                          </div>
                          <span className="webcare-server-ext-box-tag">
                            CSS
                          </span>
                        </div>
                      </div>

                      {/* All Other Extensions */}
                      {serverInfo.filesystem.extension_counts && (
                        <div className="webcare-server-storage-box" style={{ padding: '16px' }}>
                          <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-muted)', marginBottom: '10px' }}>
                            All Other File Extensions Found on Website:
                          </div>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', maxHeight: '180px', overflowY: 'auto', paddingRight: '4px' }}>
                            {Object.entries(serverInfo.filesystem.extension_counts)
                              .filter(([ext]) => !['php', 'js', 'css'].includes(ext))
                              .map(([ext, count]) => (
                                <div
                                  key={ext}
                                  className="webcare-server-ext-pill"
                                >
                                  <span style={{ fontWeight: 700, color: 'var(--webcare-text-primary)' }}>.{ext}</span>
                                  <span className="webcare-server-ext-count">
                                    {(count as number).toLocaleString()}
                                  </span>
                                </div>
                              ))}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Total Files Summary Banner */}
                    <div className="webcare-server-summary-banner" style={{
                      borderRadius: '10px',
                      padding: '16px 20px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      flexWrap: 'wrap',
                      gap: '12px'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <div style={{ background: 'rgba(255, 255, 255, 0.1)', padding: '10px', borderRadius: '10px' }}>
                          <HardDrive size={22} color="#38bdf8" />
                        </div>
                        <div>
                          <div style={{ fontSize: '14px', fontWeight: 600, color: '#f1f5f9' }}>
                            Total Files Found Across Website
                          </div>
                          <div style={{ fontSize: '12px', color: '#94a3b8' }}>
                            Total file count indexed from the WordPress web root installation
                          </div>
                        </div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
                        <span style={{ fontSize: '28px', fontWeight: 800, color: '#38bdf8' }}>
                          {serverInfo.filesystem.total_files.toLocaleString()}
                        </span>
                        <span style={{ fontSize: '14px', color: '#cbd5e1', fontWeight: 500 }}>Total Files</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default ServerTelemetryPage;
