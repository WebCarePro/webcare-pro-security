import React, { useState } from '@wordpress/element';
import {
  Server,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  Database,
  Cpu,
  Globe,
  HardDrive,
  Shield,
  Layers,
  HelpCircle,
  RefreshCw,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  Sparkles,
  CheckCircle,
  XCircle,
  Loader2
} from 'lucide-react';
import { DeveloperDeepDive } from '../DeveloperDeepDive';

interface Step02Props {
  status: any;
  trustedProxyIps: string[];
  setTrustedProxyIps: (ips: string[]) => void;
  onRefreshStatus?: () => Promise<void>;
}

export const Step02RuntimeTelemetry: React.FC<Step02Props> = ({
  status,
  trustedProxyIps,
  setTrustedProxyIps,
  onRefreshStatus,
}) => {
  const [rechecking, setRechecking] = useState(false);
  const [copiedTab, setCopiedTab] = useState<string | null>(null);
  const [remediationTab, setRemediationTab] = useState<'apt' | 'dnf' | 'cpanel' | 'plesk'>('apt');
  const [isRemediationOpen, setIsRemediationOpen] = useState(false);

  const serverInfo = status?.server_info || {};
  const phpInfo = serverInfo.php || {};
  const dbInfo = serverInfo.database || {};
  const gate = status?.php_extension_gate || {};
  const extensions: any[] = gate.extensions || [];
  const commands = gate.commands || {};

  const criticalExts = extensions.filter((e) => e.tier === 'critical');
  const recommendedExts = extensions.filter((e) => e.tier === 'recommended');
  const runtimeExts = extensions.filter((e) => e.tier === 'runtime');

  const allCriticalMet = gate.all_critical_met !== false;
  const missingCritical: string[] = gate.missing_critical || [];
  const missingRecommended: string[] = gate.missing_recommended || [];

  const handleRecheck = async () => {
    if (!onRefreshStatus) return;
    setRechecking(true);
    try {
      await onRefreshStatus();
    } finally {
      setTimeout(() => setRechecking(false), 500);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedTab(id);
    setTimeout(() => setCopiedTab(null), 2000);
  };

  const handleProxyIpsChange = (val: string) => {
    const list = val.split('\n').map((s) => s.trim()).filter(Boolean);
    setTrustedProxyIps(list);
  };

  return (
    <div className="webcare-wizard-step-container" style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
      {/* Step Header */}
      <div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '4px 10px', borderRadius: '20px', background: 'rgba(2, 132, 199, 0.1)', color: '#0284c7', fontSize: '12px', fontWeight: 700, marginBottom: '12px' }}>
          <Server size={14} /> Phase 1: Environment Telemetry &amp; Foundation
        </div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <h1 style={{ margin: 0, fontSize: '24px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
            Server &amp; PHP Extension Requirement Gate
          </h1>
          {onRefreshStatus && (
            <button
              type="button"
              onClick={handleRecheck}
              disabled={rechecking}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '8px 14px',
                borderRadius: '8px',
                fontSize: '12px',
                fontWeight: 700,
                cursor: rechecking ? 'not-allowed' : 'pointer',
                background: 'var(--webcare-bg-elevated, #f8fafc)',
                border: '1px solid var(--webcare-border, #cbd5e1)',
                color: 'var(--webcare-text-title, #0f172a)',
                boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
              }}
            >
              <RefreshCw size={14} className={rechecking ? 'webcare-spin' : ''} />
              {rechecking ? 'Re-Checking...' : 'Re-Check Server Requirements'}
            </button>
          )}
        </div>
        <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--webcare-text-secondary, #475569)', margin: '8px 0 0 0' }}>
          Validates your server's PHP extensions, cryptographic engines, memory envelope, and runtime limits to guarantee 100% stable pre-boot WAF and behavioral analysis execution.
        </p>
      </div>

      {/* Critical Gate Status Banner */}
      <div
        style={{
          padding: '16px 20px',
          borderRadius: '12px',
          background: allCriticalMet ? 'rgba(16, 185, 129, 0.08)' : 'rgba(239, 68, 68, 0.08)',
          border: `1px solid ${allCriticalMet ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {allCriticalMet ? (
            <CheckCircle size={22} color="#059669" />
          ) : (
            <XCircle size={22} color="#dc2626" />
          )}
          <div>
            <div style={{ fontSize: '14px', fontWeight: 800, color: allCriticalMet ? '#059669' : '#dc2626' }}>
              {allCriticalMet ? 'All Critical PHP Extensions & Dependencies Verified' : 'Critical PHP Extensions Missing'}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
              {allCriticalMet
                ? 'Your hosting environment is fully equipped for Pre-Boot Micro-WAF, AST Behavioral Analysis, and AEAD encryption.'
                : `Missing: ${missingCritical.join(', ')}. Please install or enable them using the remediation guide below.`}
            </div>
          </div>
        </div>

        {(!allCriticalMet || missingRecommended.length > 0) && (
          <button
            type="button"
            onClick={() => setIsRemediationOpen(!isRemediationOpen)}
            style={{
              padding: '6px 12px',
              borderRadius: '6px',
              fontSize: '11px',
              fontWeight: 700,
              cursor: 'pointer',
              background: '#ffffff',
              border: '1px solid #cbd5e1',
              color: 'var(--webcare-text-title, #0f172a)',
            }}
          >
            {isRemediationOpen ? 'Hide Remediation Commands' : 'View Fix Commands (apt / dnf / cPanel)'}
          </button>
        )}
      </div>

      {/* Host Specs Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px' }}>
        <div style={{ padding: '14px', borderRadius: '10px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
          <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', fontWeight: 600 }}>PHP Runtime &amp; SAPI</div>
          <div style={{ fontSize: '14px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)', marginTop: '4px' }}>
            PHP {gate.php_version || phpInfo.version || '8.x'} ({phpInfo.sapi || 'FPM/FastCGI'})
          </div>
        </div>

        <div style={{ padding: '14px', borderRadius: '10px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
          <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', fontWeight: 600 }}>Memory Limit</div>
          <div style={{ fontSize: '14px', fontWeight: 800, color: gate.is_memory_sufficient ? 'var(--webcare-text-title, #0f172a)' : '#d97706', marginTop: '4px' }}>
            {gate.memory_limit || phpInfo.memory_limit || '256M'} {gate.is_memory_sufficient ? '✓' : '(Recommended ≥ 128M)'}
          </div>
        </div>

        <div style={{ padding: '14px', borderRadius: '10px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
          <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', fontWeight: 600 }}>Database Engine</div>
          <div style={{ fontSize: '14px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)', marginTop: '4px' }}>
            {dbInfo.server_type || 'MySQL'} {dbInfo.version || '8.0'}
          </div>
        </div>

        <div style={{ padding: '14px', borderRadius: '10px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
          <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', fontWeight: 600 }}>Web Server &amp; Uploads</div>
          <div style={{ fontSize: '14px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)', marginTop: '4px' }}>
            {serverInfo.server_software ? serverInfo.server_software.split(' ')[0] : 'LiteSpeed / Nginx / Apache'} {gate.upload_dir_writable ? '(Writable ✓)' : ''}
          </div>
        </div>
      </div>

      {/* Interactive Missing Extension Remediation Drawer */}
      {isRemediationOpen && (
        <div
          style={{
            padding: '20px',
            borderRadius: '12px',
            background: 'var(--webcare-bg-elevated, #f8fafc)',
            border: '1px solid var(--webcare-border, #cbd5e1)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
            <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
              Stack-Aware Server Extension Remediation
            </div>
            <div style={{ display: 'flex', gap: '6px' }}>
              {(['apt', 'dnf', 'cpanel', 'plesk'] as const).map((tab) => (
                <button
                  key={tab}
                  type="button"
                  onClick={() => setRemediationTab(tab)}
                  style={{
                    padding: '4px 10px',
                    borderRadius: '6px',
                    fontSize: '11px',
                    fontWeight: 700,
                    cursor: 'pointer',
                    background: remediationTab === tab ? 'var(--webcare-primary, #4f46e5)' : '#ffffff',
                    color: remediationTab === tab ? '#ffffff' : 'var(--webcare-text-secondary, #475569)',
                    border: '1px solid var(--webcare-border, #cbd5e1)',
                  }}
                >
                  {tab === 'apt' ? 'Ubuntu / Debian (apt)' : tab === 'dnf' ? 'RHEL / AlmaLinux (dnf)' : tab === 'cpanel' ? 'cPanel / WHM' : 'Plesk'}
                </button>
              ))}
            </div>
          </div>

          {remediationTab === 'apt' && (
            <div>
              <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginBottom: '8px' }}>
                Run this command via SSH / Terminal as root to install all required PHP modules:
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: '#0f172a', padding: '10px 14px', borderRadius: '8px' }}>
                <code style={{ flex: 1, color: '#38bdf8', fontSize: '12px', fontFamily: 'monospace', overflowX: 'auto' }}>
                  {commands.apt || 'sudo apt update && sudo apt install -y php-mbstring php-curl php-zip && sudo systemctl restart php-fpm'}
                </code>
                <button
                  type="button"
                  onClick={() => copyToClipboard(commands.apt || '', 'apt')}
                  style={{
                    background: 'rgba(255,255,255,0.1)',
                    border: 'none',
                    color: '#ffffff',
                    padding: '6px',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                  }}
                >
                  {copiedTab === 'apt' ? <Check size={14} color="#34d399" /> : <Copy size={14} />}
                </button>
              </div>
            </div>
          )}

          {remediationTab === 'dnf' && (
            <div>
              <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginBottom: '8px' }}>
                Run this command on AlmaLinux / Rocky / CentOS / Fedora:
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: '#0f172a', padding: '10px 14px', borderRadius: '8px' }}>
                <code style={{ flex: 1, color: '#38bdf8', fontSize: '12px', fontFamily: 'monospace', overflowX: 'auto' }}>
                  {commands.dnf || 'sudo dnf install -y php-mbstring php-curl php-zip && sudo systemctl restart php-fpm'}
                </code>
                <button
                  type="button"
                  onClick={() => copyToClipboard(commands.dnf || '', 'dnf')}
                  style={{
                    background: 'rgba(255,255,255,0.1)',
                    border: 'none',
                    color: '#ffffff',
                    padding: '6px',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                  }}
                >
                  {copiedTab === 'dnf' ? <Check size={14} color="#34d399" /> : <Copy size={14} />}
                </button>
              </div>
            </div>
          )}

          {(remediationTab === 'cpanel' || remediationTab === 'plesk') && (
            <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.6 }}>
              In your control panel, navigate to:
              <div style={{ padding: '10px 14px', background: 'var(--webcare-bg-panel, #ffffff)', borderRadius: '8px', border: '1px solid var(--webcare-border, #cbd5e1)', marginTop: '6px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                {commands[remediationTab] || 'Software → Select PHP Version → Extensions'}
              </div>
              <div style={{ marginTop: '8px' }}>
                Tick the missing modules (e.g. <code>mbstring</code>, <code>curl</code>, <code>zip</code>, <code>sodium</code>, <code>intl</code>), click Save, and click <strong>"Re-Check Server Requirements"</strong> above.
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tier 1: Critical Required Extensions */}
      <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
          <div style={{ fontSize: '13px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
            Tier 1: Critical Required Extensions (Hard Requirement)
          </div>
          <span style={{ fontSize: '11px', fontWeight: 700, color: allCriticalMet ? '#059669' : '#dc2626' }}>
            {criticalExts.filter((e) => e.loaded).length} / {criticalExts.length} Active
          </span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '10px' }}>
          {criticalExts.map((ext) => (
            <div
              key={ext.id}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '10px 12px',
                borderRadius: '8px',
                background: ext.loaded ? 'var(--webcare-bg-elevated, #f8fafc)' : 'rgba(239, 68, 68, 0.05)',
                border: ext.loaded ? '1px solid var(--webcare-border, #e2e8f0)' : '1px solid rgba(239, 68, 68, 0.25)',
              }}
            >
              {ext.loaded ? (
                <CheckCircle2 size={16} color="#059669" style={{ flexShrink: 0 }} />
              ) : (
                <AlertTriangle size={16} color="#dc2626" style={{ flexShrink: 0 }} />
              )}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                    {ext.name}
                  </span>
                  <span style={{ fontSize: '10px', fontWeight: 700, color: ext.loaded ? '#059669' : '#dc2626' }}>
                    {ext.loaded ? '✓ ENABLED' : 'MISSING'}
                  </span>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.3, marginTop: '2px' }}>
                  {ext.purpose}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Tier 2: High-Value Security & Cryptographic Extensions */}
      <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
          <div style={{ fontSize: '13px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
            Tier 2: High-Value Security &amp; Archive Extensions (Strongly Recommended)
          </div>
          <span style={{ fontSize: '11px', fontWeight: 700, color: '#059669' }}>
            {recommendedExts.filter((e) => e.loaded).length} / {recommendedExts.length} Active
          </span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '10px' }}>
          {recommendedExts.map((ext) => (
            <div
              key={ext.id}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '10px 12px',
                borderRadius: '8px',
                background: ext.loaded ? 'var(--webcare-bg-elevated, #f8fafc)' : 'rgba(245, 158, 11, 0.05)',
                border: ext.loaded ? '1px solid var(--webcare-border, #e2e8f0)' : '1px solid rgba(245, 158, 11, 0.25)',
              }}
            >
              {ext.loaded ? (
                <CheckCircle2 size={16} color="#059669" style={{ flexShrink: 0 }} />
              ) : (
                <AlertTriangle size={16} color="#d97706" style={{ flexShrink: 0 }} />
              )}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                    {ext.name}
                  </span>
                  <span style={{ fontSize: '10px', fontWeight: 700, color: ext.loaded ? '#059669' : '#d97706' }}>
                    {ext.loaded ? '✓ ENABLED' : 'RECOMMENDED'}
                  </span>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.3, marginTop: '2px' }}>
                  {ext.purpose}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Developer Deep Dive: Reverse Proxy & Trusted Proxy CIDRs */}
      <DeveloperDeepDive
        title="Developer Controls: Reverse Proxy & Trusted Proxy CIDRs"
        badge="SettingsManager::trusted_proxy_ips"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5 }}>
            When your WordPress site sits behind Cloudflare, AWS CloudFront, Fastly, or an Nginx/HAProxy reverse proxy, <code>REMOTE_ADDR</code> reveals only the load balancer's IP. To prevent IP spoofing, WebCare validates proxy headers only from authenticated CIDRs listed below.
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' }}>
            <div style={{ padding: '10px 12px', borderRadius: '8px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #cbd5e1)' }}>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>Direct Socket REMOTE_ADDR</div>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', fontFamily: 'monospace' }}>
                {status?.client_ip || '127.0.0.1'}
              </div>
            </div>

            <div style={{ padding: '10px 12px', borderRadius: '8px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #cbd5e1)' }}>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>Cloudflare Connecting IP</div>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', fontFamily: 'monospace' }}>
                {status?.cf_ray ? 'Active via Cloudflare Edge' : 'Direct Origin Connection'}
              </div>
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '6px' }}>
              Trusted Reverse Proxy CIDR Allowlist (One IP or CIDR per line):
            </label>
            <textarea
              rows={4}
              value={trustedProxyIps.join('\n')}
              onChange={(e) => handleProxyIpsChange(e.target.value)}
              placeholder="173.245.48.0/20&#10;103.21.244.0/22&#10;192.168.1.0/24"
              className="webcare-firewall-input"
              style={{
                width: '100%',
                padding: '10px',
                borderRadius: '8px',
                fontSize: '12px',
                fontFamily: 'monospace',
                boxSizing: 'border-box'
              }}
            />
            <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
              Cloudflare, CloudFront, and Fastly edge CIDRs are auto-whitelisted when edge proxying is enabled. Add your internal load balancer CIDRs above.
            </div>
          </div>
        </div>
      </DeveloperDeepDive>
    </div>
  );
};
