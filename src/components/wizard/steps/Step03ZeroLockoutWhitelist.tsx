import React, { useState } from 'react';
import {
  UserCheck,
  ShieldCheck,
  Plus,
  Trash2,
  Copy,
  Check,
  AlertCircle,
  Key,
  Terminal,
  LifeBuoy
} from 'lucide-react';

interface WhitelistEntry {
  ip: string;
  label: string;
  created_at?: string;
}

interface Step03Props {
  status: any;
  whitelistIp: boolean;
  setWhitelistIp: (val: boolean) => void;
  ipWhitelistEntries: WhitelistEntry[];
  setIpWhitelistEntries: (entries: WhitelistEntry[]) => void;
}

export const Step03ZeroLockoutWhitelist: React.FC<Step03Props> = ({
  status,
  whitelistIp,
  setWhitelistIp,
  ipWhitelistEntries,
  setIpWhitelistEntries,
}) => {
  const [newIp, setNewIp] = useState('');
  const [newLabel, setNewLabel] = useState('');
  const [copiedSnippet, setCopiedSnippet] = useState(false);
  const [ipError, setIpError] = useState('');

  const clientIp = status?.client_ip || '127.0.0.1';
  const supportCode = status?.support_code || '#WEBCARE-SAFE';

  const handleAddEntry = () => {
    setIpError('');
    const trimmedIp = newIp.trim();
    if (!trimmedIp) {
      setIpError('Please enter a valid IP address or CIDR range.');
      return;
    }

    // Basic format check
    const isIp = /^([0-9]{1,3}\.){3}[0-9]{1,3}$/.test(trimmedIp) || trimmedIp.includes(':');
    const isCidr = trimmedIp.includes('/');
    if (!isIp && !isCidr) {
      setIpError('Invalid IP or CIDR notation (e.g. 203.0.113.1 or 198.51.100.0/24).');
      return;
    }

    // Check duplicate
    if (ipWhitelistEntries.some((e) => e.ip === trimmedIp)) {
      setIpError('This IP or CIDR is already in your whitelist table.');
      return;
    }

    const entry: WhitelistEntry = {
      ip: trimmedIp,
      label: newLabel.trim() || 'Workstation / Office IP',
      created_at: new Date().toISOString().split('T')[0]
    };

    setIpWhitelistEntries([...ipWhitelistEntries, entry]);
    setNewIp('');
    setNewLabel('');
  };

  const handleRemoveEntry = (ipToRemove: string) => {
    setIpWhitelistEntries(ipWhitelistEntries.filter((e) => e.ip !== ipToRemove));
  };

  const handleCopyOverride = () => {
    const snippet = `// WebCare Pro Emergency Firewall Rescue Override\ndefine( 'WEBCAREPROSCAN_FIREWALL_DISABLED', true );`;
    navigator.clipboard.writeText(snippet);
    setCopiedSnippet(true);
    setTimeout(() => setCopiedSnippet(false), 2500);
  };

  return (
    <div className="webcare-wizard-step-container" style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
      {/* Step Header */}
      <div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '4px 10px', borderRadius: '20px', background: 'rgba(16, 185, 129, 0.1)', color: '#059669', fontSize: '12px', fontWeight: 700, marginBottom: '12px' }}>
          <UserCheck size={14} /> Phase 1: Environment Telemetry &amp; Foundation
        </div>
        <h1 style={{ margin: '0 0 10px 0', fontSize: '24px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
          Zero-Lockout Owner Guarantee &amp; IP Whitelist
        </h1>
        <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--webcare-text-secondary, #475569)', margin: 0 }}>
          WebCare Pro is architected with a strict <strong>Zero-Lockout Guarantee</strong>. Even under aggressive automated attack mitigation, authorized site owners and developers are permanently immune from false-positive firewall locks.
        </p>
      </div>

      {/* 1-Click Current IP Whitelist Card */}
      <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '16px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
            <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: 'rgba(16, 185, 129, 0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#059669', flexShrink: 0 }}>
              <ShieldCheck size={22} />
            </div>
            <div>
              <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Detected Administrator IP: <code style={{ color: 'var(--webcare-primary, #4f46e5)', fontSize: '14px' }}>{clientIp}</code>
              </div>
              <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '4px' }}>
                Automatically bypasses all rate limiting, 404 traps, country blocking, and honeypot inspection for this workstation.
              </div>
            </div>
          </div>

          <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer', background: 'var(--webcare-bg-panel, #ffffff)', padding: '8px 14px', borderRadius: '8px', border: '1px solid var(--webcare-border, #cbd5e1)' }}>
            <input
              type="checkbox"
              checked={whitelistIp}
              onChange={(e) => setWhitelistIp(e.target.checked)}
              style={{ accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
              Whitelist My Current IP
            </span>
          </label>
        </div>
      </div>

      {/* Multi-IP & CIDR Whitelist Table */}
      <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
          <div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
              Additional Developer IPs &amp; Office CIDR Blocks
            </div>
            <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
              Add team members, agency static IPs, or office subnets (supports IPv4, IPv6, and CIDR ranges like <code>198.51.100.0/24</code>).
            </div>
          </div>
        </div>

        {/* Add Entry Row */}
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginBottom: '16px' }}>
          <input
            type="text"
            placeholder="IP Address or CIDR (e.g. 203.0.113.5 or 198.51.100.0/24)"
            value={newIp}
            onChange={(e) => setNewIp(e.target.value)}
            className="webcare-firewall-input"
            style={{ flex: '1 1 240px', padding: '8px 12px', fontSize: '13px', borderRadius: '8px' }}
          />
          <input
            type="text"
            placeholder="Label (e.g. Lead Dev Office, VPN)"
            value={newLabel}
            onChange={(e) => setNewLabel(e.target.value)}
            className="webcare-firewall-input"
            style={{ flex: '1 1 180px', padding: '8px 12px', fontSize: '13px', borderRadius: '8px' }}
          />
          <button
            type="button"
            onClick={handleAddEntry}
            className="webcare-btn-primary"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 16px',
              borderRadius: '8px',
              fontSize: '13px',
              fontWeight: 700,
              cursor: 'pointer',
              background: 'var(--webcare-primary, #4f46e5)',
              color: '#ffffff',
              border: 'none'
            }}
          >
            <Plus size={15} /> Add Whitelist
          </button>
        </div>

        {ipError && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: '#dc2626', marginBottom: '12px' }}>
            <AlertCircle size={14} /> {ipError}
          </div>
        )}

        {/* Whitelist Entries List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {ipWhitelistEntries.length === 0 ? (
            <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--webcare-bg-elevated, #f8fafc)', fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', textAlign: 'center' }}>
              No custom whitelist entries added yet. Your detected IP is protected above.
            </div>
          ) : (
            ipWhitelistEntries.map((item) => (
              <div
                key={item.ip}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '10px 14px',
                  borderRadius: '8px',
                  background: 'var(--webcare-bg-elevated, #f8fafc)',
                  border: '1px solid var(--webcare-border, #e2e8f0)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <code style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                    {item.ip}
                  </code>
                  <span style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>
                    {item.label}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => handleRemoveEntry(item.ip)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: '#dc2626',
                    cursor: 'pointer',
                    padding: '4px',
                    display: 'flex',
                    alignItems: 'center'
                  }}
                  title="Remove from Whitelist"
                >
                  <Trash2 size={15} />
                </button>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Emergency Rescue Kit & Support Code */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px' }}>
        {/* Support Code Card */}
        <div style={{ padding: '16px', borderRadius: '12px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '6px' }}>
            <Key size={16} color="var(--webcare-primary, #4f46e5)" />
            Customer Support Emergency Unlock Code
          </div>
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5, marginBottom: '10px' }}>
            If a customer ever encounters an accidental block, they can share this unique security token with you to instantly locate and unblock their session:
          </div>
          <div style={{ padding: '8px 12px', borderRadius: '6px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #cbd5e1)', fontFamily: 'monospace', fontSize: '14px', fontWeight: 800, color: 'var(--webcare-primary, #4f46e5)', display: 'inline-block' }}>
            {supportCode}
          </div>
        </div>

        {/* wp-config.php Snippet Card */}
        <div style={{ padding: '16px', borderRadius: '12px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
              <Terminal size={16} color="#0284c7" />
              Emergency wp-config.php Override
            </div>
            <button
              type="button"
              onClick={handleCopyOverride}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px',
                fontSize: '11px',
                fontWeight: 600,
                color: copiedSnippet ? '#059669' : 'var(--webcare-primary, #4f46e5)',
                background: 'none',
                border: 'none',
                cursor: 'pointer'
              }}
            >
              {copiedSnippet ? <Check size={13} /> : <Copy size={13} />}
              {copiedSnippet ? 'Copied' : 'Copy'}
            </button>
          </div>
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5, marginBottom: '10px' }}>
            In the impossible event that all administrative credentials are lost, placing this constant in <code>wp-config.php</code> immediately mutes all WAF filters:
          </div>
          <div style={{ padding: '8px 12px', borderRadius: '6px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #cbd5e1)', fontFamily: 'monospace', fontSize: '11px', color: 'var(--webcare-text-title, #0f172a)' }}>
            define('WEBCAREPROSCAN_FIREWALL_DISABLED', true);
          </div>
        </div>
      </div>
    </div>
  );
};
