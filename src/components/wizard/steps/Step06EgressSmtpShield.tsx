import React from 'react';
import {
  Activity,
  Mail,
  ShieldCheck,
  AlertTriangle,
  Globe,
  Lock,
  Server,
  Check,
  CheckCircle2
} from 'lucide-react';
import { DeveloperDeepDive } from '../DeveloperDeepDive';

interface Step06Props {
  status: any;
  egressMode: 'off' | 'monitor' | 'enforce';
  setEgressMode: (mode: 'off' | 'monitor' | 'enforce') => void;
  egressAllowedDomains: string[];
  setEgressAllowedDomains: (domains: string[]) => void;
  egressBlockUnverifiedSsl: boolean;
  setEgressBlockUnverifiedSsl: (val: boolean) => void;
}

export const Step06EgressSmtpShield: React.FC<Step06Props> = ({
  status,
  egressMode,
  setEgressMode,
  egressAllowedDomains,
  setEgressAllowedDomains,
  egressBlockUnverifiedSsl,
  setEgressBlockUnverifiedSsl,
}) => {
  const egressStatus = status?.egress_status || {};
  const activeMailer = egressStatus.active_mailer || 'Standard wp_mail() / PHP mail()';
  const detectedSmtpHosts = egressStatus.detected_smtp_hosts || [];

  const handleDomainsChange = (val: string) => {
    const list = val.split('\n').map((s) => s.trim().toLowerCase()).filter(Boolean);
    setEgressAllowedDomains(list);
  };

  const modes = [
    {
      id: 'monitor',
      label: 'Monitor & Log Only (Safe Default)',
      desc: 'Monitors all outbound connections, logs destinations, and highlights anomalies without dropping traffic.',
      badge: 'Zero Risk'
    },
    {
      id: 'enforce',
      label: 'Strict Enforce (Full SSRF Shield)',
      desc: 'Strictly blocks requests to unauthorized external domains, private RFC-1918 subnets, and cloud metadata APIs.',
      badge: 'Maximum SOC Armor'
    },
    {
      id: 'off',
      label: 'Disabled',
      desc: 'Disables outbound inspection hooks on wp_remote_request.',
      badge: 'Bypassed'
    }
  ];

  const approvedRelays = [
    'SendGrid', 'Mailgun', 'Amazon SES', 'Postmark', 'Brevo / Sendinblue',
    'Gmail API', 'Office 365 / Outlook', 'Mailtrap', 'Resend', 'SparkPost',
    'Mandrill', 'Zoho Mail', 'SMTP2GO', 'ActiveCampaign', 'HubSpot API'
  ];

  return (
    <div className="webcare-wizard-step-container" style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
      {/* Step Header */}
      <div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '4px 10px', borderRadius: '20px', background: 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.08))', color: 'var(--webcare-primary, #4f46e5)', fontSize: '12px', fontWeight: 700, marginBottom: '12px' }}>
          <Activity size={14} /> Phase 2: Multi-Layer Perimeter WAF
        </div>
        <h1 style={{ margin: '0 0 10px 0', fontSize: '24px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
          Outbound Egress Firewall &amp; Smart SMTP Shield
        </h1>
        <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--webcare-text-secondary, #475569)', margin: 0 }}>
          Modern webshells and compromised plugins steal sensitive data via outbound HTTP requests. WebCare's <strong>Outbound Egress Firewall</strong> intercepts all outgoing HTTP/cURL socket connections to halt SSRF and unauthorized data exfiltration.
        </p>
      </div>

      {/* Mode Selector */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '14px' }}>
        {modes.map((m) => {
          const isSelected = egressMode === m.id;
          return (
            <div
              key={m.id}
              onClick={() => setEgressMode(m.id as any)}
              style={{
                padding: '16px',
                borderRadius: '12px',
                cursor: 'pointer',
                border: isSelected ? '2px solid var(--webcare-primary, #4f46e5)' : '1px solid var(--webcare-border, #e2e8f0)',
                background: isSelected ? 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.04))' : 'var(--webcare-bg-panel, #ffffff)',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px',
                transition: 'all 0.15s ease'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '14px', fontWeight: 700, color: isSelected ? 'var(--webcare-primary, #4f46e5)' : 'var(--webcare-text-title, #0f172a)' }}>
                  {m.label}
                </span>
                {isSelected && (
                  <span style={{ width: '18px', height: '18px', borderRadius: '50%', background: 'var(--webcare-primary, #4f46e5)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#ffffff' }}>
                    <Check size={12} />
                  </span>
                )}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.4 }}>
                {m.desc}
              </div>
              <div style={{ fontSize: '11px', fontWeight: 600, color: isSelected ? 'var(--webcare-primary, #4f46e5)' : 'var(--webcare-text-muted, #64748b)', background: 'var(--webcare-bg-elevated, #f1f5f9)', padding: '3px 8px', borderRadius: '6px', alignSelf: 'flex-start' }}>
                {m.badge}
              </div>
            </div>
          );
        })}
      </div>

      {/* Hard-Deny SSRF Telemetry Banner */}
      <div style={{ padding: '16px 20px', borderRadius: '12px', background: 'rgba(239, 68, 68, 0.04)', border: '1px solid rgba(239, 68, 68, 0.2)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', fontWeight: 700, color: '#dc2626', marginBottom: '6px' }}>
          <Lock size={16} />
          Unconditional Hard-Deny SSRF Protection (Always Enforced)
        </div>
        <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5 }}>
          Regardless of the egress mode selected, WebCare unconditionally blocks all outbound requests to AWS/GCP/Azure Cloud Metadata (<code>169.254.169.254</code>), loopback (<code>127.0.0.1</code>), and private RFC-1918 subnets (<code>10.0.0.0/8</code>, <code>172.16.0.0/12</code>, <code>192.168.0.0/16</code>) to prevent internal infrastructure takeover.
        </div>
      </div>

      {/* Smart Email & SMTP Delivery Shield Banner */}
      <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
            <Mail size={18} color="var(--webcare-primary, #4f46e5)" />
            Smart Email &amp; SMTP Delivery Shield
          </div>
          <span style={{ fontSize: '11px', fontWeight: 700, color: '#059669', background: 'rgba(16, 185, 129, 0.1)', padding: '2px 8px', borderRadius: '6px' }}>
            AUTO-WHITELISTED
          </span>
        </div>
        <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5, marginBottom: '12px' }}>
          Customer order receipts, password resets, and notifications never fail. WebCare dynamically recognizes your configured mailer (<strong>{activeMailer}</strong>) and auto-whitelists 21 leading transactional email relays:
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
          {approvedRelays.map((relay) => (
            <span
              key={relay}
              style={{
                fontSize: '11px',
                fontWeight: 600,
                color: 'var(--webcare-text-secondary, #475569)',
                background: 'var(--webcare-bg-panel, #ffffff)',
                border: '1px solid var(--webcare-border, #cbd5e1)',
                padding: '3px 8px',
                borderRadius: '6px'
              }}
            >
              ✓ {relay}
            </span>
          ))}
        </div>
      </div>

      {/* Developer Deep Dive: Outbound Allowlist & TLS Enforcement */}
      <DeveloperDeepDive
        title="Developer Controls: Custom Outbound Domains & TLS Verification"
        badge="OutboundEgressFirewall API"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '6px' }}>
              Custom Outbound API Domain Allowlist (One domain per line):
            </label>
            <textarea
              rows={4}
              value={egressAllowedDomains.join('\n')}
              onChange={(e) => handleDomainsChange(e.target.value)}
              placeholder="api.customcrm.com&#10;erp.internal-gateway.io&#10;webhook.inventory-sync.org"
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
              WordPress.org API, WordPress core updates, and detected active plugin update servers are automatically permitted.
            </div>
          </div>

          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={egressBlockUnverifiedSsl}
              onChange={(e) => setEgressBlockUnverifiedSsl(e.target.checked)}
              style={{ marginTop: '2px', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)' }}>
                Enforce Strict TLS Certificate Verification on Outbound Requests
              </div>
              <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
                Prevents outbound man-in-the-middle attacks by dropping outbound HTTP requests with invalid, self-signed, or expired SSL certificates.
              </div>
            </div>
          </label>
        </div>
      </DeveloperDeepDive>
    </div>
  );
};
