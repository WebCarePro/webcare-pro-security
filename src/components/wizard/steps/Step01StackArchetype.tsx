import React from 'react';
import {
  Layers,
  Sparkles,
  ShoppingBag,
  Users,
  Briefcase,
  BookOpen,
  Check,
  ShieldCheck,
  Zap,
  Lock,
  Cpu
} from 'lucide-react';
import { DeveloperDeepDive } from '../DeveloperDeepDive';

interface Step01Props {
  archetype: string;
  setArchetype: (archetype: string) => void;
  status: any;
  adaptiveStackMonitoring: boolean;
  setAdaptiveStackMonitoring: (val: boolean) => void;
  environmentOverride: string;
  setEnvironmentOverride: (val: string) => void;
}

export const Step01StackArchetype: React.FC<Step01Props> = ({
  archetype,
  setArchetype,
  status,
  adaptiveStackMonitoring,
  setAdaptiveStackMonitoring,
  environmentOverride,
  setEnvironmentOverride,
}) => {
  const stack = status?.stack_snapshot || {};
  const affiliateTelemetry = status?.affiliate_telemetry || stack?.affiliate_telemetry || null;
  const detectedEcosystems: string[] = stack.detected_ecosystems || [];
  const detectedPlugins: any[] = stack.active_security_relevant_plugins || [];
  const hasAffiliate = !!(affiliateTelemetry?.is_active || detectedEcosystems.includes('affiliate'));
  const affiliateSummary = affiliateTelemetry?.summary || (affiliateTelemetry?.plugins?.length ? affiliateTelemetry.plugins.join(', ') : 'Affiliate Ecosystem Active');

  const archetypes = [
    {
      id: 'ecommerce',
      label: 'E-Commerce / WooCommerce',
      icon: <ShoppingBag size={20} />,
      desc: 'High-velocity checkout shielding, carding bot rate limits, coupon flood traps, and Store API locks.',
      tuning: `Auto-arms WooCommerce Revenue Armor + Smart Rules #54${hasAffiliate ? ' + Rule #43 Affiliate Shield' : ''}`
    },
    {
      id: 'membership',
      label: 'Membership / LMS / Portal',
      icon: <Users size={20} />,
      desc: 'Credential stuffing defense, account takeover mitigation, and protected digital asset streaming.',
      tuning: 'Auto-arms 2FA Enforcement + Strict REST Session Guards'
    },
    {
      id: 'business',
      label: 'Corporate / Lead-Gen Website',
      icon: <Briefcase size={20} />,
      desc: 'Contact form spam mitigation, lead injection blocking, and stealth reconnaissance shields.',
      tuning: 'Auto-arms Zero-Day Virtual Patching + RASP Rule #44'
    },
    {
      id: 'blog',
      label: 'Blog / Editorial / Media',
      icon: <BookOpen size={20} />,
      desc: 'Comment spam traps, high-concurrency caching bypass guards, and RSS / feed scraper mitigation.',
      tuning: 'Auto-arms Smart Rule #48 (W3TC) & #49 (LSCache)'
    }
  ];

  return (
    <div className="webcare-wizard-step-container" style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
      {/* Step Header */}
      <div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '4px 10px', borderRadius: '20px', background: 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.08))', color: 'var(--webcare-primary, #4f46e5)', fontSize: '12px', fontWeight: 700, marginBottom: '12px' }}>
          <Sparkles size={14} /> Phase 1: Environment Telemetry &amp; Foundation
        </div>
        <h1 style={{ margin: '0 0 10px 0', fontSize: '24px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
          Site Archetype &amp; Live Stack Auto-Detection
        </h1>
        <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--webcare-text-secondary, #475569)', margin: 0 }}>
          WebCare Pro dynamically profiles your active WordPress environment to tailor perimeter firewalls, virtual patches, and rate limiters specifically to your active technology stack.
        </p>
      </div>

      {/* 100% On-Premise Sovereign Security Pledge */}
      <div
        style={{
          padding: '20px 24px',
          borderRadius: '14px',
          background: 'linear-gradient(135deg, rgba(79, 70, 229, 0.06) 0%, rgba(16, 185, 129, 0.06) 100%)',
          border: '1px solid rgba(79, 70, 229, 0.2)',
          boxShadow: '0 4px 16px rgba(0, 0, 0, 0.03)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px', marginBottom: '16px' }}>
          <div
            style={{
              padding: '10px',
              borderRadius: '10px',
              background: 'var(--webcare-primary, #4f46e5)',
              color: '#ffffff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}
          >
            <ShieldCheck size={24} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
                100% On-Premise Sovereign Security Guarantee
              </h3>
              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  color: '#059669',
                  background: 'rgba(16, 185, 129, 0.12)',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  padding: '2px 8px',
                  borderRadius: '12px',
                }}
              >
                Zero 3rd-Party Telemetry
              </span>
            </div>
            <p style={{ margin: '6px 0 0 0', fontSize: '13px', lineHeight: 1.6, color: 'var(--webcare-text-secondary, #475569)' }}>
              WebCare Pro runs entirely inside your own hosting server environment. We never phone home, never track your visitors, and never transmit your source code, database records, customer PII, or security logs to any external cloud or third-party server.
            </p>
          </div>
        </div>

        {/* 3 Cryptographic Guarantees */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
            gap: '12px',
            paddingTop: '14px',
            borderTop: '1px solid rgba(79, 70, 229, 0.12)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
            <div style={{ color: '#059669', marginTop: '2px', flexShrink: 0 }}>
              <Check size={16} strokeWidth={3} />
            </div>
            <div>
              <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Zero Data Harvesting
              </div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', lineHeight: 1.5 }}>
                All malware scans, AST code audits, and behavioral models execute and stay strictly on your server's disk.
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
            <div style={{ color: '#059669', marginTop: '2px', flexShrink: 0 }}>
              <Check size={16} strokeWidth={3} />
            </div>
            <div>
              <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Local Encrypted Vault Storage
              </div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', lineHeight: 1.5 }}>
                Intelligence telemetry and keys are sealed inside your local <code style={{ fontSize: '10px', color: 'var(--webcare-primary, #4f46e5)' }}>uploads/webcare-pro-security/intel-vault/</code> with HMAC-SHA256 &amp; AES-256.
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
            <div style={{ color: '#059669', marginTop: '2px', flexShrink: 0 }}>
              <Check size={16} strokeWidth={3} />
            </div>
            <div>
              <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Direct Opt-In Connections Only
              </div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', lineHeight: 1.5 }}>
                External APIs (such as Cloudflare Edge or Slack/Discord webhooks) only connect if you explicitly enter your own API credentials.
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Auto-Detected Ecosystems Banner */}
      <div style={{ padding: '16px 20px', borderRadius: '12px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
            <Layers size={16} color="var(--webcare-primary, #4f46e5)" />
            Live Stack Profile Detected
          </div>
          <span style={{ fontSize: '11px', fontWeight: 600, color: '#059669', background: 'rgba(16, 185, 129, 0.1)', padding: '2px 8px', borderRadius: '12px' }}>
            {detectedEcosystems.length} Ecosystems Active
          </span>
        </div>

        {detectedEcosystems.length > 0 || hasAffiliate ? (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
            {detectedEcosystems.map((eco) => (
              <span
                key={eco}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '4px 10px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  fontWeight: 600,
                  background: 'var(--webcare-bg-panel, #ffffff)',
                  border: '1px solid var(--webcare-border, #cbd5e1)',
                  color: 'var(--webcare-text-title, #0f172a)',
                  textTransform: 'capitalize'
                }}
              >
                <Check size={12} color="#059669" />
                {eco}
              </span>
            ))}
            {hasAffiliate && !detectedEcosystems.includes('affiliate') && (
              <span
                key="affiliate_shield_telemetry"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '4px 10px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  fontWeight: 600,
                  background: 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.08))',
                  border: '1px solid rgba(79, 70, 229, 0.3)',
                  color: 'var(--webcare-primary, #4f46e5)',
                }}
              >
                <ShieldCheck size={12} color="var(--webcare-primary, #4f46e5)" />
                Rule #43 Affiliate Shield ({affiliateSummary})
              </span>
            )}
          </div>
        ) : (
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
            Standard WordPress Core runtime detected.
          </div>
        )}
      </div>

      {/* Archetype Selector Cards */}
      <div>
        <label style={{ display: 'block', fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '10px' }}>
          Select Primary Site Archetype:
        </label>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '14px' }}>
          {archetypes.map((arch) => {
            const isSelected = archetype === arch.id;
            return (
              <div
                key={arch.id}
                onClick={() => setArchetype(arch.id)}
                style={{
                  padding: '16px',
                  borderRadius: '12px',
                  cursor: 'pointer',
                  border: isSelected ? '2px solid var(--webcare-primary, #4f46e5)' : '1px solid var(--webcare-border, #e2e8f0)',
                  background: isSelected ? 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.04))' : 'var(--webcare-bg-panel, #ffffff)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '10px',
                  transition: 'all 0.15s ease',
                  position: 'relative'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: isSelected ? 'var(--webcare-primary, #4f46e5)' : 'var(--webcare-text-title, #0f172a)', fontWeight: 700, fontSize: '14px' }}>
                    {arch.icon}
                    {arch.label}
                  </div>
                  {isSelected && (
                    <span style={{ width: '18px', height: '18px', borderRadius: '50%', background: 'var(--webcare-primary, #4f46e5)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#ffffff' }}>
                      <Check size={12} />
                    </span>
                  )}
                </div>
                <div style={{ fontSize: '12px', lineHeight: 1.5, color: 'var(--webcare-text-secondary, #475569)' }}>
                  {arch.desc}
                </div>
                <div style={{ fontSize: '11px', fontWeight: 600, color: isSelected ? 'var(--webcare-primary, #4f46e5)' : 'var(--webcare-text-muted, #64748b)', background: 'var(--webcare-bg-elevated, #f1f5f9)', padding: '4px 8px', borderRadius: '6px' }}>
                  ⚡ {arch.tuning}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Developer Deep Dive Drawer */}
      <DeveloperDeepDive
        title="Developer Controls: Stack Monitoring & Environment Calibration"
        badge="SettingsManager API"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Adaptive Monitoring Toggle */}
          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={adaptiveStackMonitoring}
              onChange={(e) => setAdaptiveStackMonitoring(e.target.checked)}
              style={{ marginTop: '2px', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)' }}>
                Adaptive Stack Monitoring (<code>adaptive_stack_monitoring_enabled</code>)
              </div>
              <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
                Automatically re-evaluates firewall attack-surface rules and virtual patches whenever plugins or themes are activated or deactivated in WordPress.
              </div>
            </div>
          </label>

          {/* Environment Override Selector */}
          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '6px' }}>
              Runtime Environment Mode (<code>environment_override</code>):
            </label>
            <select
              value={environmentOverride}
              onChange={(e) => setEnvironmentOverride(e.target.value)}
              className="webcare-input"
              style={{
                width: '100%',
                maxWidth: '320px',
                padding: '8px 12px',
                borderRadius: '8px',
                fontSize: '13px',
                border: '1px solid var(--webcare-border, #cbd5e1)',
                background: 'var(--webcare-bg-panel, #ffffff)',
                color: 'var(--webcare-text-title, #0f172a)'
              }}
            >
              <option value="auto">Auto-Detect (Recommended based on WP_ENVIRONMENT_TYPE)</option>
              <option value="production">Strict Production (Strict Rate Limits &amp; Full WAF Enforcement)</option>
              <option value="staging">Staging / QA (Enhanced Logging, Muted IP Lockouts)</option>
              <option value="local">Local Development (Permissive Mode for Docker / LocalWP)</option>
            </select>
          </div>
        </div>
      </DeveloperDeepDive>
    </div>
  );
};
