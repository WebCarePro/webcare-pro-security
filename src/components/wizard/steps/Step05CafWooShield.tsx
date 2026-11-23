import React from 'react';
import {
  Zap,
  ShoppingBag,
  ShieldAlert,
  Sliders,
  CheckCircle2,
  Lock,
  Layers,
  Sparkles,
  Cpu,
  FileText,
  MessageSquare,
  ShieldCheck,
  Check
} from 'lucide-react';
import { DeveloperDeepDive } from '../DeveloperDeepDive';

interface Step05Props {
  archetype: string;
  status: any;
  wafAdvanced: any;
  setWafAdvanced: React.Dispatch<React.SetStateAction<any>>;
  cafProfile?: string;
  setCafProfile?: (profile: string) => void;
}

export const Step05CafWooShield: React.FC<Step05Props> = ({
  archetype,
  status,
  wafAdvanced,
  setWafAdvanced,
  cafProfile = 'balanced',
  setCafProfile,
}) => {
  const isWooDetected = (status?.stack_snapshot?.detected_ecosystems || []).includes('woocommerce') || archetype === 'ecommerce';

  const isLowMemoryHost = status?.server_info?.php?.memory_limit === '128M' || status?.server_info?.is_shared_hosting;

  const recommendedProfile = status?.caf_status?.recommended_profile ||
    (isLowMemoryHost ? 'cpanel_shared_saver' : (isWooDetected ? 'ecommerce_hardened' : 'balanced'));

  const profiles = [
    {
      id: 'cpanel_shared_saver',
      name: 'cPanel / Shared Saver',
      icon: <Cpu size={16} color="#f59e0b" />,
      desc: 'Low-resource & CloudLinux hosting. Minimizes PHP worker wakeups with lean fast-path preload execution.',
    },
    {
      id: 'balanced',
      name: 'Balanced (Default)',
      icon: <ShieldCheck size={16} color="#6366f1" />,
      desc: 'Adaptive standard profile. Comprehensive brute-force filters, crawler verification, and virtual patching.',
    },
    {
      id: 'ecommerce_hardened',
      name: 'E-Commerce Hardened',
      icon: <ShoppingBag size={16} color="#10b981" />,
      desc: 'High-velocity checkout shielding, anti-carding bot traps, and automatic payment webhook immunity.',
    },
    {
      id: 'corporate_brochure',
      name: 'Corporate / Brochure',
      icon: <FileText size={16} color="#0284c7" />,
      desc: 'Elementor, Divi & Contact Forms. Page-builder compatibility with strict perimeter probe defense.',
    },
    {
      id: 'membership_lms',
      name: 'Membership & LMS',
      icon: <Layers size={16} color="#8b5cf6" />,
      desc: 'MemberPress, LearnDash & BuddyBoss. Anti-credential stuffing, concurrent session armor, and video throughput.',
    },
    {
      id: 'community_forum',
      name: 'Community & Forum',
      icon: <MessageSquare size={16} color="#06b6d4" />,
      desc: 'bbPress, wpForo & Asgaros. Mitigates topic/reply spambots, shields member directories from scraping.',
    },
    {
      id: 'high_security_paranoid',
      name: 'High-Security / Paranoid',
      icon: <Lock size={16} color="#ef4444" />,
      desc: 'Zero-trust defense mode. Strict zero-tolerance perimeter filters, early honeytokens, and aggressive lockouts.',
    },
  ];

  const handleSelectProfile = (pId: string) => {
    if (setCafProfile) {
      setCafProfile(pId);
    }
    if (pId === 'ecommerce_hardened') {
      setWafAdvanced((prev: any) => ({ ...prev, waf_ecommerce_safe_mode: true }));
    }
  };

  const cafSwitches = [
    {
      key: 'waf_caf_block_inactive_plugins',
      title: 'Block Dormant Plugin / Theme Probing',
      desc: 'Halts direct HTTP reconnaissance targeting inactive plugins in /wp-content/plugins/.'
    },
    {
      key: 'waf_caf_lock_dormant_rest',
      title: 'Dormant REST Namespace Lockdown',
      desc: 'Restricts public access to unused or dormant /wp-json/ endpoints.'
    },
    {
      key: 'waf_caf_strict_guest_admin_ajax',
      title: 'Strict Guest Admin-AJAX Policy',
      desc: 'Protects /wp-admin/admin-ajax.php from unauthenticated SQLi and SSRF exploitation.'
    }
  ];

  const smartRules = [
    { id: '#48', name: 'W3TC CacheShell RCE', tag: 'CVE-2026-W3TC' },
    { id: '#49', name: 'LiteSpeed Cache Crawler Priv-Esc', tag: 'CVE-2026-LSCACHE' },
    { id: '#50', name: 'Bricks Builder Render RCE', tag: 'CVE-2026-BRICKS' },
    { id: '#51', name: 'WP Mail SMTP / Post SMTP Takeover', tag: 'CVE-2026-MAIL-AUTH' },
    { id: '#52', name: 'LLM AI Prompt Injection Shield', tag: 'AI-INJECTION' },
    { id: '#53', name: 'WPGraphQL Introspection DoS', tag: 'GRAPHQL-DOS' },
    { id: '#54', name: 'Store API Batch SKU Harvesting', tag: 'WC-BATCH-DOS' },
  ];

  return (
    <div className="webcare-wizard-step-container" style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
      {/* Step Header */}
      <div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '4px 10px', borderRadius: '20px', background: 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.08))', color: 'var(--webcare-primary, #4f46e5)', fontSize: '12px', fontWeight: 700, marginBottom: '12px' }}>
          <Zap size={14} /> Phase 2: Multi-Layer Perimeter WAF
        </div>
        <h1 style={{ margin: '0 0 10px 0', fontSize: '24px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
          Context-Aware Firewall (CAF 2.0) &amp; WooCommerce Armor
        </h1>
        <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--webcare-text-secondary, #475569)', margin: 0 }}>
          CAF 2.0 shrinks attack surfaces dynamically by inspecting active WordPress plugins and enforcing dedicated checkout armor to eliminate card testing bots and coupon brute-forcing.
        </p>
      </div>

      {/* Context-Adaptive Firewall (CAF) Protection Profile Selector */}
      <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
          <div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Cpu size={16} color="var(--webcare-primary, #4f46e5)" />
              Context-Adaptive Firewall (CAF) Protection Profile
            </div>
            <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
              Select a specialized execution profile tailored to your hosting environment and application demands.
            </div>
          </div>
          <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-primary, #4f46e5)', background: 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.08))', padding: '3px 10px', borderRadius: '10px' }}>
            Active: {profiles.find(p => p.id === cafProfile)?.name || 'Balanced'}
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '12px', marginBottom: '12px' }}>
          {profiles.map((p) => {
            const isSelected = cafProfile === p.id;
            const isRecommended = p.id === recommendedProfile;
            return (
              <div
                key={p.id}
                onClick={() => handleSelectProfile(p.id)}
                style={{
                  padding: '14px',
                  borderRadius: '10px',
                  cursor: 'pointer',
                  border: isSelected
                    ? '2px solid var(--webcare-primary, #4f46e5)'
                    : '1px solid var(--webcare-border, #e2e8f0)',
                  background: isSelected
                    ? 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.04))'
                    : 'var(--webcare-bg-elevated, #f8fafc)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                  transition: 'all 0.15s ease-in-out'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {p.icon}
                    <strong style={{ fontSize: '13px', color: 'var(--webcare-text-title, #0f172a)' }}>
                      {p.name}
                    </strong>
                  </div>
                  {isSelected ? (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '10px', fontWeight: 700, color: '#059669', background: 'rgba(16, 185, 129, 0.1)', padding: '2px 6px', borderRadius: '6px' }}>
                      <Check size={11} strokeWidth={3} /> Selected
                    </span>
                  ) : isRecommended ? (
                    <span style={{ fontSize: '10px', fontWeight: 700, color: '#0284c7', background: 'rgba(2, 132, 199, 0.1)', padding: '2px 6px', borderRadius: '6px' }}>
                      Recommended
                    </span>
                  ) : null}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.45, flex: 1 }}>
                  {p.desc}
                </div>
              </div>
            );
          })}
        </div>

        {cafProfile === 'cpanel_shared_saver' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 14px', borderRadius: '8px', background: 'rgba(245, 158, 11, 0.08)', border: '1px solid rgba(245, 158, 11, 0.25)', fontSize: '12px', color: 'var(--webcare-text-title, #0f172a)' }}>
            <Cpu size={15} color="#f59e0b" style={{ flexShrink: 0 }} />
            <span><strong>cPanel / Shared Host Saver Active:</strong> Preload Micro-WAF and background scanners will execute with ultra-lean fast-path buffers to strictly respect CloudLinux LVE memory and CPU ceilings.</span>
          </div>
        )}
      </div>

      {/* CAF 2.0 Attack Surface Reduction Toggles */}
      <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '14px' }}>
          CAF 2.0 Attack-Surface Reduction Suite
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px' }}>
          {cafSwitches.map((item) => {
            const isChecked = !!wafAdvanced[item.key];
            return (
              <label
                key={item.key}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '12px',
                  padding: '14px',
                  borderRadius: '10px',
                  background: isChecked ? 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.03))' : 'var(--webcare-bg-elevated, #f8fafc)',
                  border: isChecked ? '1px solid var(--webcare-primary, #4f46e5)' : '1px solid var(--webcare-border, #e2e8f0)',
                  cursor: 'pointer'
                }}
              >
                <input
                  type="checkbox"
                  checked={isChecked}
                  onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, [item.key]: e.target.checked }))}
                  style={{ marginTop: '2px', accentColor: 'var(--webcare-primary, #4f46e5)' }}
                />
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                    {item.title}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.4, marginTop: '2px' }}>
                    {item.desc}
                  </div>
                </div>
              </label>
            );
          })}
        </div>
      </div>

      {/* 2026 Smart Rules (#48 - #54) Matrix */}
      <div style={{ padding: '16px 20px', borderRadius: '12px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
          <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
            2026 High-Severity Smart Rules (#48 – #54 Active)
          </div>
          <span style={{ fontSize: '11px', fontWeight: 700, color: '#059669', background: 'rgba(16, 185, 129, 0.1)', padding: '2px 8px', borderRadius: '8px' }}>
            7 Rules Armed
          </span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '8px' }}>
          {smartRules.map((r) => (
            <div
              key={r.id}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 10px',
                borderRadius: '6px',
                background: 'var(--webcare-bg-panel, #ffffff)',
                border: '1px solid var(--webcare-border, #cbd5e1)',
                fontSize: '11px'
              }}
            >
              <span style={{ fontWeight: 800, color: 'var(--webcare-primary, #4f46e5)' }}>{r.id}</span>
              <span style={{ fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)', flex: 1 }}>{r.name}</span>
              <span style={{ fontSize: '9px', fontWeight: 700, color: '#64748b', background: 'var(--webcare-bg-elevated, #f1f5f9)', padding: '1px 5px', borderRadius: '4px' }}>
                {r.tag}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* WooCommerce Revenue Armor (Auto-Expanded for E-Commerce) */}
      {isWooDetected && (
        <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-panel, #ffffff)', border: '2px solid rgba(16, 185, 129, 0.3)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ width: '32px', height: '32px', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#059669' }}>
                <ShoppingBag size={18} />
              </div>
              <div>
                <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
                  WooCommerce Revenue &amp; Checkout Armor
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)' }}>
                  Shopper-aware defense calibrated for live stores with zero checkout false positives.
                </div>
              </div>
            </div>
            <span style={{ fontSize: '11px', fontWeight: 700, color: '#059669', background: 'rgba(16, 185, 129, 0.1)', padding: '3px 10px', borderRadius: '10px' }}>
              REVENUE SHIELD ACTIVE
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px', marginBottom: '16px' }}>
            {/* Safe Mode Toggle */}
            <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', padding: '12px', borderRadius: '8px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={wafAdvanced.waf_ecommerce_safe_mode}
                onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, waf_ecommerce_safe_mode: e.target.checked }))}
                style={{ marginTop: '2px', accentColor: '#10b981' }}
              />
              <div>
                <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                  Zero Checkout False-Positive Guarantee
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
                  Auto-exempts Stripe/PayPal webhooks and active cart tokens from strict WAF payload filters.
                </div>
              </div>
            </label>

            {/* Carding Protection */}
            <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', padding: '12px', borderRadius: '8px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={wafAdvanced.waf_woo_carding_protection}
                onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, waf_woo_carding_protection: e.target.checked }))}
                style={{ marginTop: '2px', accentColor: '#10b981' }}
              />
              <div>
                <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                  Anti-Carding Velocity Shield
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
                  Limits rapid declined checkout attempts to defend against stolen credit card testing bots.
                </div>
              </div>
            </label>

            {/* Coupon Protection */}
            <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', padding: '12px', borderRadius: '8px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={wafAdvanced.waf_woo_coupon_protection}
                onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, waf_woo_coupon_protection: e.target.checked }))}
                style={{ marginTop: '2px', accentColor: '#10b981' }}
              />
              <div>
                <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                  Coupon Brute-Force Trap
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
                  Defends against coupon code enumeration (8 failures + 4 shopper bonus).
                </div>
              </div>
            </label>

            {/* Cart Flood Protection */}
            <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', padding: '12px', borderRadius: '8px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={wafAdvanced.waf_woo_cart_flood_protection}
                onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, waf_woo_cart_flood_protection: e.target.checked }))}
                style={{ marginTop: '2px', accentColor: '#10b981' }}
              />
              <div>
                <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                  Cart Flood &amp; Inventory Denial
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
                  Stops bots from locking out stock by adding hundreds of items to cart.
                </div>
              </div>
            </label>
          </div>
        </div>
      )}

      {/* Developer Deep Dive: Fine-Tuning WooCommerce Sliders */}
      <DeveloperDeepDive
        title="Developer Controls: WooCommerce Attack Velocity Sliders"
        badge="SettingsManager::waf_settings"
      >
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
              <label style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Max Carding Attempts (waf_woo_carding_max_attempts):
              </label>
              <span style={{ fontSize: '12px', fontWeight: 800, color: 'var(--webcare-primary, #4f46e5)' }}>
                {wafAdvanced.waf_woo_carding_max_attempts || 5}
              </span>
            </div>
            <input
              type="range"
              min={2}
              max={15}
              value={wafAdvanced.waf_woo_carding_max_attempts || 5}
              onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, waf_woo_carding_max_attempts: parseInt(e.target.value, 10) }))}
              style={{ width: '100%', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
              <label style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Coupon Failure Cap (waf_woo_coupon_max_failures):
              </label>
              <span style={{ fontSize: '12px', fontWeight: 800, color: 'var(--webcare-primary, #4f46e5)' }}>
                {wafAdvanced.waf_woo_coupon_max_failures || 8} (+4 shopper)
              </span>
            </div>
            <input
              type="range"
              min={3}
              max={25}
              value={wafAdvanced.waf_woo_coupon_max_failures || 8}
              onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, waf_woo_coupon_max_failures: parseInt(e.target.value, 10) }))}
              style={{ width: '100%', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
              <label style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Cart Additions / Min (waf_woo_cart_max_adds_per_min):
              </label>
              <span style={{ fontSize: '12px', fontWeight: 800, color: 'var(--webcare-primary, #4f46e5)' }}>
                {wafAdvanced.waf_woo_cart_max_adds_per_min || 35}
              </span>
            </div>
            <input
              type="range"
              min={10}
              max={120}
              value={wafAdvanced.waf_woo_cart_max_adds_per_min || 35}
              onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, waf_woo_cart_max_adds_per_min: parseInt(e.target.value, 10) }))}
              style={{ width: '100%', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
              <label style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Catalog Scraping / Min (waf_woo_scraping_max_reqs_per_min):
              </label>
              <span style={{ fontSize: '12px', fontWeight: 800, color: 'var(--webcare-primary, #4f46e5)' }}>
                {wafAdvanced.waf_woo_scraping_max_reqs_per_min || 60}
              </span>
            </div>
            <input
              type="range"
              min={20}
              max={200}
              value={wafAdvanced.waf_woo_scraping_max_reqs_per_min || 60}
              onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, waf_woo_scraping_max_reqs_per_min: parseInt(e.target.value, 10) }))}
              style={{ width: '100%', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
          </div>
        </div>
      </DeveloperDeepDive>
    </div>
  );
};
