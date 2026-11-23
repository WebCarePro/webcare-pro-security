import React, { useState } from 'react';
import {
  Shield,
  Zap,
  CheckCircle2,
  AlertCircle,
  Sliders,
  Globe,
  Loader2,
  FileCode,
  Lock,
  Terminal,
  Activity
} from 'lucide-react';
import { DeveloperDeepDive } from '../DeveloperDeepDive';
import { apiRequest } from '../../../utils/api';

interface Step04Props {
  status: any;
  firewallToggles: {
    block_malicious_uploads: boolean;
    brute_force_protection: boolean;
    virtual_patching: boolean;
    bad_bot_shield: boolean;
  };
  setFirewallToggles: React.Dispatch<React.SetStateAction<{
    block_malicious_uploads: boolean;
    brute_force_protection: boolean;
    virtual_patching: boolean;
    bad_bot_shield: boolean;
  }>>;
  wafAdvanced: {
    waf_enabled: boolean;
    waf_learning_mode: boolean;
    waf_rasp_enabled: boolean;
    waf_max_404_per_minute: number;
    waf_lockout_duration_mins: number;
    waf_404_exempt_patterns: string;
    waf_blocked_countries: string;
    waf_geo_block_mode: string;
  };
  setWafAdvanced: React.Dispatch<React.SetStateAction<any>>;
}

export const Step04CorePreloadWaf: React.FC<Step04Props> = ({
  status,
  firewallToggles,
  setFirewallToggles,
  wafAdvanced,
  setWafAdvanced,
}) => {
  const [installingPreload, setInstallingPreload] = useState(false);
  const [preloadResult, setPreloadResult] = useState<{ success: boolean; message: string } | null>(null);

  const preloadInfo = status?.preload_waf || {};
  const isPreloadActive = preloadInfo.is_active || preloadInfo.is_compiled;

  const handleInstallPreload = async () => {
    setInstallingPreload(true);
    setPreloadResult(null);
    try {
      const res = await apiRequest({
        path: '/firewall/micro-waf/install',
        method: 'POST'
      });
      if (res && res.success) {
        setPreloadResult({
          success: true,
          message: res.message || 'Pre-Boot Micro-WAF compiled and wired into server config successfully!'
        });
      } else {
        setPreloadResult({
          success: false,
          message: res?.message || 'Could not auto-write .user.ini. Host permissions may require manual configuration.'
        });
      }
    } catch (e: any) {
      setPreloadResult({
        success: false,
        message: e?.message || 'Failed to trigger Micro-WAF installation.'
      });
    } finally {
      setInstallingPreload(false);
    }
  };

  const coreToggles = [
    {
      key: 'virtual_patching',
      title: 'Zero-Day Virtual Patching Engine',
      desc: 'Real-time defense against SQLi, XSS, Path Traversal, SSRF, Object Injection, and known CVEs.',
      badge: 'Core Shield'
    },
    {
      key: 'block_malicious_uploads',
      title: 'Malicious File Upload & Polyglot Inspector',
      desc: 'Inspects file headers, blocks executable PHP in disguise (GIF/PNG shells, double extensions .php.jpg).',
      badge: 'File Armor'
    },
    {
      key: 'brute_force_protection',
      title: 'XML-RPC & Auth Brute-Force Rate Limiter',
      desc: 'Halts password spray attacks on wp-login.php and disables unauthenticated XML-RPC methods.',
      badge: 'Auth Guard'
    },
    {
      key: 'bad_bot_shield',
      title: 'Autonomous AI Scraper & Bad Bot Shield',
      desc: 'Traps headless vulnerability scanners (Nikto, SQLMap, WPScan) and blocks unauthorized AI training bots.',
      badge: 'Bot Shield'
    }
  ];

  return (
    <div className="webcare-wizard-step-container" style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
      {/* Step Header */}
      <div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '4px 10px', borderRadius: '20px', background: 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.08))', color: 'var(--webcare-primary, #4f46e5)', fontSize: '12px', fontWeight: 700, marginBottom: '12px' }}>
          <Shield size={14} /> Phase 2: Multi-Layer Perimeter WAF
        </div>
        <h1 style={{ margin: '0 0 10px 0', fontSize: '24px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
          Preload Micro-WAF &amp; Core WAF Engine
        </h1>
        <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--webcare-text-secondary, #475569)', margin: 0 }}>
          WebCare Pro operates a dual-layer firewall: a pre-boot <strong>0ms Micro-WAF</strong> executing before WordPress core initialises, backed by an in-flight PHP application firewall.
        </p>
      </div>

      {/* Preload Micro-WAF Status & Action Card */}
      <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '16px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
            <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: isPreloadActive ? 'rgba(16, 185, 129, 0.12)' : 'rgba(79, 70, 229, 0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: isPreloadActive ? '#059669' : 'var(--webcare-primary, #4f46e5)', flexShrink: 0 }}>
              <Zap size={22} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '15px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                  Pre-Boot Micro-WAF (<code>auto_prepend_file</code>)
                </span>
                <span style={{ fontSize: '11px', fontWeight: 700, color: isPreloadActive ? '#059669' : '#d97706', background: isPreloadActive ? 'rgba(16, 185, 129, 0.1)' : 'rgba(217, 119, 6, 0.1)', padding: '2px 8px', borderRadius: '10px' }}>
                  {isPreloadActive ? '0ms ACTIVE & COMPILED' : 'READY TO COMPILE'}
                </span>
              </div>
              <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '4px', lineHeight: 1.5 }}>
                Compiles a standalone, zero-dependency PHP firewall into your web server's <code>.user.ini</code> or <code>.htaccess</code>. Blocks malicious payloads with <strong>0ms database overhead</strong>.
              </div>
            </div>
          </div>

          <button
            type="button"
            onClick={handleInstallPreload}
            disabled={installingPreload}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '10px 16px',
              borderRadius: '8px',
              fontSize: '13px',
              fontWeight: 700,
              cursor: 'pointer',
              background: 'var(--webcare-primary, #4f46e5)',
              color: '#ffffff',
              border: 'none',
              opacity: installingPreload ? 0.7 : 1
            }}
          >
            {installingPreload ? <Loader2 size={15} className="webcare-spin" /> : <Zap size={15} />}
            {isPreloadActive ? 'Re-Compile Micro-WAF' : 'Compile & Install Micro-WAF'}
          </button>
        </div>

        {preloadResult && (
          <div style={{ marginTop: '14px', padding: '10px 14px', borderRadius: '8px', background: preloadResult.success ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)', border: `1px solid ${preloadResult.success ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`, display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: preloadResult.success ? '#059669' : '#dc2626' }}>
            {preloadResult.success ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
            {preloadResult.message}
          </div>
        )}
      </div>

      {/* Core WAF Toggles */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
          Core Perimeter Inspection Modules
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px' }}>
          {coreToggles.map((item) => {
            const isChecked = (firewallToggles as any)[item.key];
            return (
              <label
                key={item.key}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '12px',
                  padding: '16px',
                  borderRadius: '10px',
                  background: isChecked ? 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.03))' : 'var(--webcare-bg-panel, #ffffff)',
                  border: isChecked ? '1px solid var(--webcare-primary, #4f46e5)' : '1px solid var(--webcare-border, #e2e8f0)',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease'
                }}
              >
                <input
                  type="checkbox"
                  checked={isChecked}
                  onChange={(e) => {
                    const checked = e.target.checked;
                    setFirewallToggles((prev) => ({ ...prev, [item.key]: checked }));
                  }}
                  style={{ marginTop: '3px', accentColor: 'var(--webcare-primary, #4f46e5)' }}
                />
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                      {item.title}
                    </div>
                    <span style={{ fontSize: '10px', fontWeight: 700, color: 'var(--webcare-primary, #4f46e5)', background: 'var(--webcare-bg-elevated, #f1f5f9)', padding: '2px 6px', borderRadius: '4px' }}>
                      {item.badge}
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.4, marginTop: '4px' }}>
                    {item.desc}
                  </div>
                </div>
              </label>
            );
          })}
        </div>

        {/* RASP Rule #44 Module */}
        <label
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '12px',
            padding: '16px',
            borderRadius: '10px',
            background: wafAdvanced.waf_rasp_enabled ? 'rgba(16, 185, 129, 0.03)' : 'var(--webcare-bg-panel, #ffffff)',
            border: wafAdvanced.waf_rasp_enabled ? '1px solid #10b981' : '1px solid var(--webcare-border, #e2e8f0)',
            cursor: 'pointer',
            marginTop: '4px'
          }}
        >
          <input
            type="checkbox"
            checked={wafAdvanced.waf_rasp_enabled}
            onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, waf_rasp_enabled: e.target.checked }))}
            style={{ marginTop: '3px', accentColor: '#10b981' }}
          />
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Runtime Application Self-Protection (RASP Rule #44)
              </div>
              <span style={{ fontSize: '10px', fontWeight: 700, color: '#059669', background: 'rgba(16, 185, 129, 0.1)', padding: '2px 6px', borderRadius: '4px' }}>
                Zero-Day Shield
              </span>
            </div>
            <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.4, marginTop: '4px' }}>
              Deep-inspects PHP execution sinks (e.g. <code>system</code>, <code>eval</code>, <code>passthru</code>, <code>unserialize</code>) to neutralize zero-day remote code execution exploits before execution.
            </div>
          </div>
        </label>
      </div>

      {/* Developer Deep Dive: Learning Mode, Sliders & Country Blocking */}
      <DeveloperDeepDive
        title="Developer Controls: Learning Mode, 404 Velocity Sliders & Geo-Blocking"
        badge="SettingsManager::waf_settings"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
          {/* Learning Mode */}
          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={wafAdvanced.waf_learning_mode}
              onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, waf_learning_mode: e.target.checked }))}
              style={{ marginTop: '2px', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)' }}>
                24-Hour Monitor-Only Learning Mode (<code>waf_learning_mode</code>)
              </div>
              <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
                Logs suspicious traffic and attacks without blocking client requests. Ideal for testing new e-commerce stores before full enforcement.
              </div>
            </div>
          </label>

          {/* 404 Velocity Slider */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)' }}>
                404 Probe Lockout Threshold (<code>waf_max_404_per_minute</code>):
              </label>
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-primary, #4f46e5)' }}>
                {wafAdvanced.waf_max_404_per_minute} errors / min
              </span>
            </div>
            <input
              type="range"
              min={5}
              max={100}
              step={5}
              value={wafAdvanced.waf_max_404_per_minute}
              onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, waf_max_404_per_minute: parseInt(e.target.value, 10) }))}
              style={{ width: '100%', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
          </div>

          {/* Lockout Duration Slider */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)' }}>
                IP Lockout Duration (<code>waf_lockout_duration_mins</code>):
              </label>
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-primary, #4f46e5)' }}>
                {wafAdvanced.waf_lockout_duration_mins} minutes
              </span>
            </div>
            <input
              type="range"
              min={5}
              max={1440}
              step={15}
              value={wafAdvanced.waf_lockout_duration_mins}
              onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, waf_lockout_duration_mins: parseInt(e.target.value, 10) }))}
              style={{ width: '100%', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
          </div>

          {/* Geo Blocking */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '4px' }}>
                Blocked ISO Country Codes (comma-separated):
              </label>
              <input
                type="text"
                placeholder="e.g. RU, CN, KP"
                value={wafAdvanced.waf_blocked_countries}
                onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, waf_blocked_countries: e.target.value }))}
                className="webcare-firewall-input"
                style={{ width: '100%', padding: '8px 12px', fontSize: '12px', borderRadius: '6px' }}
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '4px' }}>
                Country Block Scope:
              </label>
              <select
                value={wafAdvanced.waf_geo_block_mode}
                onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, waf_geo_block_mode: e.target.value }))}
                className="webcare-input"
                style={{ width: '100%', padding: '8px 12px', fontSize: '12px', borderRadius: '6px' }}
              >
                <option value="admin_only">Block wp-login.php &amp; wp-admin only (Recommended)</option>
                <option value="entire_site">Block Entire Website (Public Frontend)</option>
              </select>
            </div>
          </div>
        </div>
      </DeveloperDeepDive>
    </div>
  );
};
