import React, { useState } from 'react';
import {
  FileText,
  Search,
  Sparkles,
  ShieldCheck,
  Plus,
  Trash2,
  Lock,
  Globe,
  Sliders,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import { PRESET_TEMPLATES, PresetTemplate } from '../../TargetedAllowlistManagerCard';

interface Step07Props {
  status: any;
  targetedRules: any[];
  setTargetedRules: React.Dispatch<React.SetStateAction<any[]>>;
  wafAdvanced: any;
  setWafAdvanced: React.Dispatch<React.SetStateAction<any>>;
}

export const Step07BypassSeoBots: React.FC<Step07Props> = ({
  status,
  targetedRules,
  setTargetedRules,
  wafAdvanced,
  setWafAdvanced,
}) => {
  const [presetCategory, setPresetCategory] = useState<string>('All');
  const [presetSearch, setPresetSearch] = useState<string>('');
  const [newRuleName, setNewRuleName] = useState<string>('');
  const [newRuleUa, setNewRuleUa] = useState<string>('');
  const [newRuleEndpoint, setNewRuleEndpoint] = useState<string>('');

  const activeSlugs = status?.active_plugin_slugs || [];

  // Filter detected templates
  const detectedPresets = PRESET_TEMPLATES.filter((p) => {
    if (!p.plugin_slugs) return false;
    return p.plugin_slugs.some((slug) => activeSlugs.includes(slug));
  });

  const isPresetRuleAdded = (preset: PresetTemplate) => {
    const pName = (preset.name || '').toLowerCase();
    const pRuleName = (preset.rule && preset.rule.name ? preset.rule.name : '').toLowerCase();
    return targetedRules.some((r: any) => {
      const rName = (r.name || '').toLowerCase();
      return rName === pRuleName || rName === pName || (pName && rName.includes(pName));
    });
  };

  const handleTogglePreset = (preset: PresetTemplate) => {
    if (isPresetRuleAdded(preset)) {
      const pName = (preset.name || '').toLowerCase();
      const pRuleName = (preset.rule && preset.rule.name ? preset.rule.name : '').toLowerCase();
      setTargetedRules(targetedRules.filter((r: any) => {
        const rName = (r.name || '').toLowerCase();
        return rName !== pRuleName && rName !== pName && !rName.includes(pName);
      }));
    } else {
      const uniqueSlug = (preset.plugin_slugs && preset.plugin_slugs[0]) || preset.name.toLowerCase().replace(/[^a-z0-9]/g, '_');
      const newRule = {
        id: 'rule_' + uniqueSlug + '_' + Date.now().toString(36),
        name: preset.rule.name,
        enabled: true,
        user_agents: preset.rule.user_agents,
        endpoints: preset.rule.endpoints,
        methods: preset.rule.methods || ['ALL'],
        description: preset.rule.description,
        created_at: new Date().toISOString()
      };
      setTargetedRules([...targetedRules, newRule]);
    }
  };

  const handleEnableAllDetected = () => {
    const newlyAdded: any[] = [];
    detectedPresets.forEach((preset, idx) => {
      if (!isPresetRuleAdded(preset)) {
        const uniqueSlug = (preset.plugin_slugs && preset.plugin_slugs[0]) || preset.name.toLowerCase().replace(/[^a-z0-9]/g, '_');
        newlyAdded.push({
          id: 'rule_' + uniqueSlug + '_' + (Date.now() + idx).toString(36),
          name: preset.rule.name,
          enabled: true,
          user_agents: preset.rule.user_agents,
          endpoints: preset.rule.endpoints,
          methods: preset.rule.methods || ['ALL'],
          description: preset.rule.description,
          created_at: new Date().toISOString()
        });
      }
    });
    if (newlyAdded.length > 0) {
      setTargetedRules([...targetedRules, ...newlyAdded]);
    }
  };

  const handleAddCustom = () => {
    if (!newRuleName.trim() || !newRuleEndpoint.trim()) return;
    const newRule = {
      id: 'rule_custom_' + Date.now().toString(36),
      name: newRuleName.trim(),
      user_agents: newRuleUa ? newRuleUa.split('\n').map((s) => s.trim()).filter(Boolean) : ['*'],
      endpoints: newRuleEndpoint.split('\n').map((s) => s.trim()).filter(Boolean),
      methods: ['ALL'],
      enabled: true,
      created_at: new Date().toISOString()
    };
    setTargetedRules([...targetedRules, newRule]);
    setNewRuleName('');
    setNewRuleUa('');
    setNewRuleEndpoint('');
  };

  const filteredPresets = PRESET_TEMPLATES.filter((p) => {
    if (presetCategory !== 'All' && p.category !== presetCategory) return false;
    if (presetSearch) {
      const q = presetSearch.toLowerCase();
      return (
        p.name.toLowerCase().includes(q) ||
        (p.description && p.description.toLowerCase().includes(q)) ||
        (p.badge && p.badge.toLowerCase().includes(q))
      );
    }
    return true;
  });

  return (
    <div className="webcare-wizard-step-container" style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
      {/* Step Header */}
      <div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '4px 10px', borderRadius: '20px', background: 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.08))', color: 'var(--webcare-primary, #4f46e5)', fontSize: '12px', fontWeight: 700, marginBottom: '12px' }}>
          <FileText size={14} /> Phase 2: Multi-Layer Perimeter WAF
        </div>
        <h1 style={{ margin: '0 0 10px 0', fontSize: '24px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
          Zero-Trust Webhook Bypass &amp; 3-Tier SEO Bots
        </h1>
        <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--webcare-text-secondary, #475569)', margin: 0 }}>
          Safely whitelist legitimate external webhooks (Stripe, PayPal, HubSpot, Zapier) and govern search engine crawlers with strict read-only jail policies.
        </p>
      </div>

      {/* 3-Tier SEO & Bot Governance Card */}
      <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '12px' }}>
          3-Tier Search Engine &amp; Crawler Governance
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px', marginBottom: '14px' }}>
          {/* Tier 1 Card */}
          <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', fontWeight: 700, color: '#059669', marginBottom: '4px' }}>
              <ShieldCheck size={16} /> Tier 1: Search Engines (FCrDNS Verified)
            </div>
            <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.4 }}>
              Googlebot, Bingbot, Applebot, and DuckDuckBot are always allowed on public pages with cryptographic reverse-DNS verification.
            </div>
          </div>

          {/* Tier 2 & 3 Card */}
          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', padding: '14px', borderRadius: '8px', background: wafAdvanced.waf_allow_seo_bots ? 'rgba(79, 70, 229, 0.04)' : 'var(--webcare-bg-elevated, #f8fafc)', border: wafAdvanced.waf_allow_seo_bots ? '1px solid var(--webcare-primary, #4f46e5)' : '1px solid var(--webcare-border, #e2e8f0)', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={wafAdvanced.waf_allow_seo_bots}
              onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, waf_allow_seo_bots: e.target.checked }))}
              style={{ marginTop: '2px', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <div>
              <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Allow Tier 2 SEO Audit Suites (Ahrefs, Semrush, Moz)
              </div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px', lineHeight: 1.4 }}>
                Permits verified SEO audit crawlers on read-only public GET/HEAD requests.
              </div>
            </div>
          </label>
        </div>

        {/* Read-Only Crawl Jail Guarantee */}
        <div style={{ padding: '10px 14px', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.2)', fontSize: '11px', color: '#047857', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Lock size={14} />
          <strong>Strict Crawl Jail Active:</strong> Any crawler attempting mutations (POST/PUT/DELETE) or probing <code>/wp-login.php</code>, <code>/cart/</code>, or <code>/checkout/</code> is instantly blocked with HTTP 403.
        </div>
      </div>

      {/* Auto-Detected Webhook Presets Banner */}
      {detectedPresets.length > 0 && (
        <div style={{ padding: '16px 20px', borderRadius: '12px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px', flexWrap: 'wrap', gap: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
              <Sparkles size={16} color="var(--webcare-primary, #4f46e5)" />
              Auto-Detected Active Integrations ({detectedPresets.length} Found)
            </div>
            <button
              type="button"
              onClick={handleEnableAllDetected}
              style={{
                background: 'var(--webcare-primary, #4f46e5)',
                color: '#ffffff',
                border: 'none',
                padding: '6px 12px',
                borderRadius: '6px',
                fontSize: '11px',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              Enable All Auto-Detected
            </button>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
            {detectedPresets.map((preset) => {
              const isAdded = isPresetRuleAdded(preset);
              return (
                <button
                  key={preset.name}
                  type="button"
                  onClick={() => handleTogglePreset(preset)}
                  style={{
                    padding: '6px 12px',
                    borderRadius: '6px',
                    fontSize: '11px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    background: isAdded ? 'var(--webcare-primary, #4f46e5)' : 'var(--webcare-bg-panel, #ffffff)',
                    color: isAdded ? '#ffffff' : 'var(--webcare-text-title, #0f172a)',
                    border: isAdded ? '1px solid var(--webcare-primary, #4f46e5)' : '1px solid var(--webcare-border, #cbd5e1)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}
                >
                  {isAdded ? '✓ Enabled' : '+ Add'} {preset.name}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Preset Library & Custom Webhook Rule Builder */}
      <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
          <div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
              Enterprise Integration Library (30+ Presets)
            </div>
            <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)' }}>
              Select external services that call into your site without tripping WAF inspection.
            </div>
          </div>
          <input
            type="text"
            placeholder="Search integrations (e.g. Stripe, Zapier, Jetpack)..."
            value={presetSearch}
            onChange={(e) => setPresetSearch(e.target.value)}
            className="webcare-firewall-input"
            style={{ padding: '6px 12px', fontSize: '12px', borderRadius: '6px', width: '220px' }}
          />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '8px', maxHeight: '220px', overflowY: 'auto', paddingRight: '4px', marginBottom: '16px' }}>
          {filteredPresets.map((preset) => {
            const isAdded = isPresetRuleAdded(preset);
            return (
              <div
                key={preset.name}
                onClick={() => handleTogglePreset(preset)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '8px 10px',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  background: isAdded ? 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.05))' : 'var(--webcare-bg-elevated, #f8fafc)',
                  border: isAdded ? '1px solid var(--webcare-primary, #4f46e5)' : '1px solid var(--webcare-border, #e2e8f0)',
                  fontSize: '11px'
                }}
              >
                <div style={{ fontWeight: 600, color: isAdded ? 'var(--webcare-primary, #4f46e5)' : 'var(--webcare-text-title, #0f172a)' }}>
                  {preset.name}
                </div>
                <span style={{ fontSize: '10px', fontWeight: 700, color: isAdded ? 'var(--webcare-primary, #4f46e5)' : '#64748b' }}>
                  {isAdded ? '✓ Added' : '+ Add'}
                </span>
              </div>
            );
          })}
        </div>

        {/* Custom Rule Row */}
        <div style={{ borderTop: '1px solid var(--webcare-border, #e2e8f0)', paddingTop: '14px' }}>
          <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '8px' }}>
            Add Custom Webhook Bypass Rule:
          </div>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            <input
              type="text"
              placeholder="Rule Name (e.g. My Custom ERP Webhook)"
              value={newRuleName}
              onChange={(e) => setNewRuleName(e.target.value)}
              className="webcare-firewall-input"
              style={{ flex: '1 1 180px', padding: '6px 10px', fontSize: '12px', borderRadius: '6px' }}
            />
            <input
              type="text"
              placeholder="Endpoint URI (e.g. /wp-json/erp/v1/webhook)"
              value={newRuleEndpoint}
              onChange={(e) => setNewRuleEndpoint(e.target.value)}
              className="webcare-firewall-input"
              style={{ flex: '1 1 200px', padding: '6px 10px', fontSize: '12px', borderRadius: '6px' }}
            />
            <button
              type="button"
              onClick={handleAddCustom}
              style={{
                background: 'var(--webcare-primary, #4f46e5)',
                color: '#ffffff',
                border: 'none',
                padding: '6px 14px',
                borderRadius: '6px',
                fontSize: '12px',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              + Add Rule
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
