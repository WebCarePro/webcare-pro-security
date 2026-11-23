import React, { useState } from 'react';
import {
  Globe,
  Zap,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
  Loader2,
  Lock,
  Sliders,
  ShieldCheck,
  Activity,
  Save,
  Trash2,
  Eye,
  EyeOff
} from 'lucide-react';
import { DeveloperDeepDive } from '../DeveloperDeepDive';
import { apiRequest } from '../../../utils/api';
import { confirmAction } from '../../ui/ConfirmModal';

interface Step08Props {
  status: any;
  cfToken: string;
  setCfToken: (token: string) => void;
  cfZone: string;
  setCfZone: (zone: string) => void;
  wafAdvanced: any;
  setWafAdvanced: React.Dispatch<React.SetStateAction<any>>;
}

export const Step08CloudflareEdge: React.FC<Step08Props> = ({
  status,
  cfToken,
  setCfToken,
  cfZone,
  setCfZone,
  wafAdvanced,
  setWafAdvanced,
}) => {
  const [verifying, setVerifying] = useState(false);
  const [saving, setSaving] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [showToken, setShowToken] = useState(false);
  const [deployingRules, setDeployingRules] = useState(false);
  const [verifyMsg, setVerifyMsg] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);
  const [deployMsg, setDeployMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const cfStatus = status?.cloudflare_status || {};
  const isCfConnected = !!(cfStatus.has_saved_token || (cfToken && cfToken !== '••••••••' && cfToken.trim().length > 10));

  const handleSaveCredentials = async () => {
    const token = cfToken.trim();
    if (!token && !cfStatus.has_saved_token) {
      setVerifyMsg({ type: 'error', text: 'Please enter a Cloudflare API Token before saving.' });
      return;
    }

    setSaving(true);
    setVerifyMsg(null);
    try {
      const tokenToSave = (token && token !== '••••••••') ? token : undefined;
      const zoneToSave = cfZone.trim() || undefined;

      const res = await apiRequest({
        path: '/settings',
        method: 'POST',
        data: {
          cloudflare_enabled: true,
          ...(tokenToSave ? { cloudflare_api_token: tokenToSave } : {}),
          ...(zoneToSave ? { cloudflare_zone_id: zoneToSave } : {}),
          cloudflare_auto_sync_bans: true,
        }
      });

      if (res && res.success !== false) {
        if (cfStatus) {
          cfStatus.has_saved_token = true;
          if (zoneToSave) cfStatus.zone_id = zoneToSave;
        }
        setCfToken('••••••••');
        setVerifyMsg({
          type: 'success',
          text: 'Cloudflare API Token & Zone ID saved securely in the Secret Vault!'
        });
      } else {
        setVerifyMsg({
          type: 'error',
          text: res?.message || 'Failed to save Cloudflare settings.'
        });
      }
    } catch (e: any) {
      setVerifyMsg({ type: 'error', text: e?.message || 'Failed to save Cloudflare settings.' });
    } finally {
      setSaving(false);
    }
  };

  const handleVerify = async () => {
    const token = cfToken.trim();
    if (!token && !cfStatus.has_saved_token) {
      setVerifyMsg({ type: 'error', text: 'Please enter your Cloudflare API Token to verify.' });
      return;
    }

    setVerifying(true);
    setVerifyMsg(null);
    try {
      const res = await apiRequest({
        path: '/cloudflare/verify',
        method: 'POST',
        data: {
          token: token !== '••••••••' ? token : undefined,
          zone_id: cfZone.trim() || undefined
        }
      });

      if (res && res.success) {
        const resolvedZone = (res.zone_id || cfZone).trim();
        if (resolvedZone) setCfZone(resolvedZone);

        // Automatically persist verified credentials to Secret Vault & Settings
        try {
          const tokenToSave = (token && token !== '••••••••') ? token : undefined;
          await apiRequest({
            path: '/settings',
            method: 'POST',
            data: {
              cloudflare_enabled: true,
              ...(tokenToSave ? { cloudflare_api_token: tokenToSave } : {}),
              ...(resolvedZone ? { cloudflare_zone_id: resolvedZone } : {}),
              cloudflare_auto_sync_bans: true,
            }
          });
          if (cfStatus) {
            cfStatus.has_saved_token = true;
            if (resolvedZone) cfStatus.zone_id = resolvedZone;
          }
          setCfToken('••••••••');
        } catch (saveErr) {
          console.error('Failed to auto-save verified credentials', saveErr);
        }

        setVerifyMsg({
          type: 'success',
          text: `Verified & Saved: Connected to zone "${res.zone_name || status?.site_domain || 'Active'}" (${res.plan || 'Free'} plan). API Token and Zone ID saved in Vault!`
        });
      } else {
        setVerifyMsg({
          type: 'error',
          text: res?.message || 'Could not verify token. Ensure permissions: "Zone:Read" & "Zone WAF:Edit".'
        });
      }
    } catch (e: any) {
      setVerifyMsg({ type: 'error', text: e?.message || 'Failed to verify Cloudflare token.' });
    } finally {
      setVerifying(false);
    }
  };

  const handleDisconnect = async () => {
    const confirmed = await confirmAction({
      title: 'Disconnect Cloudflare Integration',
      message: 'Are you sure you want to disconnect Cloudflare? This will remove the API Token and Zone ID from the database vault.',
      confirmLabel: 'Disconnect',
      variant: 'danger',
    });
    if (!confirmed) {
      return;
    }
    setDisconnecting(true);
    setVerifyMsg(null);
    try {
      const res = await apiRequest({
        path: '/cloudflare/disconnect',
        method: 'POST'
      });
      if (res && res.success !== false) {
        setCfToken('');
        setCfZone('');
        if (cfStatus) {
          cfStatus.has_saved_token = false;
          cfStatus.zone_id = '';
        }
        setVerifyMsg({
          type: 'info',
          text: 'Cloudflare disconnected and credentials wiped from Secret Vault.'
        });
      } else {
        setVerifyMsg({
          type: 'error',
          text: res?.message || 'Failed to disconnect Cloudflare.'
        });
      }
    } catch (e: any) {
      setVerifyMsg({ type: 'error', text: e?.message || 'Error disconnecting Cloudflare.' });
    } finally {
      setDisconnecting(false);
    }
  };

  const handleDeployRules = async () => {
    setDeployingRules(true);
    setDeployMsg(null);
    try {
      // Auto-persist credentials if user entered an unmasked token or zone ID
      const tokenToSave = (cfToken.trim() && cfToken !== '••••••••') ? cfToken.trim() : undefined;
      const zoneToSave = cfZone.trim() || undefined;
      if (tokenToSave || zoneToSave) {
        await apiRequest({
          path: '/settings',
          method: 'POST',
          data: {
            cloudflare_enabled: true,
            ...(tokenToSave ? { cloudflare_api_token: tokenToSave } : {}),
            ...(zoneToSave ? { cloudflare_zone_id: zoneToSave } : {}),
            cloudflare_auto_sync_bans: true,
          }
        });
        if (cfStatus) {
          cfStatus.has_saved_token = true;
          if (zoneToSave) cfStatus.zone_id = zoneToSave;
        }
        setCfToken('••••••••');
      }

      // Calls sync-cloudflare or deploy-rules
      const res = await apiRequest({
        path: '/caf/sync-cloudflare',
        method: 'POST'
      });
      if (res && res.success) {
        setDeployMsg({
          type: 'success',
          text: res.message || 'Successfully deployed 4 consolidated CAF edge rules to Cloudflare! Slot 5 is free.'
        });
      } else {
        setDeployMsg({
          type: 'error',
          text: res?.message || 'Could not deploy rules to Cloudflare. Check your token permissions.'
        });
      }
    } catch (e: any) {
      setDeployMsg({
        type: 'error',
        text: e?.message || 'Failed to trigger Cloudflare edge rule deployment.'
      });
    } finally {
      setDeployingRules(false);
    }
  };

  const slots = [
    { num: 1, name: 'WebCare CAF 1: Threat Reputation, Attack Tools & Aggressive Bots', action: 'BLOCK' },
    { num: 2, name: 'WebCare CAF 2: Sensitive Files, Credential Stores & Uploads PHP Lock', action: 'BLOCK' },
    { num: 3, name: 'WebCare CAF 3: Protocol Integrity, Loopback Spoofing & Perimeter Shield', action: 'CHALLENGE' },
    { num: 4, name: 'WebCare CAF 4: Context-Aware Dynamic Surface & Dormant Endpoint Lock', action: 'BLOCK' },
    { num: 5, name: 'Spare Slot Reserved Free for Site Owner Custom Rules', action: '1 FREE SLOT' },
  ];

  return (
    <div className="webcare-wizard-step-container" style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
      {/* Step Header */}
      <div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '4px 10px', borderRadius: '20px', background: 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.08))', color: 'var(--webcare-primary, #4f46e5)', fontSize: '12px', fontWeight: 700, marginBottom: '12px' }}>
          <Globe size={14} /> Phase 2: Multi-Layer Perimeter WAF
        </div>
        <h1 style={{ margin: '0 0 10px 0', fontSize: '24px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
          Cloudflare Edge Command Center ("4 + 1" Smart Rules)
        </h1>
        <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--webcare-text-secondary, #475569)', margin: 0 }}>
          Stop volumetric attacks, bad bots, and exploit scanners on Cloudflare's global edge network before traffic ever hits your origin server.
        </p>
      </div>

      {/* Cloudflare Connection Form */}
      <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
            Cloudflare API Authentication
          </div>
          <a
            href="https://dash.cloudflare.com/profile/api-tokens?name=WebCare%20Security%20Scanner&permissionGroupKeys=%5B%7B%22key%22%3A%22zone%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22zone_waf%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22firewall_services%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22analytics%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22cache%22%2C%22type%22%3A%22purge%22%7D%5D&accountId=*&zoneId=all"
            target="_blank"
            rel="noopener noreferrer"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-primary, #4f46e5)', textDecoration: 'none' }}
          >
            Create API Token ↗
          </a>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '14px', marginBottom: '16px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '4px' }}>
              API Token (Requires Zone:Read &amp; Zone WAF:Edit):
            </label>
            <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <input
                type={showToken ? 'text' : 'password'}
                placeholder={cfStatus.has_saved_token ? '•••••••• (Token Saved in SecretVault)' : 'Paste your Cloudflare API Token...'}
                value={cfToken}
                onChange={(e) => setCfToken(e.target.value)}
                className="webcare-firewall-input"
                style={{ width: '100%', padding: '8px 36px 8px 12px', fontSize: '13px', borderRadius: '8px', boxSizing: 'border-box' }}
              />
              <button
                type="button"
                onClick={() => setShowToken(!showToken)}
                title={showToken ? 'Hide Token' : 'Show Token'}
                aria-label={showToken ? 'Hide Token' : 'Show Token'}
                style={{
                  position: 'absolute',
                  right: '8px',
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  color: 'var(--webcare-text-muted, #64748b)',
                  padding: '4px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                {showToken ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '4px' }}>
              Zone ID (Auto-detected on verification):
            </label>
            <input
              type="text"
              placeholder="e.g. 023e105f4ecef8ad9ca31a8372d0c353"
              value={cfZone}
              onChange={(e) => setCfZone(e.target.value)}
              className="webcare-firewall-input"
              style={{ width: '100%', padding: '8px 12px', fontSize: '13px', borderRadius: '8px', boxSizing: 'border-box' }}
            />
          </div>
        </div>

        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'center' }}>
          <button
            type="button"
            onClick={handleSaveCredentials}
            disabled={saving || verifying || (!cfToken.trim() && !cfStatus.has_saved_token)}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 16px',
              borderRadius: '8px',
              fontSize: '13px',
              fontWeight: 700,
              cursor: 'pointer',
              background: '#10b981',
              color: '#ffffff',
              border: 'none',
              opacity: (saving || verifying || (!cfToken.trim() && !cfStatus.has_saved_token)) ? 0.7 : 1
            }}
          >
            {saving ? <Loader2 size={14} className="webcare-spin" /> : <Save size={14} />}
            Save API &amp; Zone ID
          </button>

          <button
            type="button"
            onClick={handleVerify}
            disabled={verifying || saving || (!cfToken.trim() && !cfStatus.has_saved_token)}
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
              border: 'none',
              opacity: (verifying || saving || (!cfToken.trim() && !cfStatus.has_saved_token)) ? 0.7 : 1
            }}
          >
            {verifying ? <Loader2 size={14} className="webcare-spin" /> : <ShieldCheck size={14} />}
            Verify Token &amp; Auto-Detect Zone
          </button>

          {(cfStatus.has_saved_token || cfToken === '••••••••' || (cfToken && cfToken.length > 10)) && (
            <button
              type="button"
              onClick={handleDisconnect}
              disabled={disconnecting}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '8px 14px',
                borderRadius: '8px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
                background: 'transparent',
                color: '#dc2626',
                border: '1px solid rgba(220, 38, 38, 0.3)',
                opacity: disconnecting ? 0.6 : 1,
                marginLeft: 'auto'
              }}
            >
              {disconnecting ? <Loader2 size={13} className="webcare-spin" /> : <Trash2 size={13} />}
              Disconnect / Clear
            </button>
          )}
        </div>

        {verifyMsg && (
          <div style={{
            marginTop: '14px',
            padding: '10px 14px',
            borderRadius: '8px',
            background: verifyMsg.type === 'success' ? 'rgba(16, 185, 129, 0.1)' : (verifyMsg.type === 'info' ? 'rgba(99, 102, 241, 0.1)' : 'rgba(239, 68, 68, 0.1)'),
            border: `1px solid ${verifyMsg.type === 'success' ? 'rgba(16, 185, 129, 0.3)' : (verifyMsg.type === 'info' ? 'rgba(99, 102, 241, 0.3)' : 'rgba(239, 68, 68, 0.3)')}`,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '12px',
            color: verifyMsg.type === 'success' ? '#059669' : (verifyMsg.type === 'info' ? '#4f46e5' : '#dc2626')
          }}>
            {verifyMsg.type === 'success' ? <CheckCircle2 size={16} /> : (verifyMsg.type === 'info' ? <Activity size={16} /> : <AlertCircle size={16} />)}
            {verifyMsg.text}
          </div>
        )}
      </div>

      {/* Cloudflare 4+1 WAF Rule Visualizer */}
      <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
          <div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
              Cloudflare Free Plan "4 + 1" Rule Budget Visualizer
            </div>
            <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
              Free Cloudflare accounts allow exactly 5 custom WAF rules. WebCare utilizes exactly 4 slots, leaving 1 slot 100% free for your custom rules.
            </div>
          </div>
          <button
            type="button"
            onClick={handleDeployRules}
            disabled={deployingRules || (!cfToken.trim() && !cfStatus.has_saved_token)}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 16px',
              borderRadius: '8px',
              fontSize: '12px',
              fontWeight: 700,
              cursor: 'pointer',
              background: '#059669',
              color: '#ffffff',
              border: 'none',
              opacity: (deployingRules || (!cfToken.trim() && !cfStatus.has_saved_token)) ? 0.6 : 1
            }}
          >
            {deployingRules ? <Loader2 size={14} className="webcare-spin" /> : <Zap size={14} />}
            Deploy 4 Smart Edge Rules Now
          </button>
        </div>

        {deployMsg && (
          <div style={{ marginBottom: '14px', padding: '10px 14px', borderRadius: '8px', background: deployMsg.type === 'success' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)', border: `1px solid ${deployMsg.type === 'success' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`, display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: deployMsg.type === 'success' ? '#059669' : '#dc2626' }}>
            {deployMsg.type === 'success' ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
            {deployMsg.text}
          </div>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {slots.map((slot) => {
            const isSpare = slot.num === 5;
            return (
              <div
                key={slot.num}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '10px 14px',
                  borderRadius: '8px',
                  background: isSpare ? 'rgba(16, 185, 129, 0.05)' : 'var(--webcare-bg-panel, #ffffff)',
                  border: isSpare ? '1px dashed #10b981' : '1px solid var(--webcare-border, #cbd5e1)',
                  fontSize: '12px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontWeight: 800, color: isSpare ? '#059669' : 'var(--webcare-primary, #4f46e5)' }}>
                    Slot {slot.num}:
                  </span>
                  <span style={{ fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)' }}>
                    {slot.name}
                  </span>
                </div>
                <span
                  style={{
                    fontSize: '10px',
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: '4px',
                    background: isSpare ? 'rgba(16, 185, 129, 0.15)' : 'rgba(79, 70, 229, 0.1)',
                    color: isSpare ? '#059669' : 'var(--webcare-primary, #4f46e5)',
                  }}
                >
                  {slot.action}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Developer Deep Dive: Auto-Ban Sync & DDoS Threshold */}
      <DeveloperDeepDive
        title="Developer Controls: 0ms Edge IP Auto-Ban Sync & L7 Circuit Breaker"
        badge="SettingsManager::cf_settings"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={wafAdvanced.cf_auto_ban_sync}
              onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, cf_auto_ban_sync: e.target.checked }))}
              style={{ marginTop: '2px', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)' }}>
                Edge IP Auto-Ban Synchronization (<code>cf_auto_ban_sync</code>)
              </div>
              <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
                When repeat attackers or zero-day webshell uploaders are blocked locally, WebCare immediately pushes their IP to Cloudflare Edge IP Access Rules so repeat hits are dropped with <strong>0ms origin load</strong>.
              </div>
            </div>
          </label>

          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={wafAdvanced.cf_ddos_protection_enabled}
              onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, cf_ddos_protection_enabled: e.target.checked }))}
              style={{ marginTop: '2px', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)' }}>
                Origin Survival Circuit Breaker (<code>cf_ddos_protection_enabled</code>)
              </div>
              <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
                Automatically enables Cloudflare "Under Attack" challenge mode when incoming request velocity exceeds origin capacity.
              </div>
            </div>
          </label>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)' }}>
                DDoS Trigger Velocity Threshold (<code>cf_ddos_threshold</code>):
              </label>
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-primary, #4f46e5)' }}>
                {wafAdvanced.cf_ddos_threshold || 100} requests / min
              </span>
            </div>
            <input
              type="range"
              min={50}
              max={1000}
              step={50}
              value={wafAdvanced.cf_ddos_threshold || 100}
              onChange={(e) => setWafAdvanced((prev: any) => ({ ...prev, cf_ddos_threshold: parseInt(e.target.value, 10) }))}
              style={{ width: '100%', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
          </div>
        </div>
      </DeveloperDeepDive>
    </div>
  );
};
