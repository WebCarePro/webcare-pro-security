import React from 'react';
import {
  CheckCircle2,
  ShieldCheck,
  Zap,
  Globe,
  Lock,
  Radar,
  ArrowRight,
  Download,
  Trash2,
  HardDrive,
  Activity,
  Sparkles,
  Server
} from 'lucide-react';
import { DeveloperDeepDive } from '../DeveloperDeepDive';

interface Step14Props {
  postureScore: number;
  controlsArmed: number;
  archetype: string;
  isCfActive: boolean;
  isPreloadActive: boolean;
  onLaunchAudit: () => void;
  onOpenDashboard: () => void;
  onExportBlueprint: () => void;
  saving: boolean;
  governanceSettings: {
    logRetentionDays: number;
    tamperWebhookUrl: string;
    deleteDataOnUninstall: boolean;
    dropTablesOnUninstall: boolean;
    deleteOptionsOnUninstall: boolean;
  };
  setGovernanceSettings: React.Dispatch<React.SetStateAction<any>>;
}

export const Step14LedgerLaunch: React.FC<Step14Props> = ({
  postureScore,
  controlsArmed,
  archetype,
  isCfActive,
  isPreloadActive,
  onLaunchAudit,
  onOpenDashboard,
  onExportBlueprint,
  saving,
  governanceSettings,
  setGovernanceSettings,
}) => {
  return (
    <div className="webcare-wizard-step-container" style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
      {/* Step Header */}
      <div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '4px 10px', borderRadius: '20px', background: 'rgba(16, 185, 129, 0.1)', color: '#059669', fontSize: '12px', fontWeight: 700, marginBottom: '12px' }}>
          <CheckCircle2 size={14} /> Phase 4: Scanner &amp; SOC Telemetry
        </div>
        <h1 style={{ margin: '0 0 10px 0', fontSize: '24px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
          Security Readiness Audit &amp; System Launch
        </h1>
        <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--webcare-text-secondary, #475569)', margin: 0 }}>
          Review your configured perimeter defenses, audit log retention, and launch your baseline cryptographic security audit.
        </p>
      </div>

      {/* Posture Score Hero Card */}
      <div
        style={{
          padding: '24px',
          borderRadius: '16px',
          background: 'linear-gradient(135deg, rgba(79, 70, 229, 0.08) 0%, rgba(16, 185, 129, 0.08) 100%)',
          border: '1px solid var(--webcare-border, #cbd5e1)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '20px'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '18px' }}>
          <div
            style={{
              width: '64px',
              height: '64px',
              borderRadius: '50%',
              background: 'linear-gradient(135deg, #4f46e5 0%, #10b981 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#ffffff',
              fontSize: '22px',
              fontWeight: 900,
              boxShadow: '0 8px 20px rgba(79, 70, 229, 0.25)'
            }}
          >
            {postureScore >= 90 ? 'A+' : postureScore >= 80 ? 'A' : 'B'}
          </div>
          <div>
            <div style={{ fontSize: '18px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
              Security Posture Score: {postureScore} / 100
            </div>
            <div style={{ fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
              <strong>{controlsArmed} Automated Controls Armed</strong> across Perimeter WAF, Cloudflare Edge, Identity &amp; Scanner.
            </div>
          </div>
        </div>

        <button
          type="button"
          onClick={onExportBlueprint}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            padding: '8px 14px',
            borderRadius: '8px',
            fontSize: '12px',
            fontWeight: 700,
            cursor: 'pointer',
            background: 'var(--webcare-bg-panel, #ffffff)',
            color: 'var(--webcare-text-title, #0f172a)',
            border: '1px solid var(--webcare-border, #cbd5e1)'
          }}
        >
          <Download size={14} /> Export Blueprint (.json)
        </button>
      </div>

      {/* 4-Pillar Readiness Summary */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px' }}>
        <div style={{ padding: '16px', borderRadius: '12px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', fontWeight: 700, color: 'var(--webcare-primary, #4f46e5)', marginBottom: '8px' }}>
            <Zap size={16} /> Perimeter WAF
          </div>
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.6, display: 'flex', flexDirection: 'column', gap: '3px' }}>
            <div>• Pre-Boot Micro-WAF: {isPreloadActive ? 'Active' : 'Compiled'}</div>
            <div>• Virtual Patching: Active</div>
            <div>• RASP Rule #44: Armed</div>
            <div>• Archetype: {archetype.toUpperCase()}</div>
          </div>
        </div>

        <div style={{ padding: '16px', borderRadius: '12px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', fontWeight: 700, color: '#0284c7', marginBottom: '8px' }}>
            <Globe size={16} /> Cloudflare Edge
          </div>
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.6, display: 'flex', flexDirection: 'column', gap: '3px' }}>
            <div>• Edge Rules: 4 Consolidated</div>
            <div>• Slot 5: 100% Free Slot</div>
            <div>• Auto-Ban Sync: Active</div>
            <div>• Status: {isCfActive ? 'Connected' : 'Optional / Standby'}</div>
          </div>
        </div>

        <div style={{ padding: '16px', borderRadius: '12px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', fontWeight: 700, color: '#059669', marginBottom: '8px' }}>
            <Lock size={16} /> Identity &amp; OS
          </div>
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.6, display: 'flex', flexDirection: 'column', gap: '3px' }}>
            <div>• Brute-Force Shield: Active</div>
            <div>• Honeypot Traps: Armed</div>
            <div>• 2FA / WebAuthn: Configured</div>
            <div>• Server Armor: Deployed</div>
          </div>
        </div>

        <div style={{ padding: '16px', borderRadius: '12px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', fontWeight: 700, color: '#ea580c', marginBottom: '8px' }}>
            <Radar size={16} /> Scanner &amp; SOC
          </div>
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.6, display: 'flex', flexDirection: 'column', gap: '3px' }}>
            <div>• 14 Deep Passes: Enabled</div>
            <div>• Core Auto-Repair: Armed</div>
            <div>• Auto-Quarantine: Active</div>
            <div>• Alerts: Multi-Channel</div>
          </div>
        </div>
      </div>

      {/* Primary Launch Action Buttons */}
      <div style={{ display: 'flex', gap: '14px', flexWrap: 'wrap' }}>
        <button
          type="button"
          onClick={onLaunchAudit}
          disabled={saving}
          style={{
            flex: '1 1 280px',
            padding: '16px 24px',
            borderRadius: '12px',
            fontSize: '15px',
            fontWeight: 800,
            cursor: 'pointer',
            background: 'linear-gradient(135deg, #4f46e5 0%, #4338ca 100%)',
            color: '#ffffff',
            border: 'none',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '10px',
            boxShadow: '0 8px 24px rgba(79, 70, 229, 0.25)',
            opacity: saving ? 0.7 : 1
          }}
        >
          <Sparkles size={18} />
          {saving ? 'Persisting Configuration...' : 'Save Everything & Launch Baseline Security Audit'}
        </button>

        <button
          type="button"
          onClick={onOpenDashboard}
          disabled={saving}
          style={{
            flex: '1 1 240px',
            padding: '16px 24px',
            borderRadius: '12px',
            fontSize: '14px',
            fontWeight: 700,
            cursor: 'pointer',
            background: 'var(--webcare-bg-panel, #ffffff)',
            color: 'var(--webcare-text-title, #0f172a)',
            border: '1px solid var(--webcare-border, #cbd5e1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px',
            opacity: saving ? 0.7 : 1
          }}
        >
          <CheckCircle2 size={16} color="#059669" />
          Save &amp; Open Security Dashboard
        </button>
      </div>

      {/* Developer Deep Dive: Audit Ledger & Retention Governance */}
      <DeveloperDeepDive
        title="Developer Controls: Cryptographic Audit Ledger & Data Governance"
        badge="SettingsManager::data_governance"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '4px' }}>
              Audit Log Retention Window:
            </label>
            <select
              value={governanceSettings.logRetentionDays || 30}
              onChange={(e) => setGovernanceSettings((prev: any) => ({ ...prev, logRetentionDays: parseInt(e.target.value, 10) }))}
              className="webcare-input"
              style={{ width: '100%', maxWidth: '240px', padding: '6px 12px', fontSize: '12px', borderRadius: '6px' }}
            >
              <option value={14}>14 Days</option>
              <option value={30}>30 Days (Default)</option>
              <option value={60}>60 Days</option>
              <option value={90}>90 Days (SOC 2 Baseline)</option>
              <option value={180}>180 Days (PCI-DSS)</option>
              <option value={365}>365 Days (1 Year)</option>
            </select>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
              Plugin Uninstallation &amp; Data Cleanup Policy:
            </div>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', cursor: 'pointer', color: 'var(--webcare-text-title, #0f172a)' }}>
              <input
                type="checkbox"
                checked={governanceSettings.deleteDataOnUninstall}
                onChange={(e) => setGovernanceSettings((prev: any) => ({ ...prev, deleteDataOnUninstall: e.target.checked }))}
                style={{ accentColor: 'var(--webcare-primary, #4f46e5)' }}
              />
              <span>Delete all WebCare Pro data, logs, and quarantined files on plugin deletion</span>
            </label>

            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', cursor: 'pointer', color: 'var(--webcare-text-title, #0f172a)' }}>
              <input
                type="checkbox"
                checked={governanceSettings.dropTablesOnUninstall}
                onChange={(e) => setGovernanceSettings((prev: any) => ({ ...prev, dropTablesOnUninstall: e.target.checked }))}
                style={{ accentColor: 'var(--webcare-primary, #4f46e5)' }}
              />
              <span>Drop custom database tables (webcareproscan_*) upon uninstallation</span>
            </label>
          </div>
        </div>
      </DeveloperDeepDive>
    </div>
  );
};
