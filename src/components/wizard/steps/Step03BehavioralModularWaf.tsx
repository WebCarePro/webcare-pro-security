import React, { useState, useEffect } from '@wordpress/element';
import {
  Radar,
  Play,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Shield,
  Layers,
  Terminal,
  FileCode,
  Zap,
  Lock,
  Eye,
  Check,
  X,
  Loader2,
  Download,
  Sliders,
  Sparkles,
  ExternalLink
} from 'lucide-react';
import { apiRequest } from '../../../utils/api';
import { useBehavioralScanRunner } from '../../../utils/scanTelemetry';
import { BehavioralScanProgressPanel } from '../../BehavioralScanProgressPanel';
import { DeveloperDeepDive } from '../DeveloperDeepDive';

interface ModularRule {
  id: string;
  category: string;
  title: string;
  description: string;
  origin_component: string;
  file?: string;
  line?: number;
  evidence?: string;
  severity: string;
  recommended_mode: 'enforce' | 'smart_learning' | 'monitor' | 'off';
  current_mode: 'enforce' | 'smart_learning' | 'monitor' | 'off';
  target_uri?: string;
  target_param?: string;
  target_value?: string;
  rate_limit?: number;
  block_uploads?: boolean;
  sync_cloudflare?: boolean;
}

interface Step03Props {
  status: any;
  onRefreshStatus?: () => Promise<void>;
  onContinueInBackground?: () => void;
}

export const Step03BehavioralModularWaf: React.FC<Step03Props> = ({
  status,
  onRefreshStatus,
  onContinueInBackground,
}) => {
  const [rules, setRules] = useState<ModularRule[]>([]);
  const [vaultSummary, setVaultSummary] = useState<any>(null);
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [selectedSnippet, setSelectedSnippet] = useState<{
    ruleId: string;
    file: string;
    line: number;
    lines: Array<{ number: number; code: string; is_target: boolean }>;
    loading: boolean;
    error?: string;
  } | null>(null);
  const [togglingRule, setTogglingRule] = useState<string | null>(null);
  const [bulkApplying, setBulkApplying] = useState(false);
  const [bulkSuccessMsg, setBulkSuccessMsg] = useState<string | null>(null);
  const [autopilotEnabled, setAutopilotEnabled] = useState(false);
  const [togglingAutopilot, setTogglingAutopilot] = useState(false);

  // Fetch current modular WAF status on mount
  const fetchStatus = async () => {
    try {
      const res = await apiRequest({ path: '/custom-rules/status' });
      if (res && res.success) {
        setRules(res.rules || []);
        setVaultSummary(res.vault_summary || null);
        if (typeof res.autopilot_enabled === 'boolean') {
          setAutopilotEnabled(res.autopilot_enabled);
        }
        if (res.scan_progress) {
          syncProgressSnapshot(res.scan_progress);
        }
      }
    } catch (err) {
      console.error('Failed to fetch modular WAF status:', err);
    }
  };

  const {
    scanning,
    isPaused,
    scanProgress,
    syncProgressSnapshot,
    liveElapsedSeconds,
    scanError,
    startScan,
    pauseScan,
    resumeScan,
    cancelScan,
  } = useBehavioralScanRunner({
    onScanComplete: async () => {
      await fetchStatus();
      if (onRefreshStatus) await onRefreshStatus();
    },
  });

  const handleToggleAutopilot = async () => {
    const next = !autopilotEnabled;
    setTogglingAutopilot(true);
    try {
      const res = await apiRequest({
        path: '/custom-rules/autopilot',
        method: 'POST',
        data: { enabled: next },
      });
      if (res?.success) {
        setAutopilotEnabled(Boolean(res.autopilot_enabled));
        if (Array.isArray(res.rules)) {
          setRules(res.rules);
        }
        setBulkSuccessMsg(res.message || 'Auto-Pilot updated.');
        setTimeout(() => setBulkSuccessMsg(null), 5000);
      }
    } catch (err) {
      console.error('Failed to toggle Auto-Pilot:', err);
    } finally {
      setTogglingAutopilot(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  // Start new full scan
  const handleStartScan = async () => {
    await startScan();
  };

  // Toggle single rule
  const handleToggleRule = async (ruleId: string, newMode: 'enforce' | 'smart_learning' | 'monitor' | 'off') => {
    setTogglingRule(ruleId);
    try {
      const res = await apiRequest({
        path: '/custom-rules/rule/toggle',
        method: 'POST',
        data: { rule_id: ruleId, mode: newMode },
      });
      if (res && res.success) {
        setRules((prev) =>
          prev.map((r) => (r.id === ruleId ? { ...r, current_mode: newMode } : r))
        );
      }
    } catch (err) {
      console.error('Failed to toggle rule:', err);
    } finally {
      setTogglingRule(null);
    }
  };

  // Bulk enforce all recommended rules
  const handleBulkApply = async () => {
    setBulkApplying(true);
    setBulkSuccessMsg(null);
    try {
      const res = await apiRequest({
        path: '/custom-rules/rule/bulk-apply',
        method: 'POST',
      });
      if (res && res.success) {
        setRules((prev) =>
          prev.map((r) => (r.recommended_mode ? { ...r, current_mode: r.recommended_mode } : r))
        );
        setBulkSuccessMsg(res.message || 'All recommended modular rules successfully activated!');
        setTimeout(() => setBulkSuccessMsg(null), 4000);
      }
    } catch (err) {
      console.error('Failed to bulk apply rules:', err);
    } finally {
      setBulkApplying(false);
    }
  };

  // Open safe code preview modal
  const handleOpenCodeSnippet = async (rule: ModularRule) => {
    if (!rule.file) return;
    setSelectedSnippet({
      ruleId: rule.id,
      file: rule.file,
      line: rule.line || 1,
      lines: [],
      loading: true,
    });

    try {
      const res = await apiRequest({
        path: `/modular-waf/code-preview?file=${encodeURIComponent(rule.file)}&line=${rule.line || 1}`,
      });
      if (res && res.success) {
        setSelectedSnippet({
          ruleId: rule.id,
          file: res.file || rule.file,
          line: res.target_line || rule.line || 1,
          lines: res.snippet || [],
          loading: false,
        });
      } else {
        setSelectedSnippet((prev) => (prev ? { ...prev, loading: false, error: res.message || 'Failed to read snippet' } : null));
      }
    } catch (err: any) {
      setSelectedSnippet((prev) => (prev ? { ...prev, loading: false, error: err.message || 'Network error' } : null));
    }
  };

  const filteredRules = rules.filter((r) => {
    if (activeCategory === 'all') return true;
    if (activeCategory === 'ajax') return r.category === 'ajax_shield';
    if (activeCategory === 'rest') return r.category === 'rest_guard';
    if (activeCategory === 'abspath') return r.category === 'abspath_lock';
    if (activeCategory === 'cve') return r.category === 'cve_patch';
    return true;
  });

  const enforcedCount = rules.filter((r) => r.current_mode === 'enforce').length;
  const monitorCount = rules.filter((r) => r.current_mode === 'monitor').length;

  return (
    <div className="webcare-wizard-step-container" style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
      {/* Step Header */}
      <div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '4px 10px', borderRadius: '20px', background: 'rgba(79, 70, 229, 0.08)', color: 'var(--webcare-primary, #4f46e5)', fontSize: '12px', fontWeight: 700, marginBottom: '12px' }}>
          <Sparkles size={14} /> Phase 1: Environment Telemetry &amp; Foundation
        </div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h1 style={{ margin: '0 0 6px 0', fontSize: '24px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
              Deep Behavioral Intelligence &amp; Modular Firewall Synthesizer
            </h1>
            <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--webcare-text-secondary, #475569)', margin: 0 }}>
              Scans all active/inactive plugins, themes (including <code>functions.php</code>), and endpoints using token-level AST parsing to automatically synthesize tailored Modular Firewall rules for your exact codebase.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button
              type="button"
              onClick={handleStartScan}
              disabled={scanning}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                padding: '9px 18px',
                borderRadius: '8px',
                fontSize: '13px',
                fontWeight: 700,
                cursor: scanning ? 'not-allowed' : 'pointer',
                background: 'var(--webcare-primary, #4f46e5)',
                color: '#ffffff',
                border: 'none',
                boxShadow: '0 2px 8px rgba(79, 70, 229, 0.25)',
              }}
            >
              {scanning ? (
                <>
                  <Loader2 size={16} className="webcare-spin" /> Scanning AST... {Number(scanProgress?.progress_pct ?? 0).toFixed(0)}%
                </>
              ) : (
                <>
                  <Play size={15} /> Run Behavioral Scan
                </>
              )}
            </button>

            {scanning && onContinueInBackground && (
              <button
                type="button"
                onClick={onContinueInBackground}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '9px 16px',
                  borderRadius: '8px',
                  fontSize: '12px',
                  fontWeight: 700,
                  cursor: 'pointer',
                  background: 'none',
                  border: '1px solid var(--webcare-border, #cbd5e1)',
                  color: 'var(--webcare-text-title, #0f172a)',
                }}
              >
                Scan in Background &amp; Continue →
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Live AST Telemetry & Progress Bar */}
      <BehavioralScanProgressPanel
        scanning={scanning}
        isPaused={isPaused}
        scanProgress={scanProgress}
        liveElapsedSeconds={liveElapsedSeconds}
        rulesCount={rules.length}
        vaultSummary={vaultSummary}
        scanError={scanError}
        mode="wizard"
        onPause={pauseScan}
        onResume={resumeScan}
        onCancel={cancelScan}
      />

      {/* Recommended Modular Rules Section */}
      <div
        style={{
          padding: '24px',
          borderRadius: '14px',
          background: 'var(--webcare-bg-panel, #ffffff)',
          border: '1px solid var(--webcare-border, #e2e8f0)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
                Recommended Modular Firewall Rules ({rules.length})
              </h3>
              <span style={{ fontSize: '11px', fontWeight: 700, color: '#059669', background: 'rgba(16, 185, 129, 0.12)', padding: '2px 8px', borderRadius: '10px' }}>
                {enforcedCount} Enforcing
              </span>
              <span style={{ fontSize: '11px', fontWeight: 700, color: '#d97706', background: 'rgba(245, 158, 11, 0.12)', padding: '2px 8px', borderRadius: '10px' }}>
                {monitorCount} Monitoring
              </span>
            </div>
            <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>
              Synthesized specifically for your active plugins and themes. Enforced rules compile into the 0ms Pre-Boot Micro-WAF.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            <button
              type="button"
              onClick={handleToggleAutopilot}
              disabled={togglingAutopilot}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '9px 14px',
                borderRadius: '8px',
                fontSize: '12px',
                fontWeight: 700,
                cursor: togglingAutopilot ? 'wait' : 'pointer',
                background: autopilotEnabled ? 'var(--webcare-status-info-soft)' : 'var(--webcare-bg-surface, #f8fafc)',
                color: autopilotEnabled ? 'var(--webcare-status-info)' : 'var(--webcare-text-title, #0f172a)',
                border: `1px solid ${autopilotEnabled ? 'var(--webcare-status-info-border)' : 'var(--webcare-border-form, #cbd5e1)'}`,
              }}
              title="Enforces tampered/naked scripts immediately while safely learning active plugin AJAX & REST traffic for 48 hours under SQLi/XSS filtering."
            >
              <Sparkles size={14} />
              <span>{autopilotEnabled ? 'Smart 48h Auto-Pilot: ON' : 'Smart Auto-Pilot (Recommended)'}</span>
            </button>

            <button
              type="button"
              onClick={handleBulkApply}
              disabled={bulkApplying || rules.length === 0}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '9px 16px',
                borderRadius: '8px',
                fontSize: '12px',
                fontWeight: 700,
                cursor: bulkApplying ? 'not-allowed' : 'pointer',
                background: '#059669',
                color: '#ffffff',
                border: 'none',
                boxShadow: '0 2px 6px rgba(5, 150, 105, 0.25)',
              }}
            >
              <Zap size={14} />
              {bulkApplying ? 'Activating Modules...' : 'Enable All Recommended Modules'}
            </button>
          </div>
        </div>

        {bulkSuccessMsg && (
          <div style={{ padding: '10px 14px', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', color: '#059669', fontSize: '12px', fontWeight: 700, marginBottom: '14px' }}>
            ✓ {bulkSuccessMsg}
          </div>
        )}

        {/* Filter Pills */}
        <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', flexWrap: 'wrap' }}>
          {[
            { id: 'all', label: `All Rules (${rules.length})` },
            { id: 'ajax', label: `AJAX Shields (${rules.filter((r) => r.category === 'ajax_shield').length})` },
            { id: 'rest', label: `REST Guards (${rules.filter((r) => r.category === 'rest_guard').length})` },
            { id: 'abspath', label: `ABSPATH Locks (${rules.filter((r) => r.category === 'abspath_lock').length})` },
            { id: 'cve', label: `CVE Shields (${rules.filter((r) => r.category === 'cve_patch').length})` },
          ].map((cat) => (
            <button
              key={cat.id}
              type="button"
              onClick={() => setActiveCategory(cat.id)}
              style={{
                padding: '6px 12px',
                borderRadius: '20px',
                fontSize: '11px',
                fontWeight: 700,
                cursor: 'pointer',
                background: activeCategory === cat.id ? 'var(--webcare-primary, #4f46e5)' : 'var(--webcare-bg-elevated, #f8fafc)',
                color: activeCategory === cat.id ? '#ffffff' : 'var(--webcare-text-secondary, #475569)',
                border: '1px solid var(--webcare-border, #cbd5e1)',
              }}
            >
              {cat.label}
            </button>
          ))}
        </div>

        {/* Rules Cards List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '520px', overflowY: 'auto', paddingRight: '4px' }}>
          {filteredRules.slice(0, 50).map((rule) => {
            const isEnforced = rule.current_mode === 'enforce';
            const isSmartLearning = rule.current_mode === 'smart_learning';
            const isMonitoring = rule.current_mode === 'monitor';
            const isOff = rule.current_mode === 'off';

            return (
              <div
                key={rule.id}
                style={{
                  padding: '14px 16px',
                  borderRadius: '10px',
                  background: isEnforced ? 'var(--webcare-bg-elevated, #f8fafc)' : 'var(--webcare-bg-panel, #ffffff)',
                  border: isEnforced ? '1px solid var(--webcare-primary, #4f46e5)' : '1px solid var(--webcare-border, #e2e8f0)',
                  display: 'flex',
                  alignItems: 'flex-start',
                  justifyContent: 'space-between',
                  gap: '14px',
                  flexWrap: 'wrap',
                }}
              >
                <div style={{ flex: 1, minWidth: '260px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <code style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-primary, #4f46e5)' }}>
                      {rule.id}
                    </code>
                    <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)' }}>
                      • {rule.origin_component}
                    </span>
                    {rule.severity === 'critical' && (
                      <span style={{ fontSize: '10px', fontWeight: 800, color: '#dc2626', background: 'rgba(239, 68, 68, 0.1)', padding: '1px 6px', borderRadius: '4px' }}>
                        CRITICAL SINK
                      </span>
                    )}
                  </div>

                  <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', marginTop: '4px' }}>
                    {rule.title}
                  </div>

                  <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.4, marginTop: '4px' }}>
                    {rule.description}
                  </div>

                  {rule.evidence && (
                    <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', fontStyle: 'italic', marginTop: '4px' }}>
                      Evidence: {rule.evidence}
                    </div>
                  )}

                  {rule.file && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '6px' }}>
                      <span style={{ fontSize: '11px', fontFamily: 'monospace', color: '#0284c7' }}>
                        {rule.file}:{rule.line || 1}
                      </span>
                      <button
                        type="button"
                        onClick={() => handleOpenCodeSnippet(rule)}
                        style={{
                          background: 'none',
                          border: 'none',
                          color: 'var(--webcare-primary, #4f46e5)',
                          fontSize: '11px',
                          fontWeight: 700,
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '3px',
                          padding: 0,
                        }}
                      >
                        <Eye size={12} /> View Code Snippet
                      </button>
                    </div>
                  )}
                </div>

                {/* 3-State Mode Pill Selector */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '4px', background: 'var(--webcare-bg-elevated, #f1f5f9)', padding: '3px', borderRadius: '8px' }}>
                  <button
                    type="button"
                    onClick={() => handleToggleRule(rule.id, 'enforce')}
                    disabled={togglingRule === rule.id}
                    style={{
                      padding: '4px 10px',
                      borderRadius: '6px',
                      fontSize: '11px',
                      fontWeight: 700,
                      cursor: 'pointer',
                      border: 'none',
                      background: isEnforced ? '#059669' : 'transparent',
                      color: isEnforced ? '#ffffff' : 'var(--webcare-text-secondary, #475569)',
                    }}
                  >
                    Enforce (Block)
                  </button>

                  <button
                    type="button"
                    onClick={() => handleToggleRule(rule.id, 'smart_learning')}
                    disabled={togglingRule === rule.id}
                    style={{
                      padding: '4px 10px',
                      borderRadius: '6px',
                      fontSize: '11px',
                      fontWeight: 700,
                      cursor: 'pointer',
                      border: 'none',
                      background: isSmartLearning ? '#4f46e5' : 'transparent',
                      color: isSmartLearning ? '#ffffff' : 'var(--webcare-text-secondary, #475569)',
                    }}
                  >
                    Auto-Pilot (48h)
                  </button>

                  <button
                    type="button"
                    onClick={() => handleToggleRule(rule.id, 'monitor')}
                    disabled={togglingRule === rule.id}
                    style={{
                      padding: '4px 10px',
                      borderRadius: '6px',
                      fontSize: '11px',
                      fontWeight: 700,
                      cursor: 'pointer',
                      border: 'none',
                      background: isMonitoring ? '#d97706' : 'transparent',
                      color: isMonitoring ? '#ffffff' : 'var(--webcare-text-secondary, #475569)',
                    }}
                  >
                    Monitor
                  </button>

                  <button
                    type="button"
                    onClick={() => handleToggleRule(rule.id, 'off')}
                    disabled={togglingRule === rule.id}
                    style={{
                      padding: '4px 10px',
                      borderRadius: '6px',
                      fontSize: '11px',
                      fontWeight: 700,
                      cursor: 'pointer',
                      border: 'none',
                      background: isOff ? '#64748b' : 'transparent',
                      color: isOff ? '#ffffff' : 'var(--webcare-text-secondary, #475569)',
                    }}
                  >
                    Off
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Code Snippet Modal */}
      {selectedSnippet && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.65)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 99999,
            padding: '20px',
          }}
        >
          <div
            style={{
              width: '100%',
              maxWidth: '720px',
              borderRadius: '14px',
              background: '#0f172a',
              color: '#f8fafc',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              boxShadow: '0 20px 40px rgba(0,0,0,0.4)',
              overflow: 'hidden',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 20px', borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}>
              <div>
                <div style={{ fontSize: '12px', fontWeight: 700, color: '#38bdf8' }}>
                  {selectedSnippet.ruleId} • Safe AST Snippet Preview
                </div>
                <div style={{ fontSize: '11px', color: '#94a3b8', fontFamily: 'monospace', marginTop: '2px' }}>
                  {selectedSnippet.file} (Line {selectedSnippet.line})
                </div>
              </div>

              <button
                type="button"
                onClick={() => setSelectedSnippet(null)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#94a3b8',
                  cursor: 'pointer',
                  padding: '4px',
                }}
              >
                <X size={18} />
              </button>
            </div>

            <div style={{ padding: '16px 20px', maxHeight: '420px', overflowY: 'auto' }}>
              {selectedSnippet.loading ? (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', padding: '40px' }}>
                  <Loader2 size={18} className="webcare-spin" color="#38bdf8" /> Loading AST snippet...
                </div>
              ) : selectedSnippet.error ? (
                <div style={{ color: '#f87171', padding: '20px' }}>{selectedSnippet.error}</div>
              ) : (
                <div style={{ fontFamily: 'monospace', fontSize: '12px', lineHeight: 1.6 }}>
                  {selectedSnippet.lines.map((item) => (
                    <div
                      key={item.number}
                      style={{
                        display: 'flex',
                        background: item.is_target ? 'rgba(239, 68, 68, 0.2)' : 'transparent',
                        borderLeft: item.is_target ? '3px solid #ef4444' : '3px solid transparent',
                        padding: '1px 8px',
                      }}
                    >
                      <span style={{ width: '40px', color: item.is_target ? '#f87171' : '#64748b', userSelect: 'none' }}>
                        {item.number}
                      </span>
                      <pre style={{ margin: 0, color: item.is_target ? '#fca5a5' : '#e2e8f0', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                        {item.code || ' '}
                      </pre>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div style={{ padding: '12px 20px', borderTop: '1px solid rgba(255, 255, 255, 0.1)', display: 'flex', justifyContent: 'flex-end' }}>
              <button
                type="button"
                onClick={() => setSelectedSnippet(null)}
                style={{
                  padding: '6px 16px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  fontWeight: 700,
                  cursor: 'pointer',
                  background: 'rgba(255, 255, 255, 0.1)',
                  color: '#ffffff',
                  border: 'none',
                }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
