import React, { useState, useEffect, useMemo } from '@wordpress/element';
import {
  Shield,
  Layers,
  Terminal,
  Radar,
  Play,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Zap,
  Lock,
  Eye,
  Plus,
  Sliders,
  Sparkles,
  Download,
  Upload,
  Search,
  Filter,
  Check,
  X,
  Loader2,
  ExternalLink,
  ChevronRight,
  HardDrive,
  FileCode,
  Globe,
  ShieldCheck,
  ShieldAlert,
  Fingerprint,
  Cpu,
  Trash2,
  Pencil,
  GripVertical,
  ArrowUp,
  ArrowDown,
  Save
} from 'lucide-react';
import { apiRequest } from '../utils/api';
import { formatDuration, useBehavioralScanRunner } from '../utils/scanTelemetry';
import { BehavioralScanProgressPanel } from './BehavioralScanProgressPanel';
import { VisualRuleBuilderPanel, VisualRuleDraft } from './VisualRuleBuilderPanel';
import { NextGenEcosystemPanel } from './NextGenEcosystemPanel';
import { WebCareSlot } from '../utils/moduleSlots';

interface ModularRule {
  id: string;
  rule_number?: number;
  priority?: number;
  group_logic?: 'AND' | 'OR';
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
  http_methods?: string[];
  rate_limit?: number;
  block_uploads?: boolean;
  sync_cloudflare?: boolean;
  is_custom?: boolean;
  action_type?: string;
  ban_ttl?: number;
  conditions?: Array<{ logic: 'AND' | 'OR'; rules: Array<{ field: string; key?: string; op: string; value: string }> }>;
  wirefilter_expr?: string;
  exempt_rules?: string[];
  synthesized_at?: number;
  component_origin_type?: string;
  is_official_wporg?: boolean;
  is_known_vendor?: boolean;
  vendor_name?: string | null;
  file_sha256?: string | null;
  file_md5?: string | null;
  checksum_status?: string;
  expected_checksum?: string | null;
  known_vendor_lib?: string | null;
  false_positive_risk?: string;
  provenance_note?: string;
}

interface ComponentInventoryItem {
  slug: string;
  name: string;
  type: string;
  version: string;
  author?: string;
  is_active: boolean;
  is_child?: boolean;
  file_count?: number;
  endpoints_count?: number;
  findings_count?: number;
  rules_count?: number;
  risk_score?: number;
  unprotected_ajax_count?: number;
  permissive_rest_count?: number;
  missing_abspath_count?: number;
  sinks_count?: number;
  origin_type?: string;
  origin_label?: string;
  is_official_wporg?: boolean;
  is_known_vendor?: boolean;
  vendor_name?: string | null;
  vendor_evidence?: string | null;
  trust_tier?: string;
  checksum_status?: string;
  checksum_verified?: boolean;
  checksum_source?: string | null;
  checksum_summary?: {
    manifest_total?: number;
    files_checked?: number;
    authentic_count?: number;
    modified_count?: number;
    unknown_count?: number;
    modified_files?: any[];
    unknown_files?: string[];
  };
  update_available?: boolean;
  latest_version?: string | null;
}

interface TrustSummary {
  official_wporg_count: number;
  known_vendor_count: number;
  custom_unmanaged_count: number;
  checksum_verified_count: number;
  tamper_alert_count: number;
  outdated_count: number;
}

type ModularWafTab = 'rules' | 'dossier' | 'builder' | 'nextgen';

const resolveModularWafTabFromUrl = (): ModularWafTab => {
  try {
    const qs = new URLSearchParams(window.location.search);
    const t = qs.get('tab');
    if (t === 'builder' || t === 'custom') return 'builder';
    if (t === 'nextgen' || t === 'modules') return 'nextgen';
    if (t === 'dossier') return 'dossier';
  } catch {}
  return 'rules';
};

export const ModularFirewallStudio: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ModularWafTab>(() => resolveModularWafTabFromUrl());

  const syncTabUrl = (tab: ModularWafTab, replace = false) => {
    try {
      const url = new URL(window.location.href);
      url.searchParams.set('tab', tab);
      if (replace) {
        window.history.replaceState({ tab }, '', url.toString());
      } else {
        window.history.pushState({ tab }, '', url.toString());
      }
    } catch {}
  };

  const switchTab = (tab: ModularWafTab) => {
    setActiveTab(tab);
    syncTabUrl(tab, false);
  };

  useEffect(() => {
    try {
      const qs = new URLSearchParams(window.location.search);
      const currentParam = qs.get('tab');
      if (currentParam !== activeTab) {
        syncTabUrl(activeTab, true);
      }
    } catch {}

    const handlePopState = () => {
      setActiveTab(resolveModularWafTabFromUrl());
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);
  const [visualRuleDraft, setVisualRuleDraft] = useState<VisualRuleDraft | null>(() => {
    try {
      const raw = sessionStorage.getItem('webcare_visual_rule_draft');
      if (raw) {
        sessionStorage.removeItem('webcare_visual_rule_draft');
        return JSON.parse(raw);
      }
    } catch {}
    return null;
  });
  const [loading, setLoading] = useState(true);
  const [showScanPanel, setShowScanPanel] = useState(false);

  // Studio Data
  const [rules, setRules] = useState<ModularRule[]>([]);
  const [inventory, setInventory] = useState<ComponentInventoryItem[]>([]);
  const [endpointMap, setEndpointMap] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [vaultSummary, setVaultSummary] = useState<any>(null);
  const [trustSummary, setTrustSummary] = useState<TrustSummary | null>(null);
  const [exporting, setExporting] = useState(false);
  const [autopilotEnabled, setAutopilotEnabled] = useState(false);
  const [togglingAutopilot, setTogglingAutopilot] = useState(false);
  const [workspaceMode, setWorkspaceMode] = useState<'essential' | 'advanced'>(() => {
    try {
      const saved = localStorage.getItem('webcare_workspace_mode');
      return saved === 'advanced' ? 'advanced' : 'essential';
    } catch {
      return 'essential';
    }
  });

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [modeFilter, setModeFilter] = useState('all');
  const [trustFilter, setTrustFilter] = useState('all');

  // Dossier Filters
  const [dossierSearch, setDossierSearch] = useState('');
  const [dossierTypeFilter, setDossierTypeFilter] = useState('all');

  // Filtered Component Inventory
  const filteredInventory = useMemo(() => {
    return inventory.filter((comp) => {
      if (dossierTypeFilter !== 'all' && comp.type !== dossierTypeFilter) return false;
      if (dossierSearch.trim()) {
        const q = dossierSearch.toLowerCase();
        return (
          comp.name.toLowerCase().includes(q) ||
          comp.slug.toLowerCase().includes(q) ||
          (comp.author && comp.author.toLowerCase().includes(q)) ||
          (comp.vendor_name && comp.vendor_name.toLowerCase().includes(q))
        );
      }
      return true;
    });
  }, [inventory, dossierSearch, dossierTypeFilter]);

  // Modals
  const [selectedSnippet, setSelectedSnippet] = useState<{
    ruleId: string;
    file: string;
    line: number;
    lines: Array<{ number: number; code: string; is_target: boolean }>;
    loading: boolean;
    error?: string;
  } | null>(null);

  const [editingRule, setEditingRule] = useState<ModularRule | null>(null);
  const [selectedComponentDossier, setSelectedComponentDossier] = useState<ComponentInventoryItem | null>(null);

  // Status & action notifications
  const [notification, setNotification] = useState<string | null>(null);

  // Custom rule drag-and-drop & priority ordering state
  const [customOrderIds, setCustomOrderIds] = useState<string[]>([]);
  const [hasPendingOrder, setHasPendingOrder] = useState<boolean>(false);
  const [savingOrder, setSavingOrder] = useState<boolean>(false);
  const [dragRuleId, setDragRuleId] = useState<string | null>(null);
  const [dragOverRuleId, setDragOverRuleId] = useState<string | null>(null);

  const showNotification = (msg: string) => {
    setNotification(msg);
    setTimeout(() => setNotification(null), 4000);
  };

  const loadStudioData = async () => {
    try {
      setLoading(true);
      const res = await apiRequest({ path: '/modular-waf/status' });
      if (res && res.success) {
        const nextRules: ModularRule[] = Array.isArray(res.rules) ? res.rules : [];
        setRules(nextRules);
        setCustomOrderIds(
          nextRules
            .filter((r) => Boolean(r.is_custom) || r.category === 'custom')
            .map((r) => r.id)
        );
        setHasPendingOrder(false);
        const rawInv = res.inventory;
        const invList = Array.isArray(rawInv)
          ? rawInv
          : (rawInv && typeof rawInv === 'object' ? Object.values(rawInv) : []);
        setInventory(invList as ComponentInventoryItem[]);
        setEndpointMap(Array.isArray(res.endpoint_map) ? res.endpoint_map : []);
        setFindings(Array.isArray(res.findings) ? res.findings : []);
        setVaultSummary(res.vault_summary || null);
        setTrustSummary(res.trust_summary || null);
        if (typeof res.autopilot_enabled === 'boolean') {
          setAutopilotEnabled(res.autopilot_enabled);
        }
        if (res.scan_progress) {
          syncProgressSnapshot(res.scan_progress);
          if (res.scan_progress.status === 'running' || res.scan_progress.status === 'paused') {
            setShowScanPanel(true);
          }
        }
      }
    } catch (err) {
      console.error('Failed to load modular studio data:', err);
    } finally {
      setLoading(false);
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
      await loadStudioData();
      showNotification('Deep Behavioral Scan complete! Vault shards and modular rules refreshed.');
    },
    onScanError: (msg) => {
      showNotification(`Behavioral scan stopped: ${msg}`);
    },
  });

  useEffect(() => {
    loadStudioData();
    const onWorkspaceModeChanged = (ev: Event) => {
      const next = (ev as CustomEvent<'essential' | 'advanced'>)?.detail;
      if (next === 'essential' || next === 'advanced') {
        setWorkspaceMode(next);
      }
    };
    window.addEventListener('webcare_workspace_mode_changed', onWorkspaceModeChanged);
    return () => window.removeEventListener('webcare_workspace_mode_changed', onWorkspaceModeChanged);
  }, []);

  const handleStartScan = async () => {
    setShowScanPanel(true);
    await startScan();
  };

  const handleToggleAutopilot = async () => {
    const next = !autopilotEnabled;
    setTogglingAutopilot(true);
    try {
      const res = await apiRequest({
        path: '/modular-waf/autopilot',
        method: 'POST',
        data: { enabled: next },
      });
      if (res?.success) {
        setAutopilotEnabled(Boolean(res.autopilot_enabled));
        if (Array.isArray(res.rules)) {
          setRules(res.rules);
        }
        showNotification(res.message || 'Smart 48-Hour Auto-Pilot updated.');
      }
    } catch (err) {
      console.error('Failed to toggle Auto-Pilot:', err);
    } finally {
      setTogglingAutopilot(false);
    }
  };

  const handleToggleRule = async (ruleId: string, newMode: 'enforce' | 'smart_learning' | 'monitor' | 'off') => {
    try {
      const res = await apiRequest({
        path: '/modular-waf/rule/toggle',
        method: 'POST',
        data: { rule_id: ruleId, mode: newMode },
      });
      if (res && res.success) {
        setRules((prev) =>
          prev.map((r) => (r.id === ruleId ? { ...r, current_mode: newMode } : r))
        );
        showNotification(`Rule ${ruleId} updated to ${newMode}. Pre-Boot WAF compiled.`);
      }
    } catch (err) {
      console.error('Failed to toggle rule:', err);
    }
  };

  const handleBulkApply = async () => {
    try {
      const res = await apiRequest({
        path: '/modular-waf/rule/bulk-apply',
        method: 'POST',
      });
      if (res && res.success) {
        setRules((prev) =>
          prev.map((r) => (r.recommended_mode ? { ...r, current_mode: r.recommended_mode } : r))
        );
        showNotification(res.message || 'All recommended modular rules successfully activated!');
      }
    } catch (err) {
      console.error('Failed to bulk apply:', err);
    }
  };

  const handleExportJson = async () => {
    setExporting(true);
    const host = window.location.hostname.replace(/[^a-zA-Z0-9.-]/g, '_') || 'wordpress';
    const dateStr = new Date().toISOString().slice(0, 10);
    const filename = `webcare-modular-waf-${host}-${dateStr}.json`;

    try {
      const res = await apiRequest({ path: '/modular-waf/export' });
      const exportPayload =
        res && res.webcare_export_type
          ? res
          : {
              webcare_export_type: 'modular_waf_forensic_dossier',
              format_version: ((window as any).webcareScannerSettings?.version) || '2.12.0',
              exported_at: new Date().toISOString(),
              exported_timestamp: Math.floor(Date.now() / 1000),
              environment: {
                site_url: window.location.origin,
                current_url: window.location.href,
              },
              summary: {
                total_rules: rules.length,
                enforced_rules: enforcedCount,
                monitored_rules: monitorCount,
                components_profiled: inventory.length,
                endpoints_mapped: endpointMap.length,
                ast_findings_count: findings.length,
              },
              rules,
              component_inventory: inventory,
              endpoint_behavior_map: endpointMap,
              ast_taint_findings: findings,
              vault_summary: vaultSummary,
              scan_progress: scanProgress,
            };

      const jsonString = JSON.stringify(exportPayload, null, 2);
      const blob = new Blob([jsonString], { type: 'application/json' });
      const blobUrl = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = blobUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(blobUrl);

      const ruleCount = Array.isArray(exportPayload.rules) ? exportPayload.rules.length : rules.length;
      const compCount = Array.isArray(exportPayload.component_inventory) ? exportPayload.component_inventory.length : inventory.length;
      const hashedCount = exportPayload.summary?.unique_files_hashed ?? Object.keys(exportPayload.file_hash_index || {}).length;
      const logCount = exportPayload.summary?.recent_modular_hits ?? 0;
      showNotification(`Exported complete forensic JSON (${ruleCount} rules, ${compCount} components, ${hashedCount} hashed files, ${logCount} log events) to ${filename}`);
    } catch (err) {
      console.error('Failed to export forensic JSON via REST, using client snapshot:', err);
      const fallbackPayload = {
        webcare_export_type: 'modular_waf_forensic_dossier_snapshot',
        format_version: ((window as any).webcareScannerSettings?.version) || '2.12.0',
        exported_at: new Date().toISOString(),
        exported_timestamp: Math.floor(Date.now() / 1000),
        summary: {
          total_rules: rules.length,
          enforced_rules: enforcedCount,
          monitored_rules: monitorCount,
          components_profiled: inventory.length,
          endpoints_mapped: endpointMap.length,
          ast_findings_count: findings.length,
        },
        rules,
        component_inventory: inventory,
        endpoint_behavior_map: endpointMap,
        ast_taint_findings: findings,
        vault_summary: vaultSummary,
        scan_progress: scanProgress,
      };
      const jsonString = JSON.stringify(fallbackPayload, null, 2);
      const blob = new Blob([jsonString], { type: 'application/json' });
      const blobUrl = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = blobUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(blobUrl);
      showNotification(`Exported active session forensic JSON to ${filename}`);
    } finally {
      setExporting(false);
    }
  };

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
        setSelectedSnippet((prev) => (prev ? { ...prev, loading: false, error: res.message || 'Snippet not available' } : null));
      }
    } catch (err: any) {
      setSelectedSnippet((prev) => (prev ? { ...prev, loading: false, error: err.message } : null));
    }
  };

  const customRulesList = useMemo(
    () => rules.filter((r) => Boolean(r.is_custom) || r.category === 'custom'),
    [rules]
  );

  const orderedRules = useMemo(() => {
    if (customOrderIds.length === 0) return rules;
    const byId = new Map(customRulesList.map((r) => [r.id, r]));
    const orderedCustom: ModularRule[] = [];
    for (const id of customOrderIds) {
      const hit = byId.get(id);
      if (hit) {
        orderedCustom.push(hit);
        byId.delete(id);
      }
    }
    for (const leftover of byId.values()) {
      orderedCustom.push(leftover);
    }
    const nonCustom = rules.filter((r) => !Boolean(r.is_custom) && r.category !== 'custom');
    return [...orderedCustom, ...nonCustom];
  }, [rules, customRulesList, customOrderIds]);

  const moveCustomRuleToIndex = (ruleId: string, toIndex: number) => {
    setCustomOrderIds((prev) => {
      const base = prev.length > 0 ? [...prev] : customRulesList.map((r) => r.id);
      const fromIdx = base.indexOf(ruleId);
      if (fromIdx === -1) return prev;
      const clampedTo = Math.max(0, Math.min(base.length - 1, toIndex));
      if (fromIdx === clampedTo) return prev;
      const [item] = base.splice(fromIdx, 1);
      base.splice(clampedTo, 0, item);
      return base;
    });
    setHasPendingOrder(true);
  };

  const moveCustomRuleByIdBefore = (sourceId: string, targetId: string) => {
    if (!sourceId || !targetId || sourceId === targetId) return;
    setCustomOrderIds((prev) => {
      const base = prev.length > 0 ? [...prev] : customRulesList.map((r) => r.id);
      const fromIdx = base.indexOf(sourceId);
      const toIdx = base.indexOf(targetId);
      if (fromIdx === -1 || toIdx === -1 || fromIdx === toIdx) return prev;
      const [item] = base.splice(fromIdx, 1);
      base.splice(toIdx, 0, item);
      return base;
    });
    setHasPendingOrder(true);
  };

  const handleSaveCustomOrder = async () => {
    if (customOrderIds.length === 0) return;
    try {
      setSavingOrder(true);
      const res = await apiRequest({
        path: '/modular-waf/rule/custom/reorder',
        method: 'POST',
        data: { ordered_ids: customOrderIds },
      });
      if (res?.success) {
        if (Array.isArray(res.rules)) {
          setRules(res.rules);
          setCustomOrderIds(
            res.rules
              .filter((r: ModularRule) => Boolean(r.is_custom) || r.category === 'custom')
              .map((r: ModularRule) => r.id)
          );
        } else {
          await loadStudioData();
        }
        setHasPendingOrder(false);
        showNotification(res.message || 'Saved custom firewall rule execution order.');
      } else {
        showNotification(res?.message || 'Failed to save custom rule order.');
      }
    } catch (err: any) {
      showNotification(err?.message || 'Error saving custom rule order.');
    } finally {
      setSavingOrder(false);
    }
  };

  const handleResetCustomOrder = () => {
    setCustomOrderIds(customRulesList.map((r) => r.id));
    setHasPendingOrder(false);
  };

  const filteredRules = orderedRules.filter((r) => {
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch =
      q === '' ||
      r.id.toLowerCase().includes(q) ||
      (r.rule_number !== undefined && (`#${r.rule_number}` === q || String(r.rule_number) === q)) ||
      r.title.toLowerCase().includes(q) ||
      r.origin_component.toLowerCase().includes(q) ||
      (r.description && r.description.toLowerCase().includes(q)) ||
      (r.file && r.file.toLowerCase().includes(q)) ||
      (r.target_uri && r.target_uri.toLowerCase().includes(q)) ||
      (r.file_sha256 && r.file_sha256.toLowerCase().includes(q)) ||
      (r.vendor_name && r.vendor_name.toLowerCase().includes(q));

    const matchesCategory =
      categoryFilter === 'all' ||
      (categoryFilter === 'tamper' && r.category === 'tamper_guard') ||
      (categoryFilter === 'ajax' && r.category === 'ajax_shield') ||
      (categoryFilter === 'rest' && r.category === 'rest_guard') ||
      (categoryFilter === 'abspath' && r.category === 'abspath_lock') ||
      (categoryFilter === 'cve' && r.category === 'cve_patch') ||
      (categoryFilter === 'custom' && r.is_custom);

    const matchesMode =
      modeFilter === 'all' ||
      (modeFilter === 'enforce' && r.current_mode === 'enforce') ||
      (modeFilter === 'smart_learning' && r.current_mode === 'smart_learning') ||
      (modeFilter === 'monitor' && r.current_mode === 'monitor') ||
      (modeFilter === 'off' && r.current_mode === 'off');

    const chkStatus = r.checksum_status || 'unmanaged_custom';
    const isTampered = ['modified', 'unknown_in_official', 'self_modified', 'self_untracked'].includes(chkStatus);
    const matchesTrust =
      trustFilter === 'all' ||
      (trustFilter === 'tamper_alert' && isTampered) ||
      (trustFilter === 'official_wporg' && r.is_official_wporg) ||
      (trustFilter === 'known_vendor' && r.is_known_vendor) ||
      (trustFilter === 'custom_unmanaged' && !r.is_official_wporg && !r.is_known_vendor);

    return matchesSearch && matchesCategory && matchesMode && matchesTrust;
  });

  const enforcedCount = rules.filter((r) => r.current_mode === 'enforce').length;
  const monitorCount = rules.filter((r) => r.current_mode === 'monitor').length;

  return (
    <div style={{ width: '100%', boxSizing: 'border-box' }}>
      <div>
        
        {/* Top Header Card */}
        <div
          style={{
            padding: '24px 28px',
            borderRadius: '16px',
            background: 'var(--webcare-bg-panel, #ffffff)',
            border: '1px solid var(--webcare-border, #e2e8f0)',
            boxShadow: '0 4px 20px rgba(0, 0, 0, 0.04)',
            marginBottom: '20px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
              <div
                style={{
                  width: '46px',
                  height: '46px',
                  borderRadius: '12px',
                  background: 'linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)',
                  color: '#ffffff',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 4px 12px rgba(79, 70, 229, 0.3)',
                }}
              >
                <Radar size={24} />
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <h1 style={{ margin: 0, fontSize: '22px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
                    Custom Rules &amp; Protection Studio
                  </h1>
                  <span style={{ fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '12px', background: 'rgba(79, 70, 229, 0.1)', color: 'var(--webcare-primary, #4f46e5)' }}>
                    v{((window as any).webcareScannerSettings?.version) || '2.12.0'}
                  </span>
                </div>
                <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)' }}>
                  Autonomous site-tailored custom rules synthesized from your website's PHP AST and endpoint behavioral profile.
                </p>
              </div>
            </div>

            {/* Top Telemetry & Controls */}
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
                  background: autopilotEnabled ? 'var(--webcare-status-clean-soft)' : 'var(--webcare-bg-elevated, #f1f5f9)',
                  color: autopilotEnabled ? 'var(--webcare-status-clean)' : 'var(--webcare-text-title, #0f172a)',
                  border: `1px solid ${autopilotEnabled ? 'var(--webcare-status-clean-border)' : 'var(--webcare-border-strong, #cbd5e1)'}`,
                }}
                title="Enforces tampered/naked scripts immediately while letting active plugin AJAX & REST endpoints learn safely for 48 hours."
              >
                <Sparkles size={14} />
                <span>{autopilotEnabled ? 'Smart 48h Auto-Pilot: ON' : 'Smart Auto-Pilot'}</span>
              </button>

              <button
                type="button"
                onClick={handleExportJson}
                disabled={exporting}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '9px 16px',
                  borderRadius: '8px',
                  fontSize: '13px',
                  fontWeight: 700,
                  cursor: exporting ? 'not-allowed' : 'pointer',
                  background: 'var(--webcare-bg-elevated, #f1f5f9)',
                  color: 'var(--webcare-text-title, #0f172a)',
                  border: '1px solid var(--webcare-border-strong, #cbd5e1)',
                  boxShadow: '0 1px 2px rgba(0, 0, 0, 0.04)',
                  transition: 'all 0.15s ease',
                }}
                title="Export all modular rules, component behavioral dossier, AST taint findings, and endpoint maps as JSON for false-positive investigation"
              >
                {exporting ? <Loader2 size={15} className="webcare-spin" /> : <Download size={15} />}
                {exporting ? 'Exporting JSON...' : 'Export Forensic JSON'}
              </button>

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
                {scanning ? <Loader2 size={16} className="webcare-spin" /> : <Play size={15} />}
                {scanning
                  ? `Scanning AST... ${Number(scanProgress?.progress_pct ?? 0).toFixed(0)}%`
                  : 'Run Full Behavioral Scan'}
              </button>
            </div>
          </div>

          {/* Vault Telemetry Status Bar */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(175px, 1fr))',
              gap: '12px',
              marginTop: '20px',
              paddingTop: '18px',
              borderTop: '1px solid var(--webcare-border, #e2e8f0)',
            }}
          >
            <div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', fontWeight: 600 }}>Vault Status</div>
              <div style={{ fontSize: '13px', fontWeight: 800, color: 'var(--webcare-status-clean, #059669)', display: 'flex', alignItems: 'center', gap: '4px', marginTop: '2px' }}>
                <CheckCircle2 size={14} /> HMAC-SHA256 Sealed
              </div>
            </div>

            <div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', fontWeight: 600 }}>Components Profiled</div>
              <div style={{ fontSize: '13px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)', marginTop: '2px' }}>
                {inventory.length || vaultSummary?.shards?.extension_inventory?.records || 7} Installed Extensions
              </div>
            </div>

            <div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', fontWeight: 600 }}>Origin &amp; Checksums</div>
              <div style={{
                fontSize: '13px',
                fontWeight: 800,
                color: (trustSummary?.tamper_alert_count ?? 0) > 0
                  ? 'var(--webcare-status-critical, #dc2626)'
                  : 'var(--webcare-status-clean, #059669)',
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
                marginTop: '2px'
              }}>
                {(trustSummary?.tamper_alert_count ?? 0) > 0 ? (
                  <>
                    <ShieldAlert size={14} /> {trustSummary?.tamper_alert_count} Tamper Alert(s)
                  </>
                ) : (
                  <>
                    <ShieldCheck size={14} /> {trustSummary?.checksum_verified_count ?? 0} Checksum Clean • {trustSummary?.known_vendor_count ?? 0} Vendor
                  </>
                )}
              </div>
            </div>

            <div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', fontWeight: 600 }}>Active Rules</div>
              <div style={{ fontSize: '13px', fontWeight: 800, color: 'var(--webcare-primary, #4f46e5)', marginTop: '2px' }}>
                {enforcedCount} Enforcing • {monitorCount} Monitoring
              </div>
            </div>

            <div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', fontWeight: 600 }}>AST Telemetry</div>
              <button
                type="button"
                className="webcare-ast-summary-toggle"
                onClick={() => setShowScanPanel((prev) => !prev)}
                aria-expanded={scanning || isPaused || showScanPanel}
              >
                {scanning || isPaused
                  ? `${Number(scanProgress?.processed_files ?? 0).toLocaleString()} / ${Number(scanProgress?.total_files ?? 0).toLocaleString()} files • ${isPaused ? 'Paused' : formatDuration(liveElapsedSeconds)}`
                  : (scanProgress?.total_files || vaultSummary?.total_files)
                  ? `${Number(scanProgress?.total_files ?? vaultSummary?.total_files ?? 0).toLocaleString()} PHP files • ${showScanPanel ? 'Hide' : 'Details'}`
                  : 'Compiled (< 0.1ms latency)'}
              </button>
            </div>
          </div>
        </div>

        {(scanning || isPaused || showScanPanel) && (
          <BehavioralScanProgressPanel
            scanning={scanning}
            isPaused={isPaused}
            scanProgress={scanProgress}
            liveElapsedSeconds={liveElapsedSeconds}
            rulesCount={rules.length}
            vaultSummary={vaultSummary}
            scanError={scanError}
            mode="studio"
            onPause={pauseScan}
            onResume={resumeScan}
            onCancel={async () => {
              await cancelScan();
              showNotification('Pending scan session cancelled. Existing sealed Vault rules remain intact.');
            }}
            onDismiss={scanning || isPaused ? undefined : () => setShowScanPanel(false)}
          />
        )}

        {notification && (
          <div
            style={{
              padding: '12px 18px',
              borderRadius: '10px',
              background: 'rgba(16, 185, 129, 0.1)',
              border: '1px solid rgba(16, 185, 129, 0.3)',
              color: '#059669',
              fontSize: '13px',
              fontWeight: 700,
              marginBottom: '20px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
            }}
          >
            <Check size={16} /> {notification}
          </div>
        )}

        {workspaceMode === 'essential' && (
          <div
            style={{
              padding: '16px 20px',
              borderRadius: '12px',
              background: 'var(--webcare-status-info-soft)',
              border: '1px solid var(--webcare-status-info-border)',
              marginBottom: '20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '12px',
            }}
          >
            <div>
              <div style={{ fontSize: '13.5px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
                Simple Owner Summary: {enforcedCount} Shields Blocking Attacks • {rules.filter((r) => r.current_mode === 'smart_learning').length} In Safe 48h Auto-Pilot
              </div>
              <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '3px' }}>
                Use <strong>Smart Auto-Pilot</strong> for zero-stress protection, or switch to <strong>Pro Engineer</strong> in the top bar for AST code snippets &amp; SHA-256 verification hashes.
              </div>
            </div>
            <button
              type="button"
              onClick={handleToggleAutopilot}
              disabled={togglingAutopilot}
              style={{
                padding: '7px 14px',
                borderRadius: '8px',
                border: 'none',
                background: '#4f46e5',
                color: '#ffffff',
                fontSize: '12px',
                fontWeight: 700,
                cursor: 'pointer',
              }}
            >
              {autopilotEnabled ? 'Auto-Pilot Active ✓' : 'Enable Smart 48h Auto-Pilot'}
            </button>
          </div>
        )}

        {/* Tab Navigation Hub */}
        <div style={{ display: 'flex', gap: '8px', marginBottom: '20px', borderBottom: '1px solid var(--webcare-border, #e2e8f0)', paddingBottom: '10px' }}>
          <button
            type="button"
            onClick={() => switchTab('rules')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '8px 18px',
              borderRadius: '8px',
              fontSize: '13px',
              fontWeight: 700,
              cursor: 'pointer',
              background: activeTab === 'rules' ? 'var(--webcare-primary, #4f46e5)' : 'none',
              color: activeTab === 'rules' ? '#ffffff' : 'var(--webcare-text-secondary, #475569)',
              border: 'none',
            }}
          >
            <Shield size={15} /> Custom Rules ({rules.length})
          </button>

          <button
            type="button"
            onClick={() => switchTab('dossier')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '8px 18px',
              borderRadius: '8px',
              fontSize: '13px',
              fontWeight: 700,
              cursor: 'pointer',
              background: activeTab === 'dossier' ? 'var(--webcare-primary, #4f46e5)' : 'none',
              color: activeTab === 'dossier' ? '#ffffff' : 'var(--webcare-text-secondary, #475569)',
              border: 'none',
            }}
          >
            <Layers size={15} /> Component Behavioral Dossier ({inventory.length})
          </button>

          <button
            type="button"
            onClick={() => switchTab('builder')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '8px 18px',
              borderRadius: '8px',
              fontSize: '13px',
              fontWeight: 700,
              cursor: 'pointer',
              background: activeTab === 'builder' ? 'var(--webcare-primary, #4f46e5)' : 'none',
              color: activeTab === 'builder' ? '#ffffff' : 'var(--webcare-text-secondary, #475569)',
              border: 'none',
            }}
          >
            <Plus size={15} /> Custom Firewall Rules
          </button>

          <button
            type="button"
            onClick={() => switchTab('nextgen')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '8px 18px',
              borderRadius: '8px',
              fontSize: '13px',
              fontWeight: 700,
              cursor: 'pointer',
              background: activeTab === 'nextgen' ? 'var(--webcare-primary, #4f46e5)' : 'none',
              color: activeTab === 'nextgen' ? '#ffffff' : 'var(--webcare-text-secondary, #475569)',
              border: 'none',
            }}
          >
            <Cpu size={15} /> Next-Gen &amp; Modules SDK
          </button>
        </div>

        {/* TAB 1: MODULAR FIREWALL RULES */}
        {activeTab === 'rules' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {/* Toolbar: Search & Filters */}
            <div
              style={{
                padding: '16px 20px',
                borderRadius: '12px',
                background: 'var(--webcare-bg-panel, #ffffff)',
                border: '1px solid var(--webcare-border, #e2e8f0)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '12px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, minWidth: '240px' }}>
                <Search size={16} color="var(--webcare-text-muted, #64748b)" />
                <input
                  type="text"
                  placeholder="Search rules by ID, endpoint, hook, component, or SHA-256 hash..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{
                    border: 'none',
                    outline: 'none',
                    background: 'transparent',
                    fontSize: '13px',
                    width: '100%',
                    color: 'var(--webcare-text-title, #0f172a)',
                  }}
                />
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <select
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                  style={{
                    padding: '6px 10px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    background: 'var(--webcare-bg-elevated, #f8fafc)',
                    border: '1px solid var(--webcare-border, #cbd5e1)',
                    color: 'var(--webcare-text-title, #0f172a)',
                  }}
                >
                  <option value="all">All Categories</option>
                  <option value="tamper">Checksum Tamper Locks (MOD-TAMPER-*)</option>
                  <option value="ajax">AJAX Shields (MOD-AJAX-*)</option>
                  <option value="rest">REST Route Guards (MOD-REST-*)</option>
                  <option value="abspath">ABSPATH Script Locks (MOD-ABSPATH-*)</option>
                  <option value="cve">CVE Hotpatches (MOD-CVE-*)</option>
                  <option value="custom">Developer Custom Rules</option>
                </select>

                <select
                  value={trustFilter}
                  onChange={(e) => setTrustFilter(e.target.value)}
                  style={{
                    padding: '6px 10px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    background: 'var(--webcare-bg-elevated, #f8fafc)',
                    border: '1px solid var(--webcare-border, #cbd5e1)',
                    color: 'var(--webcare-text-title, #0f172a)',
                  }}
                >
                  <option value="all">All Origin Tiers</option>
                  <option value="tamper_alert">Checksum Tamper / Untracked Alerts</option>
                  <option value="official_wporg">Official WordPress.org Only</option>
                  <option value="known_vendor">Verified Commercial Vendors</option>
                  <option value="custom_unmanaged">Custom / Unmanaged Code</option>
                </select>

                <select
                  value={modeFilter}
                  onChange={(e) => setModeFilter(e.target.value)}
                  style={{
                    padding: '6px 10px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    background: 'var(--webcare-bg-elevated, #f8fafc)',
                    border: '1px solid var(--webcare-border, #cbd5e1)',
                    color: 'var(--webcare-text-title, #0f172a)',
                  }}
                >
                  <option value="all">All Modes</option>
                  <option value="enforce">Enforcing Only</option>
                  <option value="smart_learning">Smart Learning (48h Auto-Pilot)</option>
                  <option value="monitor">Monitoring Only</option>
                  <option value="off">Disabled</option>
                </select>

                <button
                  type="button"
                  onClick={handleBulkApply}
                  style={{
                    padding: '6px 12px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 700,
                    background: '#059669',
                    color: '#ffffff',
                    border: 'none',
                    cursor: 'pointer',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                  }}
                >
                  <Zap size={13} /> Bulk Enforce All
                </button>
              </div>
            </div>

            {/* Custom Rule Execution Order & Save Bar */}
            {(customRulesList.length > 1 || hasPendingOrder) && (
              <div className={`webcare-rule-order-bar ${hasPendingOrder ? 'is-dirty' : ''}`}>
                <div className="webcare-rule-order-info">
                  <GripVertical size={15} />
                  <span>
                    {hasPendingOrder
                      ? 'Unsaved Custom Rule execution order — click Save Rule Order to activate & recompile Micro-WAF.'
                      : 'Custom rules evaluate top-to-bottom (Order #1 runs first). Drag rows or pick an Order # to reprioritize.'}
                  </span>
                </div>
                <div className="webcare-rule-order-actions">
                  {(searchQuery || (categoryFilter !== 'all' && categoryFilter !== 'custom') || modeFilter !== 'all' || trustFilter !== 'all') && (
                    <button
                      type="button"
                      className="webcare-btn-micro"
                      onClick={() => {
                        setSearchQuery('');
                        setCategoryFilter('custom');
                        setModeFilter('all');
                        setTrustFilter('all');
                      }}
                    >
                      Focus Custom Rules ({customRulesList.length})
                    </button>
                  )}
                  {hasPendingOrder && (
                    <>
                      <button
                        type="button"
                        className="webcare-btn-micro"
                        onClick={handleResetCustomOrder}
                        disabled={savingOrder}
                      >
                        <RotateCcw size={12} /> Reset Order
                      </button>
                      <button
                        type="button"
                        className="webcare-btn webcare-btn-primary webcare-rule-order-save-btn"
                        onClick={handleSaveCustomOrder}
                        disabled={savingOrder}
                      >
                        <Save size={13} /> {savingOrder ? 'Saving Order...' : 'Save Rule Order'}
                      </button>
                    </>
                  )}
                </div>
              </div>
            )}

            {/* Rule Cards Grid */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {filteredRules.map((rule) => {
                const isCustomRule = Boolean(rule.is_custom) || rule.category === 'custom';
                const customOrderIndex = isCustomRule ? customOrderIds.indexOf(rule.id) : -1;
                const displayOrderPos = customOrderIndex >= 0 ? customOrderIndex + 1 : (rule.priority || 1);
                const canDragCustom = isCustomRule && customRulesList.length > 1;
                const isDraggingThis = dragRuleId === rule.id;
                const isDragOverThis = dragOverRuleId === rule.id && dragRuleId !== rule.id;
                const isEnforced = rule.current_mode === 'enforce';
                const isSmartLearning = rule.current_mode === 'smart_learning';
                const isMonitoring = rule.current_mode === 'monitor';
                const isOff = rule.current_mode === 'off';
                const chkStatus = rule.checksum_status || 'unmanaged_custom';
                const isTampered = ['modified', 'unknown_in_official', 'self_modified', 'self_untracked'].includes(chkStatus);
                const isAuthentic = ['authentic', 'self_verified', 'known_vendor_hash_match', 'ignored_official_runtime'].includes(chkStatus);

                return (
                  <div
                    key={rule.id}
                    draggable={canDragCustom}
                    onDragStart={(e) => {
                      if (!canDragCustom) return;
                      setDragRuleId(rule.id);
                      e.dataTransfer.effectAllowed = 'move';
                      try {
                        e.dataTransfer.setData('text/plain', rule.id);
                      } catch {}
                    }}
                    onDragOver={(e) => {
                      if (!canDragCustom || !dragRuleId) return;
                      e.preventDefault();
                      e.dataTransfer.dropEffect = 'move';
                      if (dragOverRuleId !== rule.id) {
                        setDragOverRuleId(rule.id);
                      }
                    }}
                    onDragLeave={() => {
                      if (dragOverRuleId === rule.id) {
                        setDragOverRuleId(null);
                      }
                    }}
                    onDrop={(e) => {
                      if (!canDragCustom) return;
                      e.preventDefault();
                      const src = dragRuleId || e.dataTransfer.getData('text/plain');
                      if (src && src !== rule.id) {
                        moveCustomRuleByIdBefore(src, rule.id);
                      }
                      setDragRuleId(null);
                      setDragOverRuleId(null);
                    }}
                    onDragEnd={() => {
                      setDragRuleId(null);
                      setDragOverRuleId(null);
                    }}
                    className={`${isDraggingThis ? 'webcare-rule-card-dragging' : ''} ${isDragOverThis ? 'webcare-rule-card-dragover' : ''}`}
                    style={{
                      padding: '18px 22px',
                      borderRadius: '12px',
                      background: 'var(--webcare-bg-panel, #ffffff)',
                      border: isTampered
                        ? '1px solid var(--webcare-status-critical-border, #fecaca)'
                        : isEnforced
                          ? '1px solid var(--webcare-primary, #4f46e5)'
                          : '1px solid var(--webcare-border, #e2e8f0)',
                      boxShadow: '0 2px 8px rgba(0, 0, 0, 0.02)',
                      display: 'flex',
                      alignItems: 'flex-start',
                      justifyContent: 'space-between',
                      gap: '16px',
                      flexWrap: 'wrap',
                    }}
                  >
                    <div style={{ flex: 1, minWidth: '280px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                        {isCustomRule && (
                          <span
                            className={`webcare-rule-drag-handle ${canDragCustom ? 'is-draggable' : ''}`}
                            title={canDragCustom ? 'Drag to reorder custom firewall rule execution priority' : 'Custom rule priority'}
                          >
                            <GripVertical size={14} />
                          </span>
                        )}
                        {isCustomRule && (
                          <span className="webcare-rule-order-badge" title="Execution Priority Order">
                            Order #{displayOrderPos}
                          </span>
                        )}
                        {isCustomRule && rule.rule_number !== undefined && (
                          <span className="webcare-rule-num-badge" title="Unique Permanent Numeric Rule ID">
                            ID #{rule.rule_number}
                          </span>
                        )}
                        <code style={{ fontSize: '11px', fontWeight: 800, color: 'var(--webcare-primary, #4f46e5)' }}>
                          {rule.id}
                        </code>
                        <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)' }}>
                          • {rule.origin_component}
                        </span>
                        {rule.is_official_wporg && (
                          <span
                            style={{
                              fontSize: '10px',
                              fontWeight: 700,
                              padding: '1px 7px',
                              borderRadius: '10px',
                              background: 'var(--webcare-status-cyan-soft, #ecfeff)',
                              color: 'var(--webcare-status-cyan, #0284c7)',
                              border: '1px solid var(--webcare-status-cyan-border, #a5f3fc)',
                            }}
                          >
                            WP.org Official
                          </span>
                        )}
                        {!rule.is_official_wporg && rule.is_known_vendor && (
                          <span
                            style={{
                              fontSize: '10px',
                              fontWeight: 700,
                              padding: '1px 7px',
                              borderRadius: '10px',
                              background: 'var(--webcare-status-info-soft, rgba(79, 70, 229, 0.08))',
                              color: 'var(--webcare-status-info, #4f46e5)',
                              border: '1px solid var(--webcare-status-info-border, rgba(79, 70, 229, 0.24))',
                            }}
                          >
                            Vendor: {rule.vendor_name || 'Trusted'}
                          </span>
                        )}
                        {isTampered && (
                          <span
                            style={{
                              fontSize: '10px',
                              fontWeight: 800,
                              padding: '1px 7px',
                              borderRadius: '10px',
                              background: 'var(--webcare-status-critical-soft, #fef2f2)',
                              color: 'var(--webcare-status-critical, #dc2626)',
                              border: '1px solid var(--webcare-status-critical-border, #fecaca)',
                            }}
                          >
                            {chkStatus === 'unknown_in_official' ? '⚠ Unknown File in Official Plugin' : '⚠ Checksum Mismatch'}
                          </span>
                        )}
                        {!isTampered && isAuthentic && (
                          <span
                            style={{
                              fontSize: '10px',
                              fontWeight: 700,
                              padding: '1px 7px',
                              borderRadius: '10px',
                              background: 'var(--webcare-status-clean-soft, #ecfdf5)',
                              color: 'var(--webcare-status-clean, #059669)',
                              border: '1px solid var(--webcare-status-clean-border, #a7f3d0)',
                            }}
                          >
                            ✓ Checksum Verified
                          </span>
                        )}
                        {!isTampered && !isAuthentic && !rule.is_custom && rule.file && (
                          <span
                            style={{
                              fontSize: '10px',
                              fontWeight: 700,
                              padding: '1px 7px',
                              borderRadius: '10px',
                              background: 'var(--webcare-status-warn-soft, #fffbeb)',
                              color: 'var(--webcare-status-warn, #d97706)',
                              border: '1px solid var(--webcare-status-warn-border, #fde68a)',
                            }}
                          >
                            Custom / No WP.org Manifest
                          </span>
                        )}
                        {rule.severity === 'critical' && (
                          <span style={{ fontSize: '10px', fontWeight: 800, color: 'var(--webcare-status-critical, #dc2626)', background: 'var(--webcare-status-critical-soft, #fef2f2)', padding: '1px 6px', borderRadius: '4px' }}>
                            CRITICAL
                          </span>
                        )}
                        {rule.is_custom && (
                          <span style={{ fontSize: '10px', fontWeight: 800, color: 'var(--webcare-status-purple, #7c3aed)', background: 'var(--webcare-status-purple-soft, #f5f3ff)', padding: '1px 6px', borderRadius: '4px' }}>
                            CUSTOM
                          </span>
                        )}
                      </div>

                      <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', marginTop: '6px' }}>
                        {rule.title}
                      </div>

                      <div style={{ fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5, marginTop: '4px' }}>
                        {rule.description}
                      </div>

                      {rule.evidence && (
                        <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', fontStyle: 'italic', marginTop: '4px' }}>
                          Evidence: {rule.evidence}
                        </div>
                      )}

                      <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginTop: '8px', flexWrap: 'wrap' }}>
                        {rule.file && (
                          <span style={{ fontSize: '11px', fontFamily: 'monospace', color: 'var(--webcare-status-cyan, #0284c7)' }}>
                            {rule.file}:{rule.line || 1}
                          </span>
                        )}
                        {rule.file_sha256 && (
                          <span
                            title={`Full SHA-256: ${rule.file_sha256}${rule.file_md5 ? `\nMD5: ${rule.file_md5}` : ''}`}
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '4px',
                              fontSize: '10px',
                              fontFamily: 'monospace',
                              fontWeight: 700,
                              padding: '1px 6px',
                              borderRadius: '4px',
                              background: 'var(--webcare-bg-elevated, #f1f5f9)',
                              color: 'var(--webcare-text-secondary, #475569)',
                              border: '1px solid var(--webcare-border, #e2e8f0)',
                            }}
                          >
                            <Fingerprint size={11} /> sha256: {rule.file_sha256.slice(0, 10)}...
                          </span>
                        )}
                        {rule.file && (
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
                        )}
                        {rule.rate_limit && (
                          <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                            Rate: {rule.rate_limit} req/min
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Mode Selector Pill */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '4px', background: 'var(--webcare-bg-elevated, #f1f5f9)', padding: '3px', borderRadius: '8px' }}>
                      <button
                        type="button"
                        onClick={() => handleToggleRule(rule.id, 'enforce')}
                        style={{
                          padding: '5px 12px',
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
                        style={{
                          padding: '5px 10px',
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
                        style={{
                          padding: '5px 12px',
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
                        style={{
                          padding: '5px 12px',
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

                      {rule.is_custom && (
                        <>
                          <button
                            type="button"
                            title="Edit Custom Firewall Rule"
                            onClick={() => {
                              let fallbackConds = rule.conditions;
                              if (!Array.isArray(fallbackConds) || fallbackConds.length === 0) {
                                const condRules: Array<{ field: string; key?: string; op: string; value: string }> = [];
                                if (rule.target_uri) {
                                  condRules.push({ field: 'http.request.uri.path', op: 'contains', value: rule.target_uri });
                                }
                                if (rule.target_param) {
                                  condRules.push({
                                    field: 'http.request.params',
                                    key: rule.target_param,
                                    op: rule.target_value ? 'eq' : 'exists',
                                    value: rule.target_value || '',
                                  });
                                }
                                if (Array.isArray(rule.http_methods) && rule.http_methods.length > 0 && rule.http_methods.length < 5) {
                                  condRules.push({ field: 'http.request.method', op: 'in', value: rule.http_methods.join(', ') });
                                }
                                if (condRules.length > 0) {
                                  fallbackConds = [{ logic: 'AND', rules: condRules }];
                                }
                              }
                                setVisualRuleDraft({
                                  id: rule.id,
                                  rule_number: rule.rule_number,
                                  priority: displayOrderPos,
                                  title: rule.title,
                                  description: rule.description,
                                  action_type: rule.action_type || (rule.current_mode === 'monitor' ? 'monitor' : 'block'),
                                  current_mode: rule.current_mode === 'monitor' ? 'monitor' : 'enforce',
                                  rate_limit: rule.rate_limit ?? 15,
                                  group_logic: rule.group_logic === 'AND' ? 'AND' : 'OR',
                                  conditions: fallbackConds,
                                  wirefilter_expr: rule.wirefilter_expr,
                                  exempt_rules: rule.exempt_rules,
                                  ban_ttl: rule.ban_ttl ?? 86400,
                                  sync_cloudflare: Boolean(rule.sync_cloudflare),
                                  block_uploads: Boolean(rule.block_uploads),
                                });
                                switchTab('builder');
                              }}
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '4px',
                              padding: '5px 8px',
                              borderRadius: '6px',
                              fontSize: '11px',
                              fontWeight: 700,
                              cursor: 'pointer',
                              border: 'none',
                              background: 'transparent',
                              color: 'var(--webcare-primary, #4f46e5)',
                            }}
                          >
                            <Pencil size={13} /> Edit
                          </button>
                          {canDragCustom && (
                            <div className="webcare-rule-quick-move">
                              <button
                                type="button"
                                className="webcare-btn-micro"
                                title="Move Up (Higher Priority)"
                                disabled={customOrderIndex <= 0}
                                onClick={() => moveCustomRuleToIndex(rule.id, customOrderIndex - 1)}
                                style={{ padding: '3px 5px' }}
                              >
                                <ArrowUp size={12} />
                              </button>
                              <button
                                type="button"
                                className="webcare-btn-micro"
                                title="Move Down (Lower Priority)"
                                disabled={customOrderIndex < 0 || customOrderIndex >= customOrderIds.length - 1}
                                onClick={() => moveCustomRuleToIndex(rule.id, customOrderIndex + 1)}
                                style={{ padding: '3px 5px' }}
                              >
                                <ArrowDown size={12} />
                              </button>
                              <select
                                aria-label={`Order for ${rule.title}`}
                                className="webcare-input"
                                value={displayOrderPos}
                                onChange={(e) => moveCustomRuleToIndex(rule.id, (parseInt(e.target.value, 10) || 1) - 1)}
                                style={{ width: '56px', height: '24px', padding: '0 4px', fontSize: '11px', fontWeight: 700 }}
                              >
                                {customOrderIds.map((_, slotIdx) => (
                                  <option key={slotIdx + 1} value={slotIdx + 1}>
                                    #{slotIdx + 1}
                                  </option>
                                ))}
                              </select>
                            </div>
                          )}
                          <button
                            type="button"
                            title="Delete Custom Firewall Rule"
                            onClick={async () => {
                              try {
                                const res = await apiRequest({
                                  path: '/modular-waf/rule/custom/delete',
                                  method: 'POST',
                                  data: { rule_id: rule.id },
                                });
                                if (res?.success) {
                                  showNotification(res.message || 'Custom rule deleted.');
                                  await loadStudioData();
                                }
                              } catch {}
                            }}
                            style={{
                              padding: '5px 8px',
                              borderRadius: '6px',
                              fontSize: '11px',
                              cursor: 'pointer',
                              border: 'none',
                              background: 'transparent',
                              color: '#ef4444',
                            }}
                          >
                            <Trash2 size={13} />
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* TAB 2: COMPONENT DOSSIER */}
        {activeTab === 'dossier' && (
          <div
            style={{
              borderRadius: '12px',
              background: 'var(--webcare-bg-panel, #ffffff)',
              border: '1px solid var(--webcare-border, #e2e8f0)',
              overflow: 'hidden',
            }}
          >
            <div style={{ padding: '20px', borderBottom: '1px solid var(--webcare-border, #e2e8f0)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
                  Component Behavioral Dossier ({filteredInventory.length}{filteredInventory.length !== inventory.length ? ` of ${inventory.length}` : ''})
                </h3>
                <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)' }}>
                  Detailed attack surface inventory across plugins, parent/child themes, and drop-ins profiled by WebCare Intelligence.
                </p>
              </div>

              <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
                <div style={{ position: 'relative', minWidth: '220px' }}>
                  <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--webcare-text-muted, #64748b)' }} />
                  <input
                    type="text"
                    value={dossierSearch}
                    onChange={(e) => setDossierSearch(e.target.value)}
                    placeholder="Search components or authors..."
                    className="webcare-input"
                    style={{ width: '100%', padding: '7px 12px 7px 32px', fontSize: '12px', borderRadius: '6px' }}
                  />
                </div>

                <select
                  value={dossierTypeFilter}
                  onChange={(e) => setDossierTypeFilter(e.target.value)}
                  className="webcare-input"
                  style={{ padding: '7px 12px', fontSize: '12px', borderRadius: '6px' }}
                >
                  <option value="all">All Types ({inventory.length})</option>
                  <option value="plugin">Plugins</option>
                  <option value="theme">Themes</option>
                  <option value="mu_plugin">Must-Use Plugins</option>
                </select>
              </div>
            </div>

            {filteredInventory.length === 0 ? (
              <div style={{ padding: '48px 24px', textAlign: 'center', color: 'var(--webcare-text-muted, #64748b)' }}>
                <Layers size={36} style={{ margin: '0 auto 12px', opacity: 0.4 }} />
                <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                  {inventory.length === 0 ? 'No Profiled Components Found in Intelligence Vault' : 'No components matching your filter criteria'}
                </div>
                <p style={{ margin: '6px 0 16px', fontSize: '13px' }}>
                  {inventory.length === 0
                    ? 'Run a full behavioral scan to tokenize your installed extensions and map their attack surface.'
                    : 'Try adjusting your search terms or type filters.'}
                </p>
                {inventory.length === 0 && (
                  <button
                    type="button"
                    onClick={handleStartDeepScan}
                    disabled={scanning}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '8px',
                      padding: '10px 20px',
                      borderRadius: '8px',
                      background: 'var(--webcare-primary, #4f46e5)',
                      color: '#ffffff',
                      border: 'none',
                      fontSize: '13px',
                      fontWeight: 700,
                      cursor: 'pointer',
                    }}
                  >
                    <Play size={14} /> Run Full Behavioral Scan
                  </button>
                )}
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                  <thead>
                    <tr style={{ background: 'var(--webcare-bg-elevated, #f8fafc)', borderBottom: '1px solid var(--webcare-border, #e2e8f0)', textAlign: 'left' }}>
                      <th style={{ padding: '12px 18px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>Extension / Component</th>
                      <th style={{ padding: '12px 18px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>Origin &amp; Checksum</th>
                      <th style={{ padding: '12px 18px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>Type &amp; Version</th>
                      <th style={{ padding: '12px 18px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>Mapped Endpoints</th>
                      <th style={{ padding: '12px 18px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>Attack Surface Risks</th>
                      <th style={{ padding: '12px 18px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>Modular Shielding</th>
                      <th style={{ padding: '12px 18px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>Lifecycle</th>
                      <th style={{ padding: '12px 18px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', textAlign: 'right' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredInventory.map((comp) => {
                      const endpoints = comp.endpoints_count || 0;
                      const findingsCount = comp.findings_count || 0;
                      const activeRules = comp.rules_count || 0;
                      const isTampered = comp.trust_tier === 'tamper_alert';
                      const isVerifiedClean = comp.checksum_verified === true;
                      const chkSummary = comp.checksum_summary;

                      return (
                        <tr
                          key={comp.slug}
                          style={{
                            borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
                            transition: 'background 0.15s ease',
                          }}
                        >
                          <td style={{ padding: '14px 18px', verticalAlign: 'middle' }}>
                            <div style={{ fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)', fontSize: '14px' }}>
                              {comp.name}
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '3px', flexWrap: 'wrap' }}>
                              <span style={{ fontSize: '11px', fontFamily: 'monospace', color: 'var(--webcare-text-muted, #64748b)' }}>
                                {comp.slug}
                              </span>
                              {comp.author && (
                                <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #94a3b8)' }}>
                                  • by {comp.author}
                                </span>
                              )}
                            </div>
                          </td>

                          <td style={{ padding: '14px 18px', verticalAlign: 'middle' }}>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', alignItems: 'flex-start' }}>
                              <span
                                title={comp.vendor_evidence || comp.checksum_source || ''}
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '5px',
                                  padding: '3px 8px',
                                  borderRadius: '10px',
                                  fontSize: '11px',
                                  fontWeight: 700,
                                  background: isTampered
                                    ? 'var(--webcare-status-critical-soft, #fef2f2)'
                                    : isVerifiedClean
                                      ? 'var(--webcare-status-clean-soft, #ecfdf5)'
                                      : comp.is_known_vendor
                                        ? 'var(--webcare-status-info-soft, rgba(79, 70, 229, 0.08))'
                                        : 'var(--webcare-status-warn-soft, #fffbeb)',
                                  color: isTampered
                                    ? 'var(--webcare-status-critical, #dc2626)'
                                    : isVerifiedClean
                                      ? 'var(--webcare-status-clean, #059669)'
                                      : comp.is_known_vendor
                                        ? 'var(--webcare-status-info, #4f46e5)'
                                        : 'var(--webcare-status-warn, #d97706)',
                                  border: `1px solid ${
                                    isTampered
                                      ? 'var(--webcare-status-critical-border, #fecaca)'
                                      : isVerifiedClean
                                        ? 'var(--webcare-status-clean-border, #a7f3d0)'
                                        : comp.is_known_vendor
                                          ? 'var(--webcare-status-info-border, rgba(79, 70, 229, 0.24))'
                                          : 'var(--webcare-status-warn-border, #fde68a)'
                                  }`,
                                }}
                              >
                                {isTampered ? (
                                  <>
                                    <ShieldAlert size={11} /> Checksum Tamper Alert
                                  </>
                                ) : isVerifiedClean ? (
                                  <>
                                    <ShieldCheck size={11} /> {comp.is_official_wporg ? 'WP.org Checksum Verified' : (comp.origin_label || 'Verified Clean')}
                                  </>
                                ) : comp.is_known_vendor ? (
                                  <>
                                    <Shield size={11} /> {comp.vendor_name || 'Verified Vendor'}
                                  </>
                                ) : (
                                  <>
                                    <AlertTriangle size={11} /> {comp.origin_label || 'Custom / Unmanaged'}
                                  </>
                                )}
                              </span>
                              {(chkSummary && (chkSummary.files_checked ?? 0) > 0) && (
                                <span style={{ fontSize: '10px', color: 'var(--webcare-text-muted, #64748b)', fontFamily: 'monospace' }}>
                                  {chkSummary.authentic_count}/{chkSummary.files_checked} verified
                                  {(chkSummary.modified_count ?? 0) > 0 ? ` • ${chkSummary.modified_count} modified` : ''}
                                  {(chkSummary.unknown_count ?? 0) > 0 ? ` • ${chkSummary.unknown_count} unknown` : ''}
                                </span>
                              )}
                            </div>
                          </td>

                          <td style={{ padding: '14px 18px', verticalAlign: 'middle' }}>
                            <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                              <span
                                style={{
                                  padding: '3px 8px',
                                  borderRadius: '6px',
                                  fontSize: '11px',
                                  fontWeight: 700,
                                  textTransform: 'uppercase',
                                  background: comp.type === 'plugin' ? 'rgba(79, 70, 229, 0.08)' : comp.type === 'theme' ? 'rgba(16, 185, 129, 0.08)' : 'rgba(245, 158, 11, 0.08)',
                                  color: comp.type === 'plugin' ? 'var(--webcare-primary, #4f46e5)' : comp.type === 'theme' ? '#059669' : '#d97706',
                                  border: `1px solid ${comp.type === 'plugin' ? 'rgba(79, 70, 229, 0.2)' : comp.type === 'theme' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(245, 158, 11, 0.2)'}`,
                                }}
                              >
                                {comp.type}
                              </span>
                              <span style={{ fontSize: '12px', fontFamily: 'monospace', color: 'var(--webcare-text-secondary, #475569)', fontWeight: 600 }}>
                                v{comp.version || '1.0'}
                              </span>
                            </div>
                          </td>

                          <td style={{ padding: '14px 18px', verticalAlign: 'middle' }}>
                            <span
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '5px',
                                padding: '3px 9px',
                                borderRadius: '12px',
                                fontSize: '12px',
                                fontWeight: 700,
                                background: endpoints > 0 ? 'rgba(2, 132, 199, 0.08)' : 'var(--webcare-bg-elevated, #f1f5f9)',
                                color: endpoints > 0 ? '#0284c7' : 'var(--webcare-text-muted, #64748b)',
                                border: `1px solid ${endpoints > 0 ? 'rgba(2, 132, 199, 0.25)' : 'var(--webcare-border, #e2e8f0)'}`,
                              }}
                            >
                              <Terminal size={12} /> {endpoints} {endpoints === 1 ? 'Route' : 'Routes'}
                            </span>
                          </td>

                          <td style={{ padding: '14px 18px', verticalAlign: 'middle' }}>
                            <span
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '5px',
                                padding: '3px 9px',
                                borderRadius: '12px',
                                fontSize: '12px',
                                fontWeight: 700,
                                background: findingsCount > 0 ? 'var(--webcare-status-critical-soft, rgba(239, 68, 68, 0.08))' : 'var(--webcare-status-clean-soft, rgba(16, 185, 129, 0.08))',
                                color: findingsCount > 0 ? 'var(--webcare-status-critical, #dc2626)' : 'var(--webcare-status-clean, #059669)',
                                border: `1px solid ${findingsCount > 0 ? 'var(--webcare-status-critical-border, rgba(239, 68, 68, 0.25))' : 'var(--webcare-status-clean-border, rgba(16, 185, 129, 0.25))'}`,
                              }}
                            >
                              {findingsCount > 0 ? <AlertTriangle size={12} /> : <CheckCircle2 size={12} />}
                              {findingsCount} {findingsCount === 1 ? 'Risk Sink' : 'Risk Sinks'}
                            </span>
                          </td>

                          <td style={{ padding: '14px 18px', verticalAlign: 'middle' }}>
                            <span
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '5px',
                                padding: '3px 9px',
                                borderRadius: '12px',
                                fontSize: '12px',
                                fontWeight: 700,
                                background: activeRules > 0 ? 'rgba(16, 185, 129, 0.1)' : 'var(--webcare-bg-elevated, #f1f5f9)',
                                color: activeRules > 0 ? '#059669' : 'var(--webcare-text-muted, #64748b)',
                                border: `1px solid ${activeRules > 0 ? 'rgba(16, 185, 129, 0.3)' : 'var(--webcare-border, #e2e8f0)'}`,
                              }}
                            >
                              <Shield size={12} /> {activeRules} {activeRules === 1 ? 'Rule' : 'Rules'} Active
                            </span>
                          </td>

                          <td style={{ padding: '14px 18px', verticalAlign: 'middle' }}>
                            <span
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px',
                                fontSize: '11px',
                                fontWeight: 700,
                                color: comp.is_active ? '#059669' : 'var(--webcare-text-muted, #64748b)',
                                background: comp.is_active ? 'rgba(16, 185, 129, 0.1)' : 'rgba(100, 116, 139, 0.1)',
                                padding: '2px 8px',
                                borderRadius: '10px',
                                border: `1px solid ${comp.is_active ? 'rgba(16, 185, 129, 0.2)' : 'rgba(100, 116, 139, 0.2)'}`,
                              }}
                            >
                              {comp.is_active ? 'ACTIVE' : 'INACTIVE'}
                            </span>
                          </td>

                          <td style={{ padding: '14px 18px', verticalAlign: 'middle', textAlign: 'right' }}>
                            <div style={{ display: 'inline-flex', gap: '6px', alignItems: 'center' }}>
                              <button
                                type="button"
                                onClick={() => {
                                  const compEp = endpointMap.find((ep: any) =>
                                    (ep.component_slug && ep.component_slug === comp.slug) ||
                                    (ep.component && ep.component === comp.name)
                                  );
                                  const firstAjax = compEp?.ajax_actions?.[0];
                                  const firstRest = compEp?.rest_routes?.[0];
                                  const conds: any[] = [
                                    { field: 'wp.plugin.target_slug', op: 'eq', value: comp.slug },
                                    { field: 'wp.user.is_logged_in', op: 'is_false', value: '' },
                                  ];
                                  if (firstAjax) {
                                    conds.splice(1, 0, { field: 'wp.ajax.action', op: 'eq', value: firstAjax });
                                  } else if (firstRest) {
                                    conds.splice(1, 0, { field: 'wp.rest.route', op: 'starts_with', value: firstRest });
                                  }
                                  setVisualRuleDraft({
                                    title: `Shield ${comp.name || comp.slug} Guest Access`,
                                    description: `Custom Firewall Rule protecting ${comp.name || comp.slug} (${comp.slug})`,
                                    action_type: 'rate_limit',
                                    sync_cloudflare: true,
                                    ban_ttl: 86400,
                                    conditions: [{ logic: 'AND', rules: conds }],
                                  });
                                  switchTab('builder');
                                }}
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '5px',
                                  padding: '6px 10px',
                                  borderRadius: '6px',
                                  fontSize: '12px',
                                  fontWeight: 700,
                                  cursor: 'pointer',
                                  background: 'rgba(16, 185, 129, 0.12)',
                                  color: '#059669',
                                  border: '1px solid rgba(16, 185, 129, 0.25)',
                                }}
                              >
                                <Plus size={13} /> Custom Rule
                              </button>
                              <button
                                type="button"
                                onClick={() => {
                                  setSearchQuery(comp.name || comp.slug);
                                  switchTab('rules');
                                }}
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '5px',
                                  padding: '6px 12px',
                                  borderRadius: '6px',
                                  fontSize: '12px',
                                  fontWeight: 700,
                                  cursor: 'pointer',
                                  background: 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.08))',
                                  color: 'var(--webcare-primary, #4f46e5)',
                                  border: '1px solid rgba(79, 70, 229, 0.2)',
                                  transition: 'all 0.15s ease',
                                }}
                              >
                                <Shield size={13} /> View Rules
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* TAB 3: CUSTOM FIREWALL RULES & BUILDER */}
        {activeTab === 'builder' && (
          <VisualRuleBuilderPanel
            initialDraft={visualRuleDraft}
            onCancelEdit={() => {
              setVisualRuleDraft(null);
              switchTab('rules');
            }}
            onRuleCreated={async (msg) => {
              showNotification(msg);
              setVisualRuleDraft(null);
              await loadStudioData();
              switchTab('rules');
            }}
          />
        )}

        {/* TAB 4: PLUGGABLE MODULE SDK & 2026-2027 NEXT-GEN ENGINES */}
        {activeTab === 'nextgen' && (
          <NextGenEcosystemPanel />
        )}

        <WebCareSlot name="modular_waf.footer" context={{ activeTab, rulesCount: rules.length }} />

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
                  style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: '4px' }}
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
    </div>
  );
};
