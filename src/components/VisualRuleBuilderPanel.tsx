import React, { Fragment, useState, useEffect, useMemo } from '@wordpress/element';
import {
  Trash2,
  Play,
  Cloud,
  Copy,
  Check,
  ShieldCheck,
  RefreshCw,
  AlertTriangle,
  ChevronDown,
  Sparkles,
  ClipboardPaste,
  Cpu,
  Info,
} from 'lucide-react';
import { apiRequest } from '../utils/api';
import { buildAiRuleMarkdownPrompt } from '../utils/aiRulePromptBuilder';
import {
  SmartConditionValueInput,
  InstalledComponentOption,
  WpRoleOption,
} from './visual-rule/SmartConditionInputs';

export interface ConditionClause {
  field: string;
  key?: string;
  op: string;
  value: string;
}

export interface ConditionGroup {
  logic: 'AND' | 'OR';
  rules: ConditionClause[];
}

export interface VisualRuleDraft {
  id?: string;
  rule_number?: number;
  priority?: number;
  title?: string;
  description?: string;
  action_type?: string;
  current_mode?: 'enforce' | 'monitor';
  rate_limit?: number;
  group_logic?: 'AND' | 'OR';
  conditions?: ConditionGroup[];
  wirefilter_expr?: string;
  exempt_rules?: string[];
  ban_ttl?: number;
  sync_cloudflare?: boolean;
  block_uploads?: boolean;
}

interface FieldSchemaItem {
  id: string;
  label: string;
  layer: string;
  needs_key?: boolean;
  key_placeholder?: string;
  edge?: boolean;
  preload?: boolean;
  ops: string[];
}

interface ExistingCustomRuleMeta {
  id: string;
  rule_number: number;
  priority: number;
  title: string;
  action_type: string;
  current_mode: string;
}

interface CloudflareConnectionStatus {
  enabled: boolean;
  configured: boolean;
  connected: boolean;
  proxied: boolean;
  zone_name: string;
}

interface RulePreset {
  id: string;
  label: string;
  title: string;
  action_type: string;
  group_logic: 'AND' | 'OR';
  groups: ConditionGroup[];
}

const DEFAULT_FIELDS: FieldSchemaItem[] = [
  { id: 'http.request.uri.path', label: 'URI Path', layer: 'HTTP Request', edge: true, preload: true, ops: ['eq', 'ne', 'contains', 'not_contains', 'starts_with', 'ends_with', 'matches_regex', 'in'] },
  { id: 'http.request.uri.query', label: 'URI Query String', layer: 'HTTP Request', edge: true, preload: true, ops: ['eq', 'ne', 'contains', 'not_contains', 'matches_regex'] },
  { id: 'http.request.method', label: 'HTTP Method', layer: 'HTTP Request', edge: true, preload: true, ops: ['eq', 'ne', 'in', 'not_in'] },
  { id: 'http.user_agent', label: 'User-Agent', layer: 'HTTP Request', edge: true, preload: true, ops: ['eq', 'contains', 'not_contains', 'matches_regex', 'in'] },
  { id: 'http.referer', label: 'Referer URL', layer: 'HTTP Request', edge: true, preload: true, ops: ['eq', 'contains', 'not_contains', 'matches_regex'] },
  { id: 'http.cookie', label: 'Cookie Header / Name', layer: 'HTTP Request', edge: true, preload: true, ops: ['contains', 'not_contains', 'matches_regex'] },
  { id: 'http.headers', label: 'Request Header [<name>]', layer: 'HTTP Request', needs_key: true, key_placeholder: 'Header name', edge: true, preload: true, ops: ['exists', 'not_exists', 'eq', 'contains', 'matches_regex'] },
  { id: 'ip.src', label: 'Client IP Address', layer: 'Network & Geo', edge: true, preload: true, ops: ['eq', 'ne', 'in_cidr', 'not_in_cidr'] },
  { id: 'ip.geoip.country', label: 'Country / Region (GeoIP)', layer: 'Network & Geo', edge: true, preload: true, ops: ['eq', 'ne', 'in', 'not_in'] },
  { id: 'ip.geoip.asnum', label: 'ASN Number', layer: 'Network & Geo', edge: true, preload: true, ops: ['eq', 'ne', 'in', 'not_in'] },
  { id: 'http.request.params', label: 'Request Param [<key>]', layer: 'Payload & Upload', needs_key: true, key_placeholder: 'Param name', edge: false, preload: true, ops: ['exists', 'not_exists', 'eq', 'contains', 'matches_regex', 'is_array'] },
  { id: 'http.upload.extension', label: 'Upload File Extension', layer: 'Payload & Upload', edge: false, preload: true, ops: ['eq', 'in', 'matches_regex'] },
  { id: 'wp.plugin.target_slug', label: 'WP Plugin / Theme Slug', layer: 'WordPress Runtime', edge: false, preload: false, ops: ['eq', 'ne', 'in'] },
  { id: 'wp.ajax.action', label: 'WP AJAX Action', layer: 'WordPress Runtime', edge: false, preload: true, ops: ['eq', 'ne', 'starts_with', 'contains', 'in'] },
  { id: 'wp.rest.route', label: 'WP REST Route', layer: 'WordPress Runtime', edge: false, preload: true, ops: ['eq', 'starts_with', 'contains', 'matches_regex'] },
  { id: 'wp.user.is_logged_in', label: 'WP User Logged In', layer: 'WordPress Runtime', edge: false, preload: false, ops: ['is_true', 'is_false'] },
  { id: 'wp.user.role', label: 'WP User Role', layer: 'WordPress Runtime', edge: false, preload: false, ops: ['has', 'not_has', 'in'] },
  { id: 'wp.woo.has_cart_session', label: 'Woo / Cart Session', layer: 'WordPress Runtime', edge: false, preload: false, ops: ['is_true', 'is_false'] },
];

const OP_LABELS: Record<string, string> = {
  eq: 'equals',
  ne: 'does not equal',
  contains: 'contains',
  not_contains: 'does not contain',
  starts_with: 'starts with',
  ends_with: 'ends with',
  matches_regex: 'matches regex',
  in: 'is in',
  not_in: 'is not in',
  in_cidr: 'is in CIDR',
  not_in_cidr: 'is not in CIDR',
  exists: 'exists',
  not_exists: 'does not exist',
  is_array: 'is array',
  is_true: 'is true',
  is_false: 'is false',
  has: 'has role',
  not_has: 'does not have role',
};

const QUICK_TEMPLATES: RulePreset[] = [
  {
    id: 'country_block',
    label: 'Block by Country',
    title: 'Block Traffic by Country',
    action_type: 'block',
    group_logic: 'OR',
    groups: [{ logic: 'AND', rules: [{ field: 'ip.geoip.country', op: 'in', value: '' }] }],
  },
  {
    id: 'plugin_url',
    label: 'Protect Plugin / Theme URL',
    title: 'Protect Plugin / Theme Path',
    action_type: 'block',
    group_logic: 'AND',
    groups: [
      {
        logic: 'AND',
        rules: [
          { field: 'http.request.uri.path', op: 'starts_with', value: '' },
          { field: 'wp.user.is_logged_in', op: 'is_false', value: '' },
        ],
      },
    ],
  },
  {
    id: 'allow_ip',
    label: 'Allow Trusted IP',
    title: 'Allow Trusted IP',
    action_type: 'allow',
    group_logic: 'OR',
    groups: [{ logic: 'AND', rules: [{ field: 'ip.src', op: 'in_cidr', value: '' }] }],
  },
];

function clauseToWirefilter(c: ConditionClause): string {
  if (!c.field || !c.op) return '';
  if (c.field === 'wp.user.is_logged_in' || c.field === 'wp.woo.has_cart_session') {
    return c.op === 'is_false' ? `not ${c.field}` : c.field;
  }
  const f = c.field === 'http.headers'
    ? `http.headers["${c.key || ''}"]`
    : c.field === 'http.request.params'
      ? `http.request.params["${c.key || ''}"]`
      : c.field;
  const rawVal = c.field === 'ip.geoip.country' ? (c.value || '').toUpperCase() : (c.value || '');
  const q = `"${rawVal.replace(/"/g, '\\"')}"`;
  switch (c.op) {
    case 'eq': return `${f} eq ${q}`;
    case 'ne': return `${f} ne ${q}`;
    case 'contains': return `${f} contains ${q}`;
    case 'not_contains': return `not (${f} contains ${q})`;
    case 'starts_with': return `starts_with(${f}, ${q})`;
    case 'ends_with': return `ends_with(${f}, ${q})`;
    case 'matches_regex': return `${f} matches ${q}`;
    case 'in':
    case 'has':
    case 'in_cidr': {
      const parts = rawVal.split(/[\s,]+/).filter(Boolean).map((v) => `"${v}"`).join(' ');
      return `${f} in {${parts}}`;
    }
    case 'not_in':
    case 'not_has':
    case 'not_in_cidr': {
      const parts = rawVal.split(/[\s,]+/).filter(Boolean).map((v) => `"${v}"`).join(' ');
      return `not (${f} in {${parts}})`;
    }
    case 'exists': return `${f} exists`;
    case 'not_exists': return `not (${f} exists)`;
    case 'is_array': return `${f} is_array`;
    default: return `${f} eq ${q}`;
  }
}

export const VisualRuleBuilderPanel: React.FC<{
  initialDraft?: VisualRuleDraft | null;
  onRuleCreated: (msg: string) => Promise<void> | void;
  onCancelEdit?: () => void;
}> = ({ initialDraft, onRuleCreated, onCancelEdit }) => {
  const [fields, setFields] = useState<FieldSchemaItem[]>(DEFAULT_FIELDS);
  const [installedComponents, setInstalledComponents] = useState<InstalledComponentOption[]>([]);
  const [wpRoles, setWpRoles] = useState<WpRoleOption[]>([]);
  const [currentIp, setCurrentIp] = useState<string>('');
  const [discoveredEndpoints, setDiscoveredEndpoints] = useState<{ ajax_actions: string[]; rest_routes: string[] }>({
    ajax_actions: [],
    rest_routes: [],
  });
  const [existingCustomRules, setExistingCustomRules] = useState<ExistingCustomRuleMeta[]>([]);

  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [editingRuleNumber, setEditingRuleNumber] = useState<number | null>(null);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [showDesc, setShowDesc] = useState(false);

  const [actionType, setActionType] = useState('');
  const [mode, setMode] = useState<'enforce' | 'monitor'>('enforce');
  const [rateLimit, setRateLimit] = useState(15);
  const [banTtl, setBanTtl] = useState(86400);
  const [syncCloudflare, setSyncCloudflare] = useState(true);
  const [blockUploads, setBlockUploads] = useState(true);
  const [exemptRules, setExemptRules] = useState('');

  const [placement, setPlacement] = useState<'last' | 'first' | 'custom'>('last');
  const [orderPosition, setOrderPosition] = useState<number>(1);
  const [groupLogic, setGroupLogic] = useState<'OR' | 'AND'>('OR');
  const [groups, setGroups] = useState<ConditionGroup[]>([
    { logic: 'AND', rules: [{ field: '', op: '', value: '' }] },
  ]);

  const [editingExpression, setEditingExpression] = useState(false);
  const [wirefilterOverride, setWirefilterOverride] = useState<string | null>(null);
  const [copiedWf, setCopiedWf] = useState(false);
  const [templateMenuOpen, setTemplateMenuOpen] = useState(false);

  const [submitting, setSubmitting] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [cloudflareStatus, setCloudflareStatus] = useState<CloudflareConnectionStatus>({
    enabled: false,
    configured: false,
    connected: false,
    proxied: false,
    zone_name: '',
  });
  const [aiStatus, setAiStatus] = useState<{ configured: boolean; provider: string; model: string }>({
    configured: false,
    provider: 'gemini',
    model: '',
  });
  const [mcpStatus, setMcpStatus] = useState<{ enabled: boolean; scope: string; modular_tools: number }>({
    enabled: true,
    scope: 'read_only',
    modular_tools: 6,
  });
  const [aiGoal, setAiGoal] = useState('');
  const [copiedAiPrompt, setCopiedAiPrompt] = useState(false);
  const [showAiAssistant, setShowAiAssistant] = useState(false);
  const [showPasteBox, setShowPasteBox] = useState(true);
  const [aiPasteText, setAiPasteText] = useState('');
  const [parsingAi, setParsingAi] = useState(false);
  const [generatingAi, setGeneratingAi] = useState(false);
  const [aiWarnings, setAiWarnings] = useState<string[]>([]);
  const [statusMsg, setStatusMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [simResult, setSimResult] = useState<{
    total_scanned: number;
    matched_count: number;
    admin_hits: number;
    logged_in_hits: number;
    guest_hits: number;
    samples: Array<{ timestamp: string; ip: string; method: string; uri: string; action: string }>;
  } | null>(null);

  useEffect(() => {
    apiRequest({ path: '/custom-rules/fields' })
      .then((res) => {
        if (res?.success) {
          if (Array.isArray(res.fields) && res.fields.length) setFields(res.fields);
          if (Array.isArray(res.installed_components)) setInstalledComponents(res.installed_components);
          if (Array.isArray(res.roles)) setWpRoles(res.roles);
          if (typeof res.current_ip === 'string') setCurrentIp(res.current_ip);
          if (res.discovered_endpoints) setDiscoveredEndpoints(res.discovered_endpoints);
          if (Array.isArray(res.existing_custom_rules)) setExistingCustomRules(res.existing_custom_rules);
          if (res.cloudflare_status && typeof res.cloudflare_status === 'object') {
            setCloudflareStatus({
              enabled: Boolean(res.cloudflare_status.enabled),
              configured: Boolean(res.cloudflare_status.configured),
              connected: Boolean(res.cloudflare_status.connected),
              proxied: Boolean(res.cloudflare_status.proxied),
              zone_name: String(res.cloudflare_status.zone_name || ''),
            });
          }
          if (res.ai_status && typeof res.ai_status === 'object') {
            setAiStatus({
              configured: Boolean(res.ai_status.configured),
              provider: String(res.ai_status.provider || 'gemini'),
              model: String(res.ai_status.model || ''),
            });
          }
          if (res.mcp_status && typeof res.mcp_status === 'object') {
            setMcpStatus({
              enabled: Boolean(res.mcp_status.enabled),
              scope: String(res.mcp_status.scope || 'read_only'),
              modular_tools: Number(res.mcp_status.modular_tools || 6),
            });
          }
        }
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!initialDraft) {
      setEditingRuleId(null);
      setEditingRuleNumber(null);
      setTitle('');
      setDescription('');
      setShowDesc(false);
      setActionType('');
      setPlacement('last');
      setGroups([{ logic: 'AND', rules: [{ field: '', op: '', value: '' }] }]);
      setWirefilterOverride(null);
      return;
    }
    setEditingRuleId(initialDraft.id || null);
    setEditingRuleNumber(initialDraft.rule_number ?? null);
    setTitle(initialDraft.title || '');
    setDescription(initialDraft.description || '');
    setShowDesc(Boolean(initialDraft.description));
    setActionType(initialDraft.action_type || 'block');
    if (initialDraft.current_mode) setMode(initialDraft.current_mode);
    if (typeof initialDraft.rate_limit === 'number') setRateLimit(initialDraft.rate_limit > 0 ? initialDraft.rate_limit : 15);
    if (typeof initialDraft.ban_ttl === 'number') setBanTtl(initialDraft.ban_ttl);
    if (typeof initialDraft.sync_cloudflare === 'boolean') setSyncCloudflare(initialDraft.sync_cloudflare);
    if (typeof initialDraft.block_uploads === 'boolean') setBlockUploads(initialDraft.block_uploads);
    setExemptRules(Array.isArray(initialDraft.exempt_rules) ? initialDraft.exempt_rules.join(', ') : '');
    setGroupLogic(initialDraft.group_logic === 'AND' ? 'AND' : 'OR');
    if (typeof initialDraft.priority === 'number' && initialDraft.priority > 0) {
      setPlacement('custom');
      setOrderPosition(initialDraft.priority);
    }
    if (initialDraft.conditions && initialDraft.conditions.length > 0) {
      setGroups(
        initialDraft.conditions.map((g) => ({
          logic: g.logic === 'OR' ? 'OR' : 'AND',
          rules: g.rules.length > 0 ? g.rules : [{ field: '', op: '', value: '' }],
        }))
      );
      setWirefilterOverride(null);
    } else if (initialDraft.wirefilter_expr) {
      setWirefilterOverride(initialDraft.wirefilter_expr);
    }
  }, [initialDraft]);

  const peerCustomRules = useMemo(
    () =>
      existingCustomRules
        .filter((r) => !editingRuleId || r.id !== editingRuleId)
        .sort((a, b) => a.priority - b.priority),
    [existingCustomRules, editingRuleId]
  );

  const maxOrderSlot = Math.max(1, peerCustomRules.length + 1);
  const resolvedOrderSlot = useMemo(() => {
    if (placement === 'first') return 1;
    if (placement === 'last') return maxOrderSlot;
    return Math.max(1, Math.min(maxOrderSlot, orderPosition || maxOrderSlot));
  }, [placement, maxOrderSlot, orderPosition]);

  const generatedWirefilter = useMemo(() => {
    const gStrings = groups
      .map((g) => {
        const validClauses = g.rules.map(clauseToWirefilter).filter(Boolean);
        if (validClauses.length === 0) return '';
        const inner = validClauses.join(g.logic === 'OR' ? ' or ' : ' and ');
        return groups.length > 1 && validClauses.length > 1 ? `(${inner})` : inner;
      })
      .filter(Boolean);
    if (gStrings.length <= 1) return gStrings[0] || '';
    return gStrings.join(groupLogic === 'AND' ? ' and ' : ' or ');
  }, [groups, groupLogic]);

  const activeWirefilter = wirefilterOverride !== null ? wirefilterOverride : generatedWirefilter;

  const updateClause = (gIdx: number, rIdx: number, patch: Partial<ConditionClause>) => {
    setWirefilterOverride(null);
    setGroups((prev) =>
      prev.map((g, gi) =>
        gi !== gIdx
          ? g
          : {
              ...g,
              rules: g.rules.map((r, ri) => {
                if (ri !== rIdx) return r;
                const updated = { ...r, ...patch };
                if (patch.field !== undefined) {
                  const meta = fields.find((f) => f.id === patch.field);
                  updated.op = meta?.ops[0] || '';
                  updated.key = '';
                  updated.value = '';
                }
                if (patch.op && ['is_true', 'is_false', 'exists', 'not_exists', 'is_array'].includes(patch.op)) {
                  updated.value = '';
                }
                return updated;
              }),
            }
      )
    );
  };

  const addClauseWithLogic = (gIdx: number, desiredLogic: 'AND' | 'OR') => {
    setWirefilterOverride(null);
    const blankRow: ConditionClause = { field: '', op: '', value: '' };
    setGroups((prev) => {
      const target = prev[gIdx];
      if (!target) return prev;
      if (target.rules.length <= 1 || target.logic === desiredLogic) {
        return prev.map((g, gi) =>
          gi === gIdx ? { ...g, logic: desiredLogic, rules: [...g.rules, blankRow] } : g
        );
      }
      const next = [...prev];
      next.splice(gIdx + 1, 0, { logic: 'AND', rules: [blankRow] });
      setGroupLogic(desiredLogic);
      return next;
    });
  };

  const removeClause = (gIdx: number, rIdx: number) => {
    setWirefilterOverride(null);
    setGroups((prev) => {
      const filtered = prev
        .map((g, gi) => (gi === gIdx ? { ...g, rules: g.rules.filter((_, ri) => ri !== rIdx) } : g))
        .filter((g) => g.rules.length > 0);
      return filtered.length > 0 ? filtered : [{ logic: 'AND', rules: [{ field: '', op: '', value: '' }] }];
    });
  };

  const setGroupLogicAt = (gIdx: number, nextLogic: 'AND' | 'OR') => {
    setWirefilterOverride(null);
    setGroups((prev) => prev.map((g, gi) => (gi === gIdx ? { ...g, logic: nextLogic } : g)));
  };

  const applyParsedRuleResult = (res: any, fallbackMessage: string) => {
    setAiWarnings(Array.isArray(res?.warnings) ? res.warnings : []);
    if (res?.success && Array.isArray(res.conditions) && res.conditions.length > 0) {
      setGroups(res.conditions);
      if (res.group_logic === 'AND' || res.group_logic === 'OR') {
        setGroupLogic(res.group_logic);
      }
      const meta = res.rule_meta || {};
      if (typeof meta.title === 'string' && meta.title.trim()) setTitle(meta.title.trim());
      if (typeof meta.description === 'string' && meta.description.trim()) {
        setDescription(meta.description.trim());
        setShowDesc(true);
      }
      if (typeof meta.action_type === 'string' && meta.action_type) setActionType(meta.action_type);
      if (typeof meta.ban_ttl === 'number') setBanTtl(meta.ban_ttl);
      if (typeof meta.rate_limit === 'number') setRateLimit(meta.rate_limit);
      if (typeof meta.block_uploads === 'boolean') setBlockUploads(meta.block_uploads);
      if (meta.placement === 'first' || meta.placement === 'last' || meta.placement === 'custom') {
        setPlacement(meta.placement);
      }
      setWirefilterOverride(null);
      setEditingExpression(false);
      setShowPasteBox(false);
      setStatusMsg({ type: 'success', text: res.message || fallbackMessage });
      return true;
    }
    setStatusMsg({
      type: 'error',
      text: res?.message || 'Could not parse Wirefilter syntax. Check field names, quotes, and operators.',
    });
    return false;
  };

  const handleCopyAiPrompt = async () => {
    const markdown = buildAiRuleMarkdownPrompt({
      userGoal: aiGoal,
      fields,
      installedComponents,
      roles: wpRoles,
      existingRules: existingCustomRules,
      discoveredEndpoints,
      cfProxied: cloudflareStatus.proxied,
    });
    try {
      await navigator.clipboard?.writeText(markdown);
      setCopiedAiPrompt(true);
      setShowAiAssistant(true);
      setShowPasteBox(true);
      setStatusMsg({
        type: 'success',
        text: 'Prompt copied to clipboard! Paste it into ChatGPT, Claude, or Gemini. When the AI gives you the Expression code, paste it into Step 3 below and click Apply.',
      });
      setTimeout(() => setCopiedAiPrompt(false), 3500);
      const pasteArea = document.getElementById('webcare-ai-paste-textarea');
      if (pasteArea) {
        pasteArea.focus();
      }
    } catch {
      setStatusMsg({ type: 'error', text: 'Clipboard access blocked. Please allow clipboard permissions.' });
    }
  };

  const handleImportAiPaste = async () => {
    if (!aiPasteText.trim()) {
      setStatusMsg({ type: 'error', text: 'Please paste the Expression code or JSON rule from your AI into Step 3 first.' });
      return;
    }
    try {
      setParsingAi(true);
      setStatusMsg(null);
      const res = await apiRequest({
        path: '/custom-rules/rule/parse-ai',
        method: 'POST',
        data: { raw_input: aiPasteText },
      });
      applyParsedRuleResult(res, 'AI rule applied! Review the rule settings below and click "Save & Deploy Rule" to activate.');
    } catch (e: any) {
      setStatusMsg({ type: 'error', text: e?.message || 'Failed to parse pasted AI rule.' });
    } finally {
      setParsingAi(false);
    }
  };

  const handleGenerateWithAi = async () => {
    if (!aiGoal.trim()) {
      setStatusMsg({ type: 'error', text: 'Describe the firewall rule you want WebCare AI to build.' });
      return;
    }
    try {
      setGeneratingAi(true);
      setStatusMsg(null);
      const res = await apiRequest({
        path: '/custom-rules/rule/ai-generate',
        method: 'POST',
        data: { goal: aiGoal.trim() },
      });
      applyParsedRuleResult(res, 'Generated rule loaded into Visual Builder. Review and click Save.');
    } catch (e: any) {
      setStatusMsg({ type: 'error', text: e?.message || 'AI generation failed.' });
    } finally {
      setGeneratingAi(false);
    }
  };

  const handleSyncFromWirefilter = async () => {
    if (!activeWirefilter.trim()) return;
    try {
      const res = await apiRequest({
        path: '/custom-rules/rule/parse-wirefilter',
        method: 'POST',
        data: { wirefilter_expr: activeWirefilter },
      });
      applyParsedRuleResult(res, 'Expression synced into visual builder.');
    } catch {
      setStatusMsg({ type: 'error', text: 'Failed to parse Wirefilter expression.' });
    }
  };

  const handleSimulate = async () => {
    try {
      setSimulating(true);
      setStatusMsg(null);
      const validGroups = groups
        .map((g) => ({ ...g, rules: g.rules.filter((r) => r.field && r.op) }))
        .filter((g) => g.rules.length > 0);
      const res = await apiRequest({
        path: '/custom-rules/rule/simulate',
        method: 'POST',
        data: {
          group_logic: groupLogic,
          conditions: validGroups,
          wirefilter_expr: activeWirefilter,
          limit: 500,
        },
      });
      if (res?.success) {
        setSimResult(res);
      }
    } catch (e: any) {
      setStatusMsg({ type: 'error', text: e?.message || 'Simulation failed.' });
    } finally {
      setSimulating(false);
    }
  };

  const handleDeployRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) {
      setStatusMsg({ type: 'error', text: 'Please enter a Rule name.' });
      return;
    }
    const validGroups = groups
      .map((g) => ({ ...g, rules: g.rules.filter((r) => r.field && r.op) }))
      .filter((g) => g.rules.length > 0);
    if (validGroups.length === 0 && !activeWirefilter.trim()) {
      setStatusMsg({ type: 'error', text: 'Please select at least one Field, Operator, and Value condition.' });
      return;
    }
    if (!actionType) {
      setStatusMsg({ type: 'error', text: 'Please choose an enforcement action.' });
      return;
    }

    try {
      setSubmitting(true);
      setStatusMsg(null);
      const res = await apiRequest({
        path: '/custom-rules/rule/custom',
        method: 'POST',
        data: {
          ...(editingRuleId ? { id: editingRuleId } : {}),
          title: title.trim(),
          description: description.trim(),
          category: 'custom',
          action_type: actionType,
          current_mode: actionType === 'monitor' ? 'monitor' : mode,
          rate_limit: actionType === 'rate_limit' ? Math.max(1, rateLimit) : 0,
          immediate_block: ['block', 'block_and_ban'].includes(actionType),
          ban_ttl: ['block', 'block_and_ban'].includes(actionType) ? banTtl : 0,
          sync_cloudflare: Boolean(cloudflareStatus.enabled && cloudflareStatus.connected && syncCloudflare),
          block_uploads: blockUploads,
          group_logic: groupLogic,
          conditions: validGroups,
          wirefilter_expr: activeWirefilter,
          exempt_rules: exemptRules.split(',').map((s) => s.trim()).filter(Boolean),
          placement,
          order_position: resolvedOrderSlot,
        },
      });
      if (res?.success) {
        setEditingRuleId(null);
        setEditingRuleNumber(null);
        setTitle('');
        setDescription('');
        setActionType('');
        setGroups([{ logic: 'AND', rules: [{ field: '', op: '', value: '' }] }]);
        apiRequest({ path: '/custom-rules/fields' })
          .then((fRes) => {
            if (fRes?.success && Array.isArray(fRes.existing_custom_rules)) {
              setExistingCustomRules(fRes.existing_custom_rules);
            }
          })
          .catch(() => {});
        await onRuleCreated(res.message || (editingRuleId ? 'Rule updated.' : 'Custom rule created.'));
      } else {
        setStatusMsg({ type: 'error', text: res?.message || 'Failed to save rule.' });
      }
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: err?.message || 'Failed to save rule.' });
    } finally {
      setSubmitting(false);
    }
  };

  const fieldLayers = Array.from(new Set(fields.map((f) => f.layer)));

  return (
    <div className="webcare-cf-vrb-root">
      {/* Minimal Header */}
      <div className="webcare-cf-vrb-header">
        <div>
          <div className="webcare-cf-vrb-title-row">
            <h2 className="webcare-cf-vrb-title">
              {editingRuleId
                ? `Edit Custom Firewall Rule${editingRuleNumber ? ` · ID #${editingRuleNumber}` : ''}`
                : 'Create Custom Firewall Rule'}
            </h2>
            {editingRuleId && (
              <span className="webcare-badge-pill webcare-badge-warn">{editingRuleId}</span>
            )}
          </div>
          <p className="webcare-cf-vrb-desc">
            Custom firewall rules run directly on your local server. Offending IP bans automatically sync to Cloudflare Edge when connected.
          </p>
        </div>

        <div className="webcare-cf-vrb-header-right">
          <a
            href="admin.php?page=webcare-pro-settings&tab=mcp"
            className={`webcare-cf-vrb-status-chip ${
              mcpStatus.enabled ? (mcpStatus.scope === 'read_only' ? 'is-mcp-ro' : 'is-mcp') : 'is-offline'
            }`}
            title="Model Context Protocol (MCP) Agent tools exposed for Custom Firewall Rules"
          >
            <Cpu size={13} />
            <span>
              {!mcpStatus.enabled
                ? 'MCP Disabled'
                : mcpStatus.scope === 'read_only'
                ? `MCP Ready (${mcpStatus.modular_tools} Tools · Read-Only)`
                : `MCP Ready (${mcpStatus.modular_tools} Tools)`}
            </span>
          </a>
          <a
            href="admin.php?page=webcare-pro-settings&tab=cloudflare"
            className={`webcare-cf-vrb-status-chip ${
              cloudflareStatus.enabled && cloudflareStatus.connected
                ? 'is-connected'
                : cloudflareStatus.enabled && cloudflareStatus.configured
                ? 'is-warning'
                : 'is-offline'
            }`}
            title="Manage Cloudflare Edge integration"
          >
            <Cloud size={13} />
            <span>
              {cloudflareStatus.enabled && cloudflareStatus.connected
                ? `Cloudflare Connected${cloudflareStatus.zone_name ? ` · ${cloudflareStatus.zone_name}` : ''}`
                : cloudflareStatus.enabled && cloudflareStatus.configured
                ? 'Cloudflare Pending Verification'
                : 'Cloudflare Not Connected'}
            </span>
          </a>
          {!editingRuleId && (
            <div className="webcare-cf-vrb-tpl-wrap">
              <button
                type="button"
                className="webcare-btn-micro"
                onClick={() => setTemplateMenuOpen((o) => !o)}
              >
                <span>Templates</span>
                <ChevronDown size={13} />
              </button>
              {templateMenuOpen && (
                <div className="webcare-smart-dropdown webcare-cf-vrb-tpl-menu">
                  {QUICK_TEMPLATES.map((tpl) => (
                    <button
                      key={tpl.id}
                      type="button"
                      className="webcare-smart-option"
                      onClick={() => {
                        setTitle(tpl.title);
                        setActionType(tpl.action_type);
                        setGroupLogic(tpl.group_logic);
                        setGroups(tpl.groups.map((g) => ({ logic: g.logic, rules: g.rules.map((r) => ({ ...r })) })));
                        setWirefilterOverride(null);
                        setTemplateMenuOpen(false);
                      }}
                    >
                      <span>{tpl.label}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* AI Rule Assistant: Collapsed by Default with Beautiful Launch Button */}
      {!showAiAssistant ? (
        <div className="webcare-ai-collapsed-banner">
          <div className="webcare-ai-collapsed-left">
            <button
              type="button"
              className="webcare-ai-launch-btn"
              onClick={() => setShowAiAssistant(true)}
            >
              <Sparkles size={16} />
              <span>Generate Firewall Rules by AI</span>
              <span className="webcare-ai-launch-badge">ChatGPT · Claude · Gemini</span>
              <ChevronDown size={14} />
            </button>
            <div className="webcare-ai-collapsed-text">
              <strong>Need a custom rule without writing code?</strong> Describe what you want to block or allow in plain English, and AI will build the rule for you.
            </div>
          </div>
          {aiStatus.configured && (
            <button
              type="button"
              className="webcare-btn-micro"
              onClick={() => {
                setShowAiAssistant(true);
                handleGenerateWithAi();
              }}
              disabled={generatingAi}
              title="Generate directly with built-in WebCare AI"
            >
              <Sparkles size={13} color="#4f46e5" />
              <span>1-Click WebCare AI</span>
            </button>
          )}
        </div>
      ) : (
        <div className="webcare-ai-helper-card is-expanded">
          <div className="webcare-ai-helper-top">
            <div className="webcare-ai-helper-title">
              <div className="webcare-ai-helper-icon-wrap">
                <Sparkles size={16} />
              </div>
              <div>
                <strong>Create Firewall Rules with AI (ChatGPT · Claude · Gemini)</strong>
                <div className="webcare-ai-helper-sub">
                  No coding required: Write what you want to block or allow, copy the prompt for any AI, and paste the code back below to create your rule automatically.
                </div>
              </div>
            </div>
            <div className="webcare-ai-helper-actions">
              {aiStatus.configured && (
                <button
                  type="button"
                  className="webcare-btn-primary webcare-ai-gen-btn"
                  onClick={handleGenerateWithAi}
                  disabled={generatingAi}
                  title="Generate directly with built-in WebCare AI without leaving this page"
                >
                  <Sparkles size={13} />
                  <span>{generatingAi ? 'Generating...' : '1-Click WebCare AI'}</span>
                </button>
              )}
              <button
                type="button"
                className="webcare-btn-micro webcare-ai-collapse-btn"
                onClick={() => setShowAiAssistant(false)}
                title="Collapse AI assistant"
              >
                <ChevronDown
                  size={14}
                  style={{
                    transform: 'rotate(180deg)',
                    transition: 'transform 0.2s',
                  }}
                />
                <span>Collapse Assistant</span>
              </button>
            </div>
          </div>

          <div className="webcare-ai-steps-container">
            {/* Step 1: Write what you want to block or allow */}
            <div className="webcare-ai-step-block">
              <div className="webcare-ai-step-header">
                <span className="webcare-ai-step-num">1</span>
                <div>
                  <span className="webcare-ai-step-title">Write what you want to block or allow</span>
                  <span className="webcare-ai-step-hint">Explain in plain English — no technical jargon needed</span>
                </div>
              </div>
              <div className="webcare-ai-goal-row">
                <input
                  type="text"
                  className="webcare-input webcare-ai-goal-input"
                  placeholder='e.g. "Block unauthenticated visitors from uploading files to PHP scripts" or "Allow only logged-in users to access /wp-json/"'
                  value={aiGoal}
                  onChange={(e) => setAiGoal(e.target.value)}
                />
              </div>
              <div className="webcare-ai-quick-chips">
                <span className="webcare-ai-quick-label">Or click an example:</span>
                <button
                  type="button"
                  className="webcare-ai-chip"
                  onClick={() =>
                    setAiGoal('Block unauthenticated requests uploading files or accessing PHP scripts in wp-content/uploads/')
                  }
                >
                  🛡️ Block uploads in /uploads/
                </button>
                <button
                  type="button"
                  className="webcare-ai-chip"
                  onClick={() =>
                    setAiGoal('Block repeated login attempts and challenge visitors on /wp-login.php')
                  }
                >
                  🚫 Protect login page from brute-force
                </button>
                <button
                  type="button"
                  className="webcare-ai-chip"
                  onClick={() =>
                    setAiGoal('Block visitors outside my country from accessing /wp-admin/ or /wp-login.php')
                  }
                >
                  🌍 Country restriction for wp-admin
                </button>
                <button
                  type="button"
                  className="webcare-ai-chip"
                  onClick={() =>
                    setAiGoal('Require login for all POST requests to REST API endpoints')
                  }
                >
                  🔒 Require login for REST API writes
                </button>
              </div>
            </div>

            {/* Step 2: Copy the prompt for AI */}
            <div className="webcare-ai-step-block">
              <div className="webcare-ai-step-header">
                <span className="webcare-ai-step-num">2</span>
                <div>
                  <span className="webcare-ai-step-title">Copy the prompt & paste it into any AI</span>
                  <span className="webcare-ai-step-hint">ChatGPT, Claude, or Gemini will generate the exact rule code for your site</span>
                </div>
              </div>
              <div className="webcare-ai-step-actions-row">
                <button
                  type="button"
                  className={`webcare-btn webcare-ai-copy-cta ${copiedAiPrompt ? 'is-copied' : ''}`}
                  onClick={handleCopyAiPrompt}
                >
                  {copiedAiPrompt ? <Check size={14} /> : <Copy size={14} />}
                  <span>{copiedAiPrompt ? '✅ Prompt Copied! Now paste into your AI' : '📋 Copy Prompt for AI (ChatGPT / Claude / Gemini)'}</span>
                </button>
                <div className="webcare-ai-step-instruction">
                  <Info size={14} />
                  <span>
                    Click copy, open <strong>ChatGPT</strong>, <strong>Claude</strong>, or <strong>Gemini</strong>, and paste. The AI will immediately reply with the Expression code!
                  </span>
                </div>
              </div>
            </div>

            {/* Step 3: Paste the AI code below */}
            <div className="webcare-ai-step-block">
              <div className="webcare-ai-step-header">
                <span className="webcare-ai-step-num">3</span>
                <div>
                  <span className="webcare-ai-step-title">Paste the code from your AI below</span>
                  <span className="webcare-ai-step-hint">Paste the Expression code or JSON result here to automatically build your firewall rule</span>
                </div>
              </div>
              <div className="webcare-ai-paste-box-wrap">
                <textarea
                  id="webcare-ai-paste-textarea"
                  className="webcare-input webcare-cf-vrb-expr-textarea webcare-ai-paste-textarea"
                  rows={3}
                  placeholder='Paste the code from ChatGPT, Claude, or Gemini here (e.g. (http.request.method eq "POST" and not wp.user.is_logged_in) or complete JSON)...'
                  value={aiPasteText}
                  onChange={(e) => setAiPasteText(e.target.value)}
                />
                <div className="webcare-ai-paste-footer">
                  <span className="webcare-cf-vrb-help" style={{ margin: 0 }}>
                    🛡️ WebCare Pro automatically validates the code, protects your admin login against accidental lockouts, and fills out the rule builder for you.
                  </span>
                  <button
                    type="button"
                    className="webcare-btn-primary webcare-ai-apply-cta"
                    onClick={handleImportAiPaste}
                    disabled={parsingAi || !aiPasteText.trim()}
                  >
                    <ClipboardPaste size={14} />
                    <span>{parsingAi ? 'Applying Rule...' : '⚡ Apply Code & Create Rule'}</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {aiWarnings.length > 0 && (
        <div className="webcare-ai-warning-banner">
          <AlertTriangle size={15} />
          <div>
            <strong>Safety Check Notice:</strong>
            <ul>
              {aiWarnings.map((w, idx) => (
                <li key={idx}>{w}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {statusMsg && (
        <div className={`webcare-vrb-alert ${statusMsg.type === 'success' ? 'is-success' : 'is-error'}`}>
          {statusMsg.text}
        </div>
      )}

      <form onSubmit={handleDeployRule} className="webcare-cf-vrb-form">
        {/* Card 1: Rule name */}
        <div className="webcare-cf-vrb-card">
          <div className="webcare-cf-vrb-card-top">
            <label htmlFor="webcare-cf-rule-name" className="webcare-cf-vrb-card-label">
              Rule name
            </label>
            {!showDesc && (
              <button
                type="button"
                className="webcare-cf-vrb-link-btn"
                onClick={() => setShowDesc(true)}
              >
                + Add note
              </button>
            )}
          </div>
          <input
            id="webcare-cf-rule-name"
            type="text"
            required
            className="webcare-input webcare-cf-vrb-input"
            placeholder=""
            value={title}
            onChange={(e) => setTitle(e.target.value)}
          />
          <div className="webcare-cf-vrb-help">Give your rule a descriptive name.</div>

          {showDesc && (
            <div style={{ marginTop: '12px' }}>
              <label htmlFor="webcare-cf-rule-desc" className="webcare-cf-vrb-sub-label">
                Description / note (optional)
              </label>
              <input
                id="webcare-cf-rule-desc"
                type="text"
                className="webcare-input webcare-cf-vrb-input"
                placeholder=""
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
          )}
        </div>

        {/* Card 2: When incoming requests match... */}
        <div className="webcare-cf-vrb-card">
          <div className="webcare-cf-vrb-card-title">When incoming requests match...</div>

          <div className="webcare-cf-vrb-groups">
            {groups.map((grp, gIdx) => (
              <Fragment key={gIdx}>
                {gIdx > 0 && (
                  <div className="webcare-cf-vrb-or-divider">
                    <div className="webcare-vrb-connector-line" />
                    <button
                      type="button"
                      className={`webcare-vrb-row-pill ${groupLogic === 'OR' ? 'is-or' : 'is-and'}`}
                      onClick={() => {
                        setWirefilterOverride(null);
                        setGroupLogic((prev) => (prev === 'OR' ? 'AND' : 'OR'));
                      }}
                      title="Click to switch between OR and AND between groups"
                    >
                      {groupLogic}
                    </button>
                    <div className="webcare-vrb-connector-line" />
                  </div>
                )}

                <div className="webcare-cf-vrb-group-box">
                  {grp.rules.map((clause, rIdx) => {
                    const schema = fields.find((f) => f.id === clause.field);
                    const hasField = Boolean(clause.field && schema);
                    const hideVal = hasField && ['is_true', 'is_false', 'exists', 'not_exists', 'is_array'].includes(clause.op);
                    const totalRows = groups.reduce((n, g) => n + g.rules.length, 0);

                    return (
                      <Fragment key={rIdx}>
                        {rIdx > 0 && (
                          <div className="webcare-cf-vrb-inner-join">
                            <button
                              type="button"
                              className={`webcare-vrb-row-pill ${grp.logic === 'OR' ? 'is-or' : 'is-and'}`}
                              onClick={() => setGroupLogicAt(gIdx, grp.logic === 'AND' ? 'OR' : 'AND')}
                              title="Click to switch And / Or"
                            >
                              {grp.logic}
                            </button>
                          </div>
                        )}

                        <div className={`webcare-cf-vrb-row ${schema?.needs_key ? 'has-key' : ''}`}>
                          <div>
                            {rIdx === 0 && <label className="webcare-cf-vrb-col-label">Field</label>}
                            <select
                              className="webcare-input webcare-cf-vrb-select"
                              value={clause.field}
                              onChange={(e) => updateClause(gIdx, rIdx, { field: e.target.value })}
                              aria-label="Field"
                            >
                              <option value="">Select...</option>
                              {fieldLayers.map((layer) => (
                                <optgroup key={layer} label={layer}>
                                  {fields.filter((f) => f.layer === layer).map((f) => (
                                    <option key={f.id} value={f.id}>{f.label}</option>
                                  ))}
                                </optgroup>
                              ))}
                            </select>
                          </div>

                          {schema?.needs_key && (
                            <div>
                              {rIdx === 0 && <label className="webcare-cf-vrb-col-label">Key</label>}
                              <input
                                type="text"
                                className="webcare-input webcare-cf-vrb-input"
                                placeholder=""
                                value={clause.key || ''}
                                onChange={(e) => updateClause(gIdx, rIdx, { key: e.target.value })}
                              />
                            </div>
                          )}

                          <div>
                            {rIdx === 0 && <label className="webcare-cf-vrb-col-label">Operator</label>}
                            <select
                              className="webcare-input webcare-cf-vrb-select"
                              value={clause.op}
                              disabled={!hasField}
                              onChange={(e) => updateClause(gIdx, rIdx, { op: e.target.value })}
                              aria-label="Operator"
                            >
                              {!hasField ? (
                                <option value="">Select...</option>
                              ) : (
                                (schema?.ops || ['eq']).map((op) => (
                                  <option key={op} value={op}>{OP_LABELS[op] || op}</option>
                                ))
                              )}
                            </select>
                          </div>

                          <div>
                            {rIdx === 0 && <label className="webcare-cf-vrb-col-label">Value</label>}
                            {!hasField ? (
                              <input
                                type="text"
                                className="webcare-input webcare-cf-vrb-input"
                                placeholder=""
                                value={clause.value}
                                disabled={!hasField}
                                onChange={(e) => updateClause(gIdx, rIdx, { value: e.target.value })}
                              />
                            ) : hideVal ? (
                              <div className="webcare-vrb-bool-pill">
                                <span>{['exists', 'not_exists'].includes(clause.op) ? 'Presence check' : 'Runtime boolean'}</span>
                              </div>
                            ) : (
                              <SmartConditionValueInput
                                field={clause.field}
                                op={clause.op}
                                value={clause.value}
                                onChangeValue={(val) => updateClause(gIdx, rIdx, { value: val })}
                                onSuggestOp={(nextOp) => updateClause(gIdx, rIdx, { op: nextOp })}
                                installedComponents={installedComponents}
                                roles={wpRoles}
                                currentIp={currentIp}
                                discoveredEndpoints={discoveredEndpoints}
                              />
                            )}
                          </div>

                          <div className={`webcare-cf-vrb-logic-btns ${rIdx === 0 ? 'with-top-pad' : ''}`}>
                            <button
                              type="button"
                              className="webcare-cf-vrb-conj-btn"
                              onClick={() => addClauseWithLogic(gIdx, 'AND')}
                            >
                              And
                            </button>
                            <button
                              type="button"
                              className="webcare-cf-vrb-conj-btn"
                              onClick={() => addClauseWithLogic(gIdx, 'OR')}
                            >
                              Or
                            </button>
                            {totalRows > 1 && (
                              <button
                                type="button"
                                className="webcare-cf-vrb-del-btn"
                                onClick={() => removeClause(gIdx, rIdx)}
                                title="Remove condition"
                                aria-label="Remove condition"
                              >
                                <Trash2 size={14} />
                              </button>
                            )}
                          </div>
                        </div>
                      </Fragment>
                    );
                  })}
                </div>
              </Fragment>
            ))}
          </div>

          {/* Expression Preview (Directly inside match card like Cloudflare) */}
          <div className="webcare-cf-vrb-expr-wrap">
            <div className="webcare-cf-vrb-expr-head">
              <span className="webcare-cf-vrb-sub-label" style={{ margin: 0 }}>Expression Preview</span>
              <div className="webcare-cf-vrb-expr-actions">
                {activeWirefilter && (
                  <button
                    type="button"
                    className="webcare-cf-vrb-link-btn"
                    onClick={() => {
                      navigator.clipboard?.writeText(activeWirefilter);
                      setCopiedWf(true);
                      setTimeout(() => setCopiedWf(false), 1800);
                    }}
                  >
                    {copiedWf ? <Check size={12} /> : <Copy size={12} />} {copiedWf ? 'Copied' : 'Copy'}
                  </button>
                )}
                <button
                  type="button"
                  className="webcare-cf-vrb-link-btn"
                  onClick={() => setEditingExpression((prev) => !prev)}
                >
                  {editingExpression ? 'Use builder view' : 'Edit expression'}
                </button>
              </div>
            </div>

            {editingExpression ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <textarea
                  className="webcare-input webcare-cf-vrb-expr-textarea"
                  rows={2}
                  value={activeWirefilter}
                  onChange={(e) => setWirefilterOverride(e.target.value)}
                />
                {wirefilterOverride !== null && (
                  <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                    <button type="button" className="webcare-btn-micro" onClick={handleSyncFromWirefilter}>
                      <RefreshCw size={12} /> Sync expression to builder
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <div className="webcare-cf-vrb-expr-box">
                <code>{activeWirefilter}</code>
              </div>
            )}
            <div className="webcare-cf-vrb-char-count">{activeWirefilter.length} / 4000 characters</div>
          </div>
        </div>

        {/* Card 3: Then take action... */}
        <div className="webcare-cf-vrb-card">
          <div className="webcare-cf-vrb-card-title">Then take action...</div>

          <div className="webcare-cf-vrb-field-narrow">
            <label htmlFor="webcare-cf-action-select" className="webcare-cf-vrb-sub-label">
              Choose action
            </label>
            <select
              id="webcare-cf-action-select"
              className="webcare-input webcare-cf-vrb-select"
              value={actionType}
              onChange={(e) => setActionType(e.target.value)}
            >
              <option value="">Select...</option>
              <option value="block">Block (HTTP 403)</option>
              <option value="block_and_ban">Block + Auto-Ban IP</option>
              <option value="rate_limit">Rate Limit (HTTP 429)</option>
              <option value="challenge_pow">WebCrypto PoW Challenge</option>
              <option value="payload_inspect">Inspect Payload (SQLi / XSS)</option>
              <option value="monitor">Monitor / Log Only</option>
              <option value="allow">Skip / Allow Matching Traffic</option>
            </select>
          </div>

          {actionType !== '' && (
            <div className="webcare-cf-vrb-action-extras">
              {actionType === 'rate_limit' && (
                <div className="webcare-cf-vrb-field-narrow">
                  <label className="webcare-cf-vrb-sub-label">Requests per minute</label>
                  <input
                    type="number"
                    min={1}
                    max={600}
                    className="webcare-input webcare-cf-vrb-input"
                    value={rateLimit}
                    onChange={(e) => setRateLimit(parseInt(e.target.value, 10) || 15)}
                  />
                </div>
              )}

              {actionType === 'allow' && (
                <div className="webcare-cf-vrb-field-narrow">
                  <label className="webcare-cf-vrb-sub-label">Rule IDs to skip (optional)</label>
                  <input
                    type="text"
                    className="webcare-input webcare-cf-vrb-input"
                    placeholder=""
                    value={exemptRules}
                    onChange={(e) => setExemptRules(e.target.value)}
                  />
                </div>
              )}

              {['block', 'block_and_ban'].includes(actionType) && (
                <div className="webcare-cf-vrb-field-narrow">
                  <label className="webcare-cf-vrb-sub-label">Auto-Ban IP duration</label>
                  <select
                    className="webcare-input webcare-cf-vrb-select"
                    value={banTtl}
                    onChange={(e) => setBanTtl(parseInt(e.target.value, 10) || 0)}
                  >
                    <option value={0}>No IP Ban (Block request only)</option>
                    <option value={900}>15 Minutes (900s)</option>
                    <option value={3600}>1 Hour (3,600s)</option>
                    <option value={21600}>6 Hours (21,600s)</option>
                    <option value={86400}>24 Hours (86,400s)</option>
                    <option value={604800}>7 Days (604,800s)</option>
                    <option value={2592000}>30 Days (2,592,000s)</option>
                  </select>
                </div>
              )}

              <div className="webcare-cf-vrb-check-strip">
                <label
                  className={`webcare-vrb-check-label ${!(cloudflareStatus.enabled && cloudflareStatus.connected) ? 'is-disabled' : ''}`}
                  title={
                    cloudflareStatus.enabled && cloudflareStatus.connected
                      ? 'Automatically push banned offender IPs to Cloudflare Edge'
                      : 'Connect Cloudflare in Settings → Cloudflare to enable automatic IP ban sync'
                  }
                >
                  <input
                    type="checkbox"
                    checked={Boolean(cloudflareStatus.enabled && cloudflareStatus.connected && syncCloudflare)}
                    disabled={!(cloudflareStatus.enabled && cloudflareStatus.connected)}
                    onChange={(e) => setSyncCloudflare(e.target.checked)}
                  />
                  <span>
                    Sync banned IP to Cloudflare Edge
                    {cloudflareStatus.enabled && cloudflareStatus.connected
                      ? ` (${cloudflareStatus.zone_name || 'Connected'})`
                      : ' (Cloudflare not connected — local ban only)'}
                  </span>
                </label>
                <label className="webcare-vrb-check-label">
                  <input type="checkbox" checked={blockUploads} onChange={(e) => setBlockUploads(e.target.checked)} />
                  <span>Block multipart file uploads on match</span>
                </label>
              </div>
            </div>
          )}
        </div>

        {/* Card 4: Execution order (#ID + Rule Name) */}
        <div className="webcare-cf-vrb-card">
          <div className="webcare-cf-vrb-card-title">Execution order</div>
          <p className="webcare-cf-vrb-help" style={{ marginBottom: '12px' }}>
            Rules are evaluated sequentially in order. The position you choose determines at which point in this sequence your rule will evaluate the traffic.
          </p>

          <div className="webcare-cf-vrb-field-order">
            <label htmlFor="webcare-cf-order-select" className="webcare-cf-vrb-sub-label">
              Select order:
            </label>
            <select
              id="webcare-cf-order-select"
              className="webcare-input webcare-cf-vrb-select"
              value={resolvedOrderSlot}
              onChange={(e) => {
                const slot = Math.max(1, Math.min(maxOrderSlot, parseInt(e.target.value, 10) || 1));
                setOrderPosition(slot);
                setPlacement(slot === 1 ? 'first' : slot === maxOrderSlot ? 'last' : 'custom');
              }}
            >
              {peerCustomRules.length === 0 ? (
                <option value={1}>First (Order #1)</option>
              ) : (
                Array.from({ length: maxOrderSlot }, (_, idx) => {
                  const slotNum = idx + 1;
                  const beforeRule = peerCustomRules[idx];
                  const afterRule = idx > 0 ? peerCustomRules[idx - 1] : null;
                  let text = '';
                  if (slotNum === 1 && beforeRule) {
                    text = `First (Order #1) — Before ID #${beforeRule.rule_number} · ${beforeRule.title}`;
                  } else if (slotNum === maxOrderSlot && afterRule) {
                    text = `Last (Order #${slotNum}) — After ID #${afterRule.rule_number} · ${afterRule.title}`;
                  } else if (afterRule && beforeRule) {
                    text = `Order #${slotNum} — After ID #${afterRule.rule_number} · ${afterRule.title} (Before ID #${beforeRule.rule_number} · ${beforeRule.title})`;
                  }
                  return (
                    <option key={slotNum} value={slotNum}>
                      {text}
                    </option>
                  );
                })
              )}
            </select>
          </div>
        </div>

        {/* Card 5: Status */}
        <div className="webcare-cf-vrb-card">
          <div className="webcare-cf-vrb-card-title">Status</div>
          <p className="webcare-cf-vrb-help" style={{ marginBottom: '12px' }}>
            Controls whether the rule actively evaluates incoming traffic
          </p>

          <div className="webcare-cf-vrb-status-pills" role="radiogroup" aria-label="Rule status">
            <button
              type="button"
              role="radio"
              aria-checked={mode === 'enforce'}
              className={`webcare-cf-vrb-status-btn ${mode === 'enforce' ? 'is-active' : ''}`}
              onClick={() => setMode('enforce')}
            >
              Active (Enforce)
            </button>
            <button
              type="button"
              role="radio"
              aria-checked={mode === 'monitor'}
              className={`webcare-cf-vrb-status-btn ${mode === 'monitor' ? 'is-monitor' : ''}`}
              onClick={() => setMode('monitor')}
            >
              Monitor Only
            </button>
          </div>
        </div>

        {/* Simulation Preview */}
        {simResult && (
          <div className="webcare-cf-vrb-card">
            <div className="webcare-vrb-sim-head">
              <strong>Dry-Run Simulation ({simResult.total_scanned} recent WAF log events inspected)</strong>
              <div className="webcare-vrb-badges">
                <span className="webcare-badge-pill webcare-badge-info">{simResult.matched_count} Total Matches</span>
                <span className="webcare-badge-pill webcare-badge-clean">{simResult.guest_hits} Guest Hits</span>
                {simResult.admin_hits > 0 && (
                  <span className="webcare-badge-pill webcare-badge-danger">
                    <AlertTriangle size={11} /> {simResult.admin_hits} Admin Matches!
                  </span>
                )}
              </div>
            </div>
            {simResult.samples.length > 0 && (
              <div className="webcare-vrb-sim-samples">
                {simResult.samples.map((s, idx) => (
                  <div key={idx} className="webcare-vrb-sim-sample-row">
                    [{s.method}] {s.ip} &rarr; {s.uri}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Footer */}
        <div className="webcare-cf-vrb-footer">
          <button
            type="button"
            onClick={handleSimulate}
            disabled={simulating}
            className="webcare-btn-micro webcare-vrb-sim-btn"
          >
            <Play size={13} /> {simulating ? 'Testing...' : 'Test against recent traffic'}
          </button>

          <div className="webcare-cf-vrb-footer-right">
            {editingRuleId && (
              <button
                type="button"
                onClick={() => {
                  setEditingRuleId(null);
                  setEditingRuleNumber(null);
                  setTitle('');
                  setDescription('');
                  if (onCancelEdit) onCancelEdit();
                }}
                className="webcare-btn-micro webcare-vrb-cancel-btn"
              >
                Cancel
              </button>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="webcare-btn webcare-btn-primary webcare-vrb-submit-btn"
            >
              <ShieldCheck size={15} />
              <span>
                {submitting
                  ? (editingRuleId ? 'Saving...' : 'Deploying...')
                  : (editingRuleId ? 'Save changes' : 'Deploy rule')}
              </span>
            </button>
          </div>
        </div>
      </form>
    </div>
  );
};
