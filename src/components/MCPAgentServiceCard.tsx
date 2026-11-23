import { useState, useEffect, useMemo } from '@wordpress/element';
import { showConfirm } from '../utils/dialog';
import {
  Copy,
  RefreshCw,
  Shield,
  Eye,
  EyeOff,
  CheckCircle2,
  AlertCircle,
  Layers,
  Lock,
  Activity,
  Trash2,
  Zap,
  ShieldAlert,
  Cpu,
  ChevronRight,
  ChevronDown,
  Monitor,
  Check,
  X,
  Clock,
  Target,
  AlertTriangle,
  Save,
  RotateCcw,
  KeyRound,
  Search,
} from 'lucide-react';

interface MCPAgentServiceCardProps {
  settings: any;
  onUpdateSetting: (key: string, value: any) => void;
  apiRequest: (options: any) => Promise<any>;
}

const getToolIcon = (name: string, isMutating: boolean) => {
  if (name.includes('quarantine') || name.includes('repair')) return ShieldAlert;
  if (name.includes('scan') || name.includes('finding')) return Target;
  if (name.includes('visual') || name.includes('modular') || name.includes('waf')) return Layers;
  if (name.includes('settings') || name.includes('cron') || name.includes('snapshot') || name.includes('undo')) return Cpu;
  if (name.includes('containment') || name.includes('drill') || name.includes('cloudflare')) return Zap;
  return isMutating ? Lock : Shield;
};

const formatUnixTime = (ts: any): string => {
  const num = Number(ts);
  if (!Number.isFinite(num) || num <= 0) {
    return typeof ts === 'string' && ts ? ts : 'Just now';
  }
  return new Date(num * 1000).toLocaleString();
};

export const MCPAgentServiceCard = ({
  settings,
  onUpdateSetting,
  apiRequest,
}: MCPAgentServiceCardProps) => {
  const [showToken, setShowToken] = useState<boolean>(false);
  const [revealedToken, setRevealedToken] = useState<string>('');
  const [rotatingToken, setRotatingToken] = useState<boolean>(false);
  const [copiedType, setCopiedType] = useState<string | null>(null);
  const [testing, setTesting] = useState<boolean>(false);
  const [testResult, setTestResult] = useState<any>(null);
  const [activeClientTab, setActiveClientTab] = useState<'claude' | 'antigravity' | 'cursor' | 'curl'>('claude');

  // Persona Preset State
  const [activePersona, setActivePersona] = useState<string>(settings?.mcp_persona_preset || 'guided');
  const [savingPersona, setSavingPersona] = useState<boolean>(false);

  // Catalog + Matrix State
  const [catalogTools, setCatalogTools] = useState<any[]>([]);
  const [toolCategoryFilter, setToolCategoryFilter] = useState<'all' | 'read' | 'mutating'>('all');
  const [toolTierFilter, setToolTierFilter] = useState<'all' | '1' | '2' | '3' | '4'>('all');
  const [toolSearch, setToolSearch] = useState<string>('');
  const [expandedToolSchema, setExpandedToolSchema] = useState<string | null>(null);
  const [activePipelineNode, setActivePipelineNode] = useState<number>(1);

  // Audit Log + Snapshots State
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [loadingAudit, setLoadingAudit] = useState<boolean>(false);
  const [clearingAudit, setClearingAudit] = useState<boolean>(false);
  const [snapshots, setSnapshots] = useState<any[]>([]);
  const [restoringSnapId, setRestoringSnapId] = useState<string | null>(null);
  const [undoBannerMsg, setUndoBannerMsg] = useState<string>('');

  // Governance Policy Matrix State
  const [toolMatrix, setToolMatrix] = useState<{ [key: string]: 'allowed' | 'confirmation_required' | 'blocked' }>({});
  const [savingMatrix, setSavingMatrix] = useState<boolean>(false);
  const [matrixSaveSuccess, setMatrixSaveSuccess] = useState<boolean>(false);

  // Staged Actions Queue State
  const [stagedActions, setStagedActions] = useState<any[]>([]);
  const [loadingStaged, setLoadingStaged] = useState<boolean>(false);
  const [processingStagedId, setProcessingStagedId] = useState<string | null>(null);
  const [stagedMessage, setStagedMessage] = useState<{ id: string; text: string; error?: boolean } | null>(null);
  const [stepUpTargetId, setStepUpTargetId] = useState<string | null>(null);
  const [stepUpSecret, setStepUpSecret] = useState<string>('');
  const [stepUpPromptMsg, setStepUpPromptMsg] = useState<string>('');

  const permissionScope = settings?.mcp_permission_scope || 'read_only';
  const rateLimit = settings?.mcp_rate_limit_per_min || 60;
  const tokenTtlDays = Number(settings?.mcp_token_ttl_days ?? 0);
  const allowedCidrs = String(settings?.mcp_allowed_cidrs ?? '');
  const displayToken = revealedToken || settings?.mcp_token || 'wcp_mcp_••••••••••••••••';

  const siteUrl = window.location.origin;
  const mcpRpcUrl = `${siteUrl}/wp-json/webcare-pro-security/v1/mcp/rpc`;
  const mcpExecuteUrl = `${siteUrl}/wp-json/webcare-pro-security/v1/mcp/execute`;

  useEffect(() => {
    if (settings?.mcp_persona_preset) {
      setActivePersona(settings.mcp_persona_preset);
    }
  }, [settings?.mcp_persona_preset]);

  const fetchToolsCatalog = async () => {
    try {
      const res = await apiRequest({ path: '/webcare-pro-security/v1/mcp/tools', method: 'GET' });
      if (Array.isArray(res?.tools)) {
        setCatalogTools(res.tools);
      }
      if (res?.personaPreset) {
        setActivePersona(res.personaPreset);
      }
    } catch (err) {
      console.error('Failed to fetch MCP catalog:', err);
    }
  };

  const fetchAuditLogs = async () => {
    setLoadingAudit(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/mcp/audit?limit=50',
        method: 'GET',
      });
      if (res?.success && Array.isArray(res.entries)) {
        setAuditLogs(res.entries);
      }
    } catch (err) {
      console.error('Failed to fetch MCP audit logs:', err);
    } finally {
      setLoadingAudit(false);
    }
  };

  const fetchSnapshots = async () => {
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/mcp/snapshots?limit=10',
        method: 'GET',
      });
      if (res?.success && Array.isArray(res.snapshots)) {
        setSnapshots(res.snapshots);
      }
    } catch (err) {
      console.error('Failed to fetch MCP snapshots:', err);
    }
  };

  const fetchToolMatrix = async () => {
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/mcp/matrix',
        method: 'GET',
      });
      if (res?.success && res?.matrix) {
        setToolMatrix(res.matrix);
      }
    } catch (err) {
      console.error('Failed to fetch MCP tool matrix:', err);
    }
  };

  const fetchStagedActions = async () => {
    setLoadingStaged(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/mcp/staged-actions?status=pending_approval',
        method: 'GET',
      });
      const list = Array.isArray(res?.actions)
        ? res.actions
        : Array.isArray(res?.staged_actions)
        ? res.staged_actions
        : [];
      setStagedActions(list);
    } catch (err) {
      console.error('Failed to fetch staged actions:', err);
    } finally {
      setLoadingStaged(false);
    }
  };

  useEffect(() => {
    fetchToolsCatalog();
    fetchAuditLogs();
    fetchToolMatrix();
    fetchStagedActions();
    fetchSnapshots();
  }, []);

  const handleApplyPersona = async (preset: 'observer' | 'guided' | 'safe_operator') => {
    setSavingPersona(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/mcp/persona',
        method: 'POST',
        data: { preset },
      });
      if (res?.success) {
        setActivePersona(preset);
        onUpdateSetting('mcp_persona_preset', preset);
        onUpdateSetting('mcp_permission_scope', res.scope);
        if (res.matrix) {
          setToolMatrix(res.matrix);
        }
        fetchToolsCatalog();
      }
    } catch (err) {
      console.error('Failed to switch MCP persona:', err);
    } finally {
      setSavingPersona(false);
    }
  };

  const handleSaveToolMatrix = async () => {
    setSavingMatrix(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/mcp/matrix',
        method: 'POST',
        data: { matrix: toolMatrix },
      });
      if (res?.success) {
        if (res.matrix) setToolMatrix(res.matrix);
        setMatrixSaveSuccess(true);
        setTimeout(() => setMatrixSaveSuccess(false), 3000);
        fetchToolsCatalog();
      }
    } catch (err) {
      console.error('Failed to save MCP tool matrix:', err);
    } finally {
      setSavingMatrix(false);
    }
  };

  const handleToggleRevealToken = async () => {
    if (showToken) {
      setShowToken(false);
      return;
    }
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/mcp/token/reveal',
        method: 'POST',
      });
      if (res?.success && res?.token) {
        setRevealedToken(res.token);
      }
      setShowToken(true);
    } catch (err) {
      console.error('Failed to reveal MCP token:', err);
    }
  };

  const handleCopyToken = async () => {
    let tok = revealedToken || settings?.mcp_token || '';
    if (!tok || tok.includes('••')) {
      try {
        const res = await apiRequest({
          path: '/webcare-pro-security/v1/mcp/token/reveal',
          method: 'POST',
        });
        if (res?.success && res?.token) {
          tok = res.token;
          setRevealedToken(tok);
        }
      } catch (e) {
        console.error(e);
      }
    }
    if (tok) {
      copyToClipboard(tok, 'c1-token');
    }
  };

  const regenerateToken = async () => {
    const confirmed = await showConfirm({
      title: 'Rotate MCP Bearer Token',
      message:
        'Are you sure you want to rotate the MCP Bearer Token? Any connected Claude, Cursor, or Antigravity clients will need the new token immediately.',
      confirmLabel: 'Rotate Token',
      variant: 'danger',
    });
    if (!confirmed) {
      return;
    }
    setRotatingToken(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/mcp/token/rotate',
        method: 'POST',
      });
      if (res?.success && res?.token) {
        setRevealedToken(res.token);
        setShowToken(true);
        onUpdateSetting('mcp_token', res.token);
      }
    } catch (err) {
      console.error('Failed to rotate MCP token:', err);
    } finally {
      setRotatingToken(false);
    }
  };

  const handleRestoreSnapshot = async (snapshotId: string) => {
    const confirmed = await showConfirm({
      title: 'Undo AI Change',
      message: 'Restore site rules and plugin settings back to this pre-change snapshot?',
      confirmLabel: 'Undo & Restore',
      variant: 'warning',
    });
    if (!confirmed) return;

    setRestoringSnapId(snapshotId);
    setUndoBannerMsg('');
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/mcp/snapshots/restore',
        method: 'POST',
        data: { snapshot_id: snapshotId },
      });
      if (res?.success) {
        setUndoBannerMsg(res.message || 'Changes reverted cleanly.');
        fetchSnapshots();
        fetchAuditLogs();
      } else {
        setUndoBannerMsg(res?.message || 'Restore failed.');
      }
    } catch (err: any) {
      setUndoBannerMsg(err?.message || 'Restore failed.');
    } finally {
      setRestoringSnapId(null);
    }
  };

  const handleApproveStaged = async (stagedId: string, riskTier: number, secretOverride = '') => {
    if (riskTier >= 4 && !secretOverride && stepUpTargetId !== stagedId) {
      setStepUpTargetId(stagedId);
      setStepUpSecret('');
      setStepUpPromptMsg('Tier 4 Destructive Action: enter your 2FA TOTP code (if enabled) or WP admin password to approve.');
      return;
    }

    setProcessingStagedId(stagedId);
    setStagedMessage(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/mcp/staged-actions/approve',
        method: 'POST',
        data: {
          staged_id: stagedId,
          step_up_secret: secretOverride || stepUpSecret,
        },
      });
      if (res?.step_up_required) {
        setStepUpTargetId(stagedId);
        setStepUpPromptMsg(res.message || 'Please enter your 2FA code or WP password.');
      } else if (res?.success) {
        setStepUpTargetId(null);
        setStepUpSecret('');
        setStepUpPromptMsg('');
        setStagedMessage({ id: stagedId, text: 'Action approved and executed safely (snapshot captured).' });
        fetchStagedActions();
        fetchAuditLogs();
        fetchSnapshots();
      } else {
        setStagedMessage({ id: stagedId, text: res?.message || 'Failed to approve action', error: true });
      }
    } catch (err: any) {
      setStagedMessage({ id: stagedId, text: err?.message || 'Execution error', error: true });
    } finally {
      setProcessingStagedId(null);
    }
  };

  const handleRejectStaged = async (stagedId: string) => {
    setProcessingStagedId(stagedId);
    setStagedMessage(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/mcp/staged-actions/reject',
        method: 'POST',
        data: { staged_id: stagedId },
      });
      if (res?.success) {
        if (stepUpTargetId === stagedId) setStepUpTargetId(null);
        setStagedMessage({ id: stagedId, text: 'Action rejected and removed from queue.' });
        fetchStagedActions();
      } else {
        setStagedMessage({ id: stagedId, text: res?.message || 'Failed to reject action', error: true });
      }
    } catch (err: any) {
      setStagedMessage({ id: stagedId, text: err?.message || 'Rejection error', error: true });
    } finally {
      setProcessingStagedId(null);
    }
  };

  const handleClearAudit = async () => {
    const confirmed = await showConfirm({
      title: 'Clear MCP Audit Trail',
      message: 'Are you sure you want to clear the MCP agent audit trail?',
      confirmLabel: 'Clear Audit Trail',
      variant: 'warning',
    });
    if (!confirmed) return;
    setClearingAudit(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/mcp/audit/clear',
        method: 'POST',
      });
      if (res?.success) {
        setAuditLogs([]);
      }
    } catch (err) {
      console.error('Failed to clear audit trail:', err);
    } finally {
      setClearingAudit(false);
    }
  };

  const copyToClipboard = (text: string, type: string) => {
    try {
      navigator.clipboard.writeText(text);
      setCopiedType(type);
      setTimeout(() => setCopiedType(null), 2500);
    } catch (e) {
      console.error('Failed to copy to clipboard', e);
    }
  };

  const handleTestHandshake = async () => {
    setTesting(true);
    setTestResult(null);
    const startTime = Date.now();
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/mcp/rpc',
        method: 'POST',
        data: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} },
      });
      const elapsed = Date.now() - startTime;
      const rpcTools = res?.result?.tools;
      if (Array.isArray(rpcTools)) {
        setTestResult({
          success: true,
          count: rpcTools.length,
          scope: permissionScope,
          latency: elapsed,
        });
      } else {
        setTestResult({ success: false, message: 'Invalid JSON-RPC response from /mcp/rpc.', latency: elapsed });
      }
    } catch (err: any) {
      const elapsed = Date.now() - startTime;
      setTestResult({ success: false, message: err?.message || 'Handshake failed.', latency: elapsed });
    } finally {
      setTesting(false);
    }
  };

  const normalizedTools = useMemo(() => {
    return catalogTools.map((t: any) => {
      const isMut = !emptyCheck(t?.isMutating);
      const tier = Number(t?.tier || (isMut ? 2 : 1));
      const props = t?.inputSchema?.properties && typeof t.inputSchema.properties === 'object' ? Object.keys(t.inputSchema.properties) : [];
      return {
        name: String(t.name || ''),
        category: isMut ? 'mutating' : 'read',
        tier,
        desc: String(t.description || ''),
        params: props.length > 0 ? props.join(', ') : 'None',
        schema: t.inputSchema || { type: 'object', properties: {} },
        policy: String(t.policy || (isMut ? 'confirmation_required' : 'allowed')),
        icon: getToolIcon(String(t.name || ''), isMut),
      };
    });
  }, [catalogTools]);

  function emptyCheck(val: any): boolean {
    return !val || val === 'false' || val === 0;
  }

  const filteredTools = useMemo(() => {
    return normalizedTools.filter((t) => {
      if (toolCategoryFilter !== 'all' && t.category !== toolCategoryFilter) return false;
      if (toolTierFilter !== 'all' && String(t.tier) !== toolTierFilter) return false;
      if (toolSearch.trim() !== '') {
        const q = toolSearch.trim().toLowerCase();
        if (!t.name.toLowerCase().includes(q) && !t.desc.toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [normalizedTools, toolCategoryFilter, toolTierFilter, toolSearch]);

  const tokenForSnippet = revealedToken || (settings?.mcp_token && !String(settings.mcp_token).includes('••') ? settings.mcp_token : '<REVEAL_OR_ROTATE_TOKEN_IN_WP_ADMIN>');

  const claudeDesktopConfig = JSON.stringify(
    {
      mcpServers: {
        'webcare-pro-security': {
          type: 'http',
          url: mcpRpcUrl,
          headers: {
            Authorization: `Bearer ${tokenForSnippet}`,
          },
        },
      },
    },
    null,
    2
  );

  const antigravityConfig = JSON.stringify(
    {
      mcpServers: {
        'webcare-pro-security': {
          type: 'http',
          url: mcpRpcUrl,
          headers: {
            Authorization: `Bearer ${tokenForSnippet}`,
          },
        },
      },
    },
    null,
    2
  );

  const cursorConfig = JSON.stringify(
    {
      mcpServers: {
        'webcare-security': {
          url: mcpRpcUrl,
          headers: {
            Authorization: `Bearer ${tokenForSnippet}`,
          },
        },
      },
    },
    null,
    2
  );

  const curlTestSnippet = `curl -X POST "${mcpRpcUrl}" \\
  -H "Authorization: Bearer ${tokenForSnippet}" \\
  -H "Content-Type: application/json" \\
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"webcareproscan_get_security_posture","arguments":{}}}'`;

  const getActiveClientCode = () => {
    switch (activeClientTab) {
      case 'claude':
        return claudeDesktopConfig;
      case 'antigravity':
        return antigravityConfig;
      case 'cursor':
        return cursorConfig;
      case 'curl':
        return curlTestSnippet;
    }
  };

  const activeUndoableSnap = snapshots.find((s) => !s.restored);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Handshake Toast */}
      {testResult && (
        <div
          className={testResult.success ? 'webcare-mcp-undo-banner' : 'webcare-mcp-stepup-box'}
          style={{ justifyContent: 'space-between', alignItems: 'center' }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            {testResult.success ? <CheckCircle2 size={18} /> : <AlertCircle size={18} />}
            <div>
              <div style={{ fontSize: '13px', fontWeight: 700 }}>
                {testResult.success ? 'Native JSON-RPC 2.0 MCP Gateway Verified' : 'Gateway Handshake Failed'}
              </div>
              <div style={{ fontSize: '12px', opacity: 0.9, marginTop: '2px' }}>
                {testResult.success
                  ? `Responded in ${testResult.latency}ms via /mcp/rpc. ${testResult.count} governed tools active under scope "${testResult.scope}".`
                  : testResult.message}
              </div>
            </div>
          </div>
          <button type="button" onClick={() => setTestResult(null)} className="webcare-c1-action-btn">
            Dismiss
          </button>
        </div>
      )}

      {/* 1-Click AI Change Undo Banner */}
      {(activeUndoableSnap || undoBannerMsg) && (
        <div className="webcare-mcp-undo-banner">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1 }}>
            <RotateCcw size={16} />
            <div style={{ fontSize: '12.5px' }}>
              {undoBannerMsg ? (
                <strong>{undoBannerMsg}</strong>
              ) : (
                <>
                  <strong>Recent AI Change:</strong> {activeUndoableSnap.summary || activeUndoableSnap.tool}{' '}
                  <span style={{ opacity: 0.8 }}>({formatUnixTime(activeUndoableSnap.timestamp)})</span>
                </>
              )}
            </div>
          </div>
          {activeUndoableSnap && (
            <button
              type="button"
              disabled={restoringSnapId === activeUndoableSnap.id}
              onClick={() => handleRestoreSnapshot(activeUndoableSnap.id)}
              className="webcare-c1-action-btn"
              style={{ fontWeight: 700 }}
            >
              <RotateCcw size={12} />
              <span>{restoringSnapId === activeUndoableSnap.id ? 'Reverting...' : 'Undo Last Change'}</span>
            </button>
          )}
        </div>
      )}

      {/* VISUAL PIPELINE STUDIO */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div className="webcare-c1-pipeline-hero">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <span style={{ fontSize: '11.5px', fontWeight: 700, color: '#0284c7', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Governed Full-Plugin Control Surface
              </span>
              <h2 style={{ fontSize: '21px', fontWeight: 800, margin: '2px 0 0', color: 'var(--webcare-text-main, #f8fafc)' }}>
                Autonomous SecOps &amp; Custom Rules MCP Gateway
              </h2>
              <p style={{ margin: '4px 0 0', fontSize: '13px', color: 'var(--webcare-text-muted, #94a3b8)' }}>
                Safe AI-agent integration bridge with granular tool permission gates and human-in-the-loop approvals.
              </p>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
              <div className="webcare-c1-status-pill">
                <span className="pulse-dot" style={{ width: '7px', height: '7px' }} />
                <span>{normalizedTools.length} Governed Tools &bull; JSON-RPC 2.0</span>
              </div>

              <button
                type="button"
                onClick={handleTestHandshake}
                disabled={testing}
                style={{
                  padding: '7px 14px',
                  borderRadius: '8px',
                  background: 'linear-gradient(135deg, #0284c7, #2563eb)',
                  color: '#ffffff',
                  border: 'none',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <RefreshCw size={13} className={testing ? 'webcare-spin-icon' : ''} />
                <span>{testing ? 'Testing...' : 'Test JSON-RPC'}</span>
              </button>
            </div>
          </div>

          <div className="webcare-c1-nodes-track">
            <div
              className={`webcare-c1-node ${activePipelineNode === 1 ? 'is-active-node' : ''}`}
              onClick={() => setActivePipelineNode(1)}
            >
              <div className="webcare-c1-node-icon">
                <Monitor size={20} />
              </div>
              <div>
                <h4 style={{ fontSize: '13.5px', fontWeight: 700, margin: 0 }}>1. External AI Clients</h4>
                <span style={{ fontSize: '11px' }}>Claude &bull; Antigravity &bull; Cursor &bull; ChatGPT</span>
              </div>
            </div>

            <div
              className={`webcare-c1-node ${activePipelineNode === 2 ? 'is-active-node' : ''}`}
              onClick={() => setActivePipelineNode(2)}
            >
              <div className="webcare-c1-node-icon" style={{ background: 'rgba(99, 102, 241, 0.15)', color: '#818cf8' }}>
                <Shield size={20} />
              </div>
              <div>
                <h4 style={{ fontSize: '13.5px', fontWeight: 700, margin: 0 }}>2. Tiered Governance Gate</h4>
                <span style={{ fontSize: '11px' }}>Anti-Lockout &bull; {rateLimit}/min Cap &bull; Step-Up 2FA</span>
              </div>
            </div>

            <div
              className={`webcare-c1-node ${activePipelineNode === 3 ? 'is-active-node' : ''}`}
              onClick={() => setActivePipelineNode(3)}
            >
              <div className="webcare-c1-node-icon" style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#34d399' }}>
                <Cpu size={20} />
              </div>
              <div>
                <h4 style={{ fontSize: '13.5px', fontWeight: 700, margin: 0 }}>3. WebCare Pro Modules</h4>
                <span style={{ fontSize: '11px' }}>Custom Rules &bull; Settings &bull; Scanner &bull; Snapshots</span>
              </div>
            </div>
          </div>
        </div>

        {/* NON-TECH FRIENDLY PERSONA PRESET SWITCHER */}
        <div className="webcare-c1-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
            <div>
              <h4 style={{ fontSize: '14.5px', fontWeight: 700, margin: 0, color: 'var(--webcare-text-main, #0f172a)' }}>
                AI Assistant Autonomy Preset (For Non-Technical Owners &amp; Operators)
              </h4>
              <span style={{ fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                Choose how much authority your connected AI agent receives. Tier 4 destructive actions always require WP Admin Step-Up confirmation.
              </span>
            </div>
            {savingPersona && <span style={{ fontSize: '11.5px', color: '#4f46e5', fontWeight: 600 }}>Applying preset...</span>}
          </div>

          <div className="webcare-mcp-persona-grid">
            <button
              type="button"
              disabled={savingPersona}
              onClick={() => handleApplyPersona('observer')}
              className={`webcare-mcp-persona-card ${activePersona === 'observer' ? 'is-active' : ''}`}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <strong style={{ fontSize: '13.5px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Lock size={14} color="#f59e0b" />
                  <span>1. Observer (Read-Only)</span>
                </strong>
                <span className="webcare-mcp-tier-badge webcare-mcp-tier-1">Safest</span>
              </div>
              <p className="webcare-mcp-persona-desc">
                AI inspects posture, findings, traffic logs, and simulates rules. All write actions stay blocked.
              </p>
            </button>

            <button
              type="button"
              disabled={savingPersona}
              onClick={() => handleApplyPersona('guided')}
              className={`webcare-mcp-persona-card ${activePersona === 'guided' ? 'is-active' : ''}`}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <strong style={{ fontSize: '13.5px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Shield size={14} color="#4f46e5" />
                  <span>2. Guided Assistant</span>
                </strong>
                <span className="webcare-mcp-tier-badge webcare-mcp-tier-2">Recommended</span>
              </div>
              <p className="webcare-mcp-persona-desc">
                AI reads &amp; simulates freely, then proposes rules, scans, and setting diffs into the Staged Queue for your 1-click Approve.
              </p>
            </button>

            <button
              type="button"
              disabled={savingPersona}
              onClick={() => handleApplyPersona('safe_operator')}
              className={`webcare-mcp-persona-card ${activePersona === 'safe_operator' ? 'is-active' : ''}`}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <strong style={{ fontSize: '13.5px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Zap size={14} color="#10b981" />
                  <span>3. Autonomous Safe Operator</span>
                </strong>
                <span className="webcare-mcp-tier-badge webcare-mcp-tier-3">Power Mode</span>
              </div>
              <p className="webcare-mcp-persona-desc">
                Tier 2 reversible writes execute automatically with pre-change snapshots &amp; anti-lockout. Tier 3/4 stay staged.
              </p>
            </button>
          </div>
        </div>

        {/* 2-COLUMN SPLIT STUDIO */}
        <div className="webcare-c1-studio-grid">
          {/* Left Column: Credentials & Safety Caps */}
          <div className="webcare-c1-control-tower">
            <div className="webcare-c1-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <span className="webcare-c1-card-title">Gateway Credentials</span>
                <button
                  type="button"
                  onClick={regenerateToken}
                  disabled={rotatingToken}
                  style={{
                    padding: '4px 10px',
                    borderRadius: '6px',
                    background: 'rgba(239, 68, 68, 0.12)',
                    color: '#ef4444',
                    border: '1px solid rgba(239, 68, 68, 0.25)',
                    fontSize: '11px',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  {rotatingToken ? 'Rotating...' : 'Rotate Token'}
                </button>
              </div>

              <div style={{ marginBottom: '12px' }}>
                <label className="webcare-c1-card-label">JSON-RPC 2.0 Endpoint URL</label>
                <div style={{ display: 'flex', gap: '6px', marginTop: '6px' }}>
                  <input
                    type="text"
                    readOnly
                    value={mcpRpcUrl}
                    onFocus={(e) => e.target.select()}
                    className="webcare-c1-input-field"
                  />
                  <button type="button" onClick={() => copyToClipboard(mcpRpcUrl, 'c1-url')} className="webcare-c1-action-btn">
                    {copiedType === 'c1-url' ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>

              <div style={{ marginBottom: '12px' }}>
                <label className="webcare-c1-card-label">Bearer Secret Token (Vault-Encrypted)</label>
                <div style={{ display: 'flex', gap: '6px', marginTop: '6px' }}>
                  <input
                    type={showToken ? 'text' : 'password'}
                    readOnly
                    value={displayToken}
                    onFocus={(e) => e.target.select()}
                    className="webcare-c1-input-field"
                  />
                  <button
                    type="button"
                    onClick={handleToggleRevealToken}
                    className="webcare-c1-action-btn"
                    style={{ padding: '6px 10px' }}
                    title={showToken ? 'Hide token' : 'Reveal token'}
                  >
                    {showToken ? <EyeOff size={13} /> : <Eye size={13} />}
                  </button>
                  <button type="button" onClick={handleCopyToken} className="webcare-c1-action-btn">
                    {copiedType === 'c1-token' ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>

              <div style={{ marginBottom: '12px' }}>
                <label className="webcare-c1-card-label">Token Expiration (TTL)</label>
                <select
                  value={tokenTtlDays}
                  onChange={(e) => onUpdateSetting('mcp_token_ttl_days', Number(e.target.value))}
                  className="webcare-c1-input-field"
                  style={{ width: '100%', marginTop: '6px' }}
                >
                  <option value={0}>Never Expires (Static until rotated)</option>
                  <option value={7}>7 Days</option>
                  <option value={30}>30 Days (Recommended)</option>
                  <option value={90}>90 Days</option>
                </select>
              </div>

              <div>
                <label className="webcare-c1-card-label">Allowed Client IPs / CIDRs (Optional)</label>
                <textarea
                  rows={2}
                  value={allowedCidrs}
                  placeholder="Leave blank to allow any authenticated Bearer client, or list 203.0.113.10/32"
                  onChange={(e) => onUpdateSetting('mcp_allowed_cidrs', e.target.value)}
                  className="webcare-c1-input-field"
                  style={{ width: '100%', marginTop: '6px', resize: 'vertical', fontFamily: 'monospace' }}
                />
              </div>
            </div>

            {/* Rate Limit Card */}
            <div className="webcare-c1-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span className="webcare-c1-card-title">Sliding Rate Limit</span>
                <span style={{ fontSize: '11px', color: '#10b981', fontWeight: 600 }}>Active Flood Shield</span>
              </div>
              <p style={{ margin: '0 0 12px', fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                Prevents runaway AI reasoning loops from overloading WordPress ({permissionScope}).
              </p>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '6px' }}>
                {[30, 60, 120, 300].map((rate) => (
                  <button
                    key={rate}
                    type="button"
                    onClick={() => onUpdateSetting('mcp_rate_limit_per_min', rate)}
                    className={`webcare-c1-rate-btn ${rateLimit === rate ? 'is-active' : ''}`}
                  >
                    {rate}/m
                  </button>
                ))}
              </div>
            </div>

            {/* Pre-Change Rollback Snapshots Card */}
            <div className="webcare-c1-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                <span className="webcare-c1-card-title">Rollback Snapshots ({snapshots.length})</span>
                <button type="button" onClick={fetchSnapshots} className="webcare-c1-action-btn" style={{ padding: '4px 8px' }}>
                  <RefreshCw size={11} />
                </button>
              </div>
              {snapshots.length === 0 ? (
                <p style={{ margin: 0, fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  Pre-change snapshots are automatically saved before any mutating MCP operation.
                </p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '220px', overflowY: 'auto' }}>
                  {snapshots.map((snap) => (
                    <div
                      key={snap.id}
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        gap: '8px',
                        fontSize: '11.5px',
                        paddingBottom: '6px',
                        borderBottom: '1px solid var(--webcare-border-subtle, rgba(148,163,184,0.2))',
                      }}
                    >
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {snap.summary || snap.tool}
                        </div>
                        <div style={{ fontSize: '10.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                          {formatUnixTime(snap.timestamp)} &bull; {snap.restored ? 'Reverted' : 'Active'}
                        </div>
                      </div>
                      {!snap.restored && (
                        <button
                          type="button"
                          onClick={() => handleRestoreSnapshot(snap.id)}
                          disabled={restoringSnapId === snap.id}
                          className="webcare-c1-action-btn"
                          style={{ padding: '4px 8px', flexShrink: 0 }}
                        >
                          <RotateCcw size={11} />
                          <span>Undo</span>
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Right Column: Client Config + Live Dynamic Tool Matrix */}
          <div className="webcare-c1-workspace">
            <div className="webcare-c1-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
                <div>
                  <h4 style={{ fontSize: '14.5px', fontWeight: 700, margin: 0, color: 'var(--webcare-text-main, #0f172a)' }}>
                    1-Click Native JSON-RPC 2.0 Client Config
                  </h4>
                  <span style={{ fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    Connect Claude, Antigravity, or Cursor directly to <code style={{ fontSize: '11px' }}>/mcp/rpc</code> (legacy <code style={{ fontSize: '11px' }}>/mcp/execute</code> also active).
                  </span>
                </div>

                <div className="webcare-c1-tab-group">
                  {(['claude', 'antigravity', 'cursor', 'curl'] as const).map((tab) => (
                    <button
                      key={tab}
                      type="button"
                      onClick={() => setActiveClientTab(tab)}
                      className={`webcare-c1-tab-btn ${activeClientTab === tab ? 'is-active' : ''}`}
                    >
                      {tab === 'claude' ? 'Claude' : tab === 'antigravity' ? 'Antigravity' : tab === 'cursor' ? 'Cursor' : 'cURL'}
                    </button>
                  ))}
                </div>
              </div>

              <div style={{ position: 'relative' }}>
                <pre className="webcare-c1-code-terminal">{getActiveClientCode()}</pre>
                <button
                  type="button"
                  onClick={() => copyToClipboard(getActiveClientCode(), 'c1-snippet')}
                  style={{
                    position: 'absolute',
                    top: '10px',
                    right: '10px',
                    padding: '5px 10px',
                    borderRadius: '6px',
                    background: 'rgba(15, 23, 42, 0.78)',
                    border: '1px solid rgba(255,255,255,0.2)',
                    color: '#ffffff',
                    fontSize: '11px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                  }}
                >
                  <Copy size={12} />
                  <span>{copiedType === 'c1-snippet' ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>
            </div>

            {/* Dynamic Exposed Tools Matrix */}
            <div className="webcare-c1-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
                <div>
                  <h4 style={{ fontSize: '14.5px', fontWeight: 700, margin: 0, color: 'var(--webcare-text-main, #0f172a)' }}>
                    Governed Security Tools Matrix ({normalizedTools.length} Loaded)
                  </h4>
                  <span style={{ fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    Per-tool autonomy &amp; risk tier controls across all WebCare Pro modules
                  </span>
                </div>

                <button
                  type="button"
                  onClick={handleSaveToolMatrix}
                  disabled={savingMatrix}
                  style={{
                    padding: '6px 12px',
                    borderRadius: '6px',
                    background: matrixSaveSuccess ? '#10b981' : '#4f46e5',
                    color: '#ffffff',
                    border: 'none',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                  }}
                >
                  {savingMatrix ? <RefreshCw size={12} className="webcare-spin-icon" /> : matrixSaveSuccess ? <Check size={12} /> : <Save size={12} />}
                  <span>{matrixSaveSuccess ? 'Policies Saved!' : 'Save Policies'}</span>
                </button>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '12px' }}>
                <div className="webcare-c1-tab-group">
                  {(['all', 'read', 'mutating'] as const).map((cat) => (
                    <button
                      key={cat}
                      type="button"
                      onClick={() => setToolCategoryFilter(cat)}
                      className={`webcare-c1-tab-btn ${toolCategoryFilter === cat ? 'is-active' : ''}`}
                    >
                      {cat === 'all'
                        ? `All (${normalizedTools.length})`
                        : cat === 'read'
                        ? `Read (${normalizedTools.filter((t) => t.category === 'read').length})`
                        : `Mutate (${normalizedTools.filter((t) => t.category === 'mutating').length})`}
                    </button>
                  ))}
                </div>

                <div className="webcare-c1-tab-group">
                  {(['all', '1', '2', '3', '4'] as const).map((tr) => (
                    <button
                      key={tr}
                      type="button"
                      onClick={() => setToolTierFilter(tr)}
                      className={`webcare-c1-tab-btn ${toolTierFilter === tr ? 'is-active' : ''}`}
                    >
                      {tr === 'all' ? 'All Tiers' : `T${tr}`}
                    </button>
                  ))}
                </div>

                <div style={{ position: 'relative', flex: 1, minWidth: '170px' }}>
                  <Search size={13} style={{ position: 'absolute', left: '9px', top: '50%', transform: 'translateY(-50%)', opacity: 0.6 }} />
                  <input
                    type="text"
                    value={toolSearch}
                    onChange={(e) => setToolSearch(e.target.value)}
                    placeholder="Filter tools..."
                    className="webcare-c1-input-field"
                    style={{ width: '100%', paddingLeft: '28px' }}
                  />
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '520px', overflowY: 'auto' }}>
                {filteredTools.map((tool) => {
                  const isExpanded = expandedToolSchema === tool.name;
                  const IconComponent = tool.icon;
                  const activePolicy = toolMatrix[tool.name] || tool.policy || (tool.category === 'read' ? 'allowed' : 'confirmation_required');
                  const tierClass = `webcare-mcp-tier-badge webcare-mcp-tier-${tool.tier}`;
                  return (
                    <div key={tool.name} className="webcare-c1-tool-row">
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, minWidth: 0 }}>
                        <div
                          style={{
                            width: '36px',
                            height: '36px',
                            borderRadius: '8px',
                            background: tool.category === 'read' ? 'rgba(16, 185, 129, 0.12)' : 'rgba(245, 158, 11, 0.12)',
                            color: tool.category === 'read' ? '#10b981' : '#d97706',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            flexShrink: 0,
                          }}
                        >
                          <IconComponent size={18} />
                        </div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                            <strong className="webcare-c1-tool-name" style={{ fontFamily: 'monospace', fontSize: '12.5px' }}>
                              {tool.name}
                            </strong>
                            <span className={tierClass}>Tier {tool.tier}</span>
                            <span className={tool.category === 'read' ? 'webcare-c1-badge-read' : 'webcare-c1-badge-mutate'}>
                              {tool.category === 'read' ? 'Read' : 'Mutate'}
                            </span>
                          </div>
                          <div className="webcare-c1-tool-desc" style={{ fontSize: '12px', marginTop: '3px' }}>
                            {tool.desc}
                          </div>
                          <div className="webcare-c1-tool-params" style={{ fontSize: '11px', marginTop: '2px', fontFamily: 'monospace' }}>
                            Params: {tool.params}
                          </div>

                          {isExpanded && (
                            <pre className="webcare-mcp-code-preview">{JSON.stringify(tool.schema, null, 2)}</pre>
                          )}
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
                        <select
                          value={tool.tier >= 4 && activePolicy === 'allowed' ? 'confirmation_required' : activePolicy}
                          onChange={(e) => {
                            const val = e.target.value as 'allowed' | 'confirmation_required' | 'blocked';
                            setToolMatrix((prev) => ({ ...prev, [tool.name]: val }));
                          }}
                          className="webcare-c1-input-field"
                          style={{ fontSize: '11.5px', fontWeight: 600, padding: '5px 8px', cursor: 'pointer' }}
                          title={tool.tier >= 4 ? 'Tier 4 tools cannot run unattended without approval' : 'Configure tool execution policy'}
                        >
                          {tool.tier < 4 && <option value="allowed">Allowed (Auto)</option>}
                          <option value="confirmation_required">Staged Approval</option>
                          <option value="blocked">Blocked</option>
                        </select>

                        <button
                          type="button"
                          onClick={() => setExpandedToolSchema(isExpanded ? null : tool.name)}
                          className="webcare-c1-action-btn"
                        >
                          <span>{isExpanded ? 'Hide' : 'Schema'}</span>
                          {isExpanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* STAGED ACTIONS APPROVAL QUEUE WITH DIFF & TIER 4 STEP-UP */}
      <section className="webcare-c1-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h3 className="webcare-c1-card-title" style={{ fontSize: '15px', display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
                <Clock size={16} color="#d97706" />
                <span>Agent Staged Actions Approval Queue</span>
              </h3>
              {stagedActions.length > 0 ? (
                <span className="webcare-mcp-tier-badge webcare-mcp-tier-3">{stagedActions.length} Pending Approval</span>
              ) : (
                <span className="webcare-mcp-tier-badge webcare-mcp-tier-1">Queue Clear</span>
              )}
            </div>
            <p style={{ margin: '4px 0 0', fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
              Proposed AI mutations awaiting interactive administrator review in WP Admin (24-hour expiry).
            </p>
          </div>

          <button type="button" onClick={fetchStagedActions} disabled={loadingStaged} className="webcare-c1-action-btn">
            <RefreshCw size={12} className={loadingStaged ? 'webcare-spin-icon' : ''} />
            <span>Refresh Queue</span>
          </button>
        </div>

        {stagedActions.length === 0 ? (
          <div className="webcare-c1-audit-empty" style={{ padding: '24px 16px', textAlign: 'center' }}>
            No pending AI proposals. Any Tier 3/4 or Guided Mode mutation proposed by your AI agent appears here with a Before/After diff card.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {stagedActions.map((action: any) => {
              const sid = String(action.id || action.action_id || '');
              const riskTier = Number(action.risk_tier || 3);
              const argsObj = action.args ?? action.arguments ?? {};
              const diffs = Array.isArray(action.diff_preview) ? action.diff_preview : [];
              const warnings = Array.isArray(action.warnings) ? action.warnings : [];
              const needsStepUpUI = stepUpTargetId === sid;

              return (
                <div key={sid} className="webcare-mcp-staged-card">
                  <div style={{ flex: 1, minWidth: '280px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                      <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: '12px', color: '#d97706' }}>{sid}</span>
                      <strong style={{ fontFamily: 'monospace', fontSize: '13px' }}>{action.tool}</strong>
                      <span className={`webcare-mcp-tier-badge webcare-mcp-tier-${riskTier}`}>Tier {riskTier}</span>
                      <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                        from {action.client_ip || '127.0.0.1'} &bull; {formatUnixTime(action.created_at)}
                      </span>
                    </div>

                    {action.summary && (
                      <div style={{ marginTop: '6px', fontSize: '12.5px', fontWeight: 600 }}>{action.summary}</div>
                    )}

                    {warnings.length > 0 && (
                      <div className="webcare-mcp-stepup-box" style={{ fontSize: '12px' }}>
                        {warnings.map((w: string, i: number) => (
                          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <AlertTriangle size={13} />
                            <span>{w}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {diffs.length > 0 && (
                      <table className="webcare-mcp-diff-table">
                        <thead>
                          <tr>
                            <th>Setting Key</th>
                            <th>Before</th>
                            <th>After</th>
                          </tr>
                        </thead>
                        <tbody>
                          {diffs.map((d: any, idx: number) => (
                            <tr key={idx}>
                              <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>{d.key}</td>
                              <td style={{ fontFamily: 'monospace' }}>{JSON.stringify(d.before)}</td>
                              <td style={{ fontFamily: 'monospace', fontWeight: 700 }}>{JSON.stringify(d.after)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}

                    <pre className="webcare-mcp-code-preview">
                      {typeof argsObj === 'object' ? JSON.stringify(argsObj, null, 2) : String(argsObj || '{}')}
                    </pre>

                    {needsStepUpUI && (
                      <div className="webcare-mcp-stepup-box">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 700, fontSize: '12px', marginBottom: '6px' }}>
                          <KeyRound size={14} />
                          <span>{stepUpPromptMsg}</span>
                        </div>
                        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                          <input
                            type="password"
                            value={stepUpSecret}
                            onChange={(e) => setStepUpSecret(e.target.value)}
                            placeholder="Enter 2FA code or WP password"
                            className="webcare-c1-input-field"
                            style={{ flex: 1, minWidth: '180px' }}
                          />
                          <button
                            type="button"
                            disabled={!stepUpSecret || processingStagedId === sid}
                            onClick={() => handleApproveStaged(sid, riskTier, stepUpSecret)}
                            style={{
                              padding: '6px 12px',
                              borderRadius: '6px',
                              border: 'none',
                              background: '#dc2626',
                              color: '#ffffff',
                              fontSize: '12px',
                              fontWeight: 600,
                              cursor: 'pointer',
                            }}
                          >
                            Confirm Tier 4 Execute
                          </button>
                        </div>
                      </div>
                    )}

                    {stagedMessage && stagedMessage.id === sid && (
                      <div
                        style={{
                          fontSize: '11.5px',
                          marginTop: '6px',
                          color: stagedMessage.error ? '#ef4444' : '#10b981',
                          fontWeight: 600,
                        }}
                      >
                        {stagedMessage.text}
                      </div>
                    )}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <button
                      type="button"
                      onClick={() => handleApproveStaged(sid, riskTier)}
                      disabled={processingStagedId === sid}
                      style={{
                        padding: '8px 14px',
                        borderRadius: '6px',
                        border: 'none',
                        background: riskTier >= 4 ? '#d97706' : '#10b981',
                        color: '#ffffff',
                        fontSize: '12px',
                        fontWeight: 600,
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                      }}
                    >
                      {processingStagedId === sid ? <RefreshCw size={12} className="webcare-spin-icon" /> : <Check size={12} />}
                      <span>{riskTier >= 4 ? 'Verify & Approve' : 'Approve & Execute'}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => handleRejectStaged(sid)}
                      disabled={processingStagedId === sid}
                      style={{
                        padding: '8px 14px',
                        borderRadius: '6px',
                        border: '1px solid rgba(239, 68, 68, 0.4)',
                        background: 'rgba(239, 68, 68, 0.12)',
                        color: '#ef4444',
                        fontSize: '12px',
                        fontWeight: 600,
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                      }}
                    >
                      <X size={12} />
                      <span>Reject</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* REAL-TIME AGENT AUDIT LEDGER */}
      <section className="webcare-c1-audit-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
          <div>
            <h3 className="webcare-c1-audit-title">
              <Activity size={16} color="#0284c7" />
              <span>Real-Time Agent Execution Audit Ledger</span>
            </h3>
            <span className="webcare-c1-audit-subtitle">
              Forensic tracking of every autonomous tool call, caller IP, redacted parameters, and duration
            </span>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <button type="button" onClick={fetchAuditLogs} disabled={loadingAudit} className="webcare-c1-action-btn">
              <RefreshCw size={12} className={loadingAudit ? 'webcare-spin-icon' : ''} />
              <span>Refresh</span>
            </button>
            <button
              type="button"
              onClick={handleClearAudit}
              disabled={clearingAudit || auditLogs.length === 0}
              className="webcare-c1-btn-danger"
            >
              <Trash2 size={12} />
              <span>Clear Log</span>
            </button>
          </div>
        </div>

        {auditLogs.length === 0 ? (
          <div className="webcare-c1-audit-empty">
            No external agent calls recorded yet. Connect an AI client using the JSON-RPC config above to inspect live calls.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="webcare-c1-audit-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Tool Invoked</th>
                  <th>Caller IP</th>
                  <th>Status</th>
                  <th>Duration</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map((log: any, idx: number) => {
                  const st = String(log.status || 'success');
                  const isOk = st === 'success' || st === 'approved_executed' || st === '200';
                  return (
                    <tr key={log.id || idx}>
                      <td className="webcare-c1-audit-mono">{formatUnixTime(log.timestamp || log.time)}</td>
                      <td className="webcare-c1-audit-tool">{log.tool || log.action || '—'}</td>
                      <td className="webcare-c1-audit-mono">{log.client_ip || log.ip || '127.0.0.1'}</td>
                      <td>
                        <span className={isOk ? 'webcare-c1-badge-ok' : 'webcare-c1-badge-err'}>{st}</span>
                      </td>
                      <td className="webcare-c1-audit-duration">
                        {log.duration_ms !== undefined ? `${log.duration_ms}ms` : log.duration ? `${log.duration}ms` : '—'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
};
