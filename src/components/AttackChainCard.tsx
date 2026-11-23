import { useState, useEffect } from '@wordpress/element';
import { showConfirm } from '../utils/dialog';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Activity,
  Layers,
  Flame,
  AlertTriangle,
  RotateCcw,
  Trash2,
  Lock,
  ChevronRight,
  ChevronDown,
  Info,
  Server,
  Database,
  UserCheck,
  FileCode,
  Radio,
  CheckCircle2,
  Clock,
  ExternalLink,
  Sparkles,
  Loader2,
  Phone,
  ArrowUpRight
} from 'lucide-react';

interface StageItem {
  stage_id: 'initial_access' | 'execution_staging' | 'persistence' | 'privilege_escalation' | 'c2_beacon';
  stage_name: string;
  status: 'breached' | 'bypassed' | 'clean';
  title: string;
  details: string;
  item_type: string;
  item_id: string | number;
}

interface RemediationPlan {
  quarantine_files: string[];
  delete_options: string[];
  delete_users: number[];
  clear_crons: string[];
  block_ips: string[];
}

interface AttackChain {
  chain_id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  blast_radius: number;
  lateral_movement: boolean;
  narrative: string;
  stages: StageItem[];
  remediation_plan: RemediationPlan;
}

interface AttackChainAuditResponse {
  success: boolean;
  timestamp: number;
  summary: {
    total_chains: number;
    max_blast_score: number;
    highest_severity: string;
    lateral_movement: boolean;
    total_isolated_threats: number;
    total_persistence_keys: number;
    firewall_threat_ips: number;
  };
  chains: AttackChain[];
}

interface AttackChainCardProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  onChainRemediated?: () => void;
  onNavigateToSupport?: () => void;
}

export function AttackChainCard({ apiRequest, onChainRemediated, onNavigateToSupport }: AttackChainCardProps) {
  const [loading, setLoading] = useState<boolean>(false);
  const [eradicating, setEradicating] = useState<boolean>(false);
  const [auditData, setAuditData] = useState<AttackChainAuditResponse | null>(null);
  const [selectedChainId, setSelectedChainId] = useState<string | null>(null);
  const [expandedStage, setExpandedStage] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const fetchAttackChains = async () => {
    setLoading(true);
    setFeedback(null);
    try {
      const res: AttackChainAuditResponse = await apiRequest({
        path: '/webcare-pro-security/v1/attack-chain/audit',
        method: 'GET',
      });
      if (res && res.success) {
        setAuditData(res);
        if (res.chains && res.chains.length > 0) {
          setSelectedChainId(res.chains[0].chain_id);
        }
      }
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || 'Failed to analyze attack-chain signals. Please try again.',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAttackChains();
  }, []);

  const handleEradicateChain = async (chain: AttackChain) => {
    const confirmed = await showConfirm({
      title: `Eradicate Attack Chain: ${chain.title}`,
      message: `Are you sure you want to eradicate the entire attack chain "${chain.title}"?\n\nThis will surgically quarantine all connected webshell files, delete malicious database persistence options, revoke unauthorized users, and block threat IPs in the WAF.`,
      confirmLabel: 'Eradicate Attack Chain',
      variant: 'danger',
    });
    if (!confirmed) {
      return;
    }

    setEradicating(true);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/attack-chain/eradicate',
        method: 'POST',
        data: {
          chain_id: chain.chain_id,
          plan: chain.remediation_plan,
        },
      });

      if (res && res.success) {
        setFeedback({
          type: 'success',
          message: res.message || 'Attack chain eradicated successfully! Encrypted safety snapshots saved to vault.',
        });
        await fetchAttackChains();
        if (onChainRemediated) {
          onChainRemediated();
        }
      } else {
        setFeedback({
          type: 'error',
          message: res?.message || 'Failed to eradicate all chain artifacts.',
        });
      }
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || 'Network error executing full-chain eradication.',
      });
    } finally {
      setEradicating(false);
    }
  };

  const selectedChain = auditData?.chains.find((c) => c.chain_id === selectedChainId) || auditData?.chains[0];

  const getBlastColor = (score: number) => {
    if (score >= 70) return '#ef4444';
    if (score >= 40) return '#f59e0b';
    return '#10b981';
  };

  return (
    <div
      className="webcare-forensics-subcard webcare-forensics-attack-chain"
      style={{ display: 'flex', flexDirection: 'column', gap: '20px', padding: 0, background: 'transparent', border: 'none', boxShadow: 'none' }}
    >
      {/* Top Header Card */}
      <div className="webcare-attack-chain-header">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div className="webcare-attack-chain-icon-wrap">
              <Zap size={26} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <h2 className="webcare-attack-chain-title" style={{ margin: 0, fontSize: '20px', fontWeight: 800 }}>
                  Behavioral Anomaly &amp; Attack-Chain Correlation Engine
                </h2>
                <span className="webcare-attack-chain-badge">
                  Phase 2 &bull; MITRE ATT&amp;CK for WordPress
                </span>
              </div>
              <p className="webcare-attack-chain-desc" style={{ margin: '6px 0 0 0', fontSize: '13px', maxWidth: '780px' }}>
                Stitches isolated scanner findings, WAF exploit probes, drop-in files, database autoload options, and user creation events into unified attack narratives with blast-radius calculation.
              </p>
            </div>
          </div>

          <button
            type="button"
            className="webcare-btn webcare-attack-chain-reload-btn"
            onClick={fetchAttackChains}
            disabled={loading}
          >
            <RotateCcw size={14} className={loading ? 'webcare-spin-icon' : ''} />
            {loading ? 'Correlating Signals...' : 'Re-Correlate Signals'}
          </button>
        </div>

        {/* 4 Summary KPI Badges */}
        {auditData && (
          <div className="webcare-attack-chain-kpis">
            <div className="webcare-attack-chain-kpi-card">
              <div className="webcare-attack-chain-kpi-label">
                <Flame size={13} color="#f87171" /> Correlated Attack Chains
              </div>
              <div className="webcare-attack-chain-kpi-value" style={{ fontFamily: 'monospace' }}>
                {auditData.summary.total_chains} Active
              </div>
            </div>

            <div className="webcare-attack-chain-kpi-card">
              <div className="webcare-attack-chain-kpi-label">
                <Activity size={13} color="#fbbf24" /> Max Blast Radius Exposure
              </div>
              <div className="webcare-attack-chain-kpi-value" style={{ color: getBlastColor(auditData.summary.max_blast_score), fontFamily: 'monospace' }}>
                {auditData.summary.max_blast_score}%
              </div>
            </div>

            <div className="webcare-attack-chain-kpi-card">
              <div className="webcare-attack-chain-kpi-label">
                <Layers size={13} color="#38bdf8" /> Lateral Movement Status
              </div>
              <div style={{ fontSize: '16px', fontWeight: 800, color: auditData.summary.lateral_movement ? '#f87171' : '#10b981', marginTop: '6px' }}>
                {auditData.summary.lateral_movement ? 'Lateral Spread Detected' : 'Isolated Boundary'}
              </div>
            </div>

            <div className="webcare-attack-chain-kpi-card">
              <div className="webcare-attack-chain-kpi-label">
                <ShieldCheck size={13} color="#a78bfa" /> Isolated Signals Clustered
              </div>
              <div className="webcare-attack-chain-kpi-value" style={{ fontFamily: 'monospace' }}>
                {auditData.summary.total_isolated_threats} Signals
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Feedback Banner */}
      {feedback && (
        <div style={{
          padding: '12px 18px',
          borderRadius: '10px',
          background: feedback.type === 'success' ? '#ecfdf5' : '#fef2f2',
          border: `1px solid ${feedback.type === 'success' ? '#a7f3d0' : '#fecaca'}`,
          color: feedback.type === 'success' ? '#065f46' : '#991b1b',
          fontSize: '13px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          fontWeight: 600
        }}>
          {feedback.type === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
          <span>{feedback.message}</span>
        </div>
      )}

      {/* Loading State */}
      {loading && !auditData && (
        <div style={{ padding: '60px', textAlign: 'center', background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
          <Loader2 size={32} className="webcare-spin-icon" color="#6366f1" style={{ margin: '0 auto 12px auto' }} />
          <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--webcare-text-primary, #1e293b)' }}>
            Correlating Multi-Vector Attack Signals...
          </div>
          <div style={{ fontSize: '13px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
            Cross-referencing CVE vulnerabilities, file system timestamps, database autoload payloads, and user capability logs.
          </div>
        </div>
      )}

      {/* Zero Chains Clean State */}
      {!loading && auditData && auditData.chains.length === 0 && (
        <div style={{
          padding: '50px 30px',
          textAlign: 'center',
          background: '#ffffff',
          borderRadius: '14px',
          border: '1px solid #e2e8f0'
        }}>
          <div style={{ width: '56px', height: '56px', borderRadius: '50%', background: '#ecfdf5', color: '#059669', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px auto' }}>
            <ShieldCheck size={32} />
          </div>
          <h3 style={{ margin: '0 0 6px 0', fontSize: '18px', fontWeight: 800, color: '#0f172a' }}>
            Zero Compound Attack Chains Detected
          </h3>
          <p style={{ margin: '0 auto', fontSize: '13px', color: '#64748b', maxWidth: '520px', lineHeight: 1.6 }}>
            The correlation engine found no multi-stage kill chains bridging vulnerabilities, webshell droppers, and database persistence. Any single isolated issues can be resolved in the main Findings table.
          </p>
        </div>
      )}

      {/* Active Attack Chains Display */}
      {!loading && selectedChain && (
        <div style={{
          background: '#ffffff',
          borderRadius: '14px',
          border: '1px solid #e2e8f0',
          boxShadow: '0 2px 8px rgba(0, 0, 0, 0.04)',
          overflow: 'hidden'
        }}>
          {/* Chain Header & Action Bar */}
          <div style={{
            padding: '20px 24px',
            borderBottom: '1px solid #f1f5f9',
            background: '#fafafa',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '16px'
          }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                <span style={{
                  background: selectedChain.severity === 'critical' ? '#fee2e2' : '#fef3c7',
                  color: selectedChain.severity === 'critical' ? '#b91c1c' : '#b45309',
                  border: `1px solid ${selectedChain.severity === 'critical' ? '#fca5a5' : '#fde68a'}`,
                  padding: '2px 8px',
                  borderRadius: '999px',
                  fontSize: '11px',
                  fontWeight: 800,
                  textTransform: 'uppercase'
                }}>
                  {selectedChain.severity.toUpperCase()} THREAT
                </span>
                <span style={{ fontSize: '12px', color: '#64748b', fontFamily: 'monospace' }}>
                  ID: #{selectedChain.chain_id}
                </span>
              </div>
              <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 800, color: '#0f172a' }}>
                {selectedChain.title}
              </h3>
            </div>

            {/* 1-Click Eradicate Full Chain Button */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <button
                type="button"
                className="webcare-btn"
                onClick={() => handleEradicateChain(selectedChain)}
                disabled={eradicating}
                style={{
                  background: 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)',
                  color: '#ffffff',
                  border: 'none',
                  padding: '10px 20px',
                  fontSize: '13px',
                  fontWeight: 800,
                  borderRadius: '8px',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  boxShadow: '0 4px 12px rgba(220, 38, 38, 0.3)'
                }}
              >
                {eradicating ? <Loader2 size={16} className="webcare-spin-icon" /> : <Trash2 size={16} />}
                {eradicating ? 'Eradicating Full Attack Chain...' : '1-Click Eradicate Entire Attack Chain'}
              </button>
            </div>
          </div>

          {/* Blast Radius & Executive Narrative Box */}
          <div style={{ padding: '24px', display: 'grid', gridTemplateColumns: 'minmax(220px, 280px) 1fr', gap: '24px', borderBottom: '1px solid #f1f5f9' }}>
            {/* Left: Blast Radius Card */}
            <div className="webcare-attack-chain-blast-box">
              <div className="webcare-attack-chain-blast-label">
                Blast Radius Exposure
              </div>
              <div style={{
                fontSize: '44px',
                fontWeight: 900,
                color: getBlastColor(selectedChain.blast_radius),
                fontFamily: 'monospace',
                margin: '8px 0',
                textShadow: `0 0 20px ${getBlastColor(selectedChain.blast_radius)}55`
              }}>
                {selectedChain.blast_radius}%
              </div>
              <div style={{
                display: 'inline-block',
                padding: '4px 10px',
                borderRadius: '999px',
                fontSize: '11px',
                fontWeight: 700,
                background: selectedChain.lateral_movement ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                color: selectedChain.lateral_movement ? '#dc2626' : '#059669',
                border: `1px solid ${selectedChain.lateral_movement ? '#fca5a5' : '#86efac'}`
              }}>
                {selectedChain.lateral_movement ? 'Lateral Movement Confirmed' : 'Contained to Local Component'}
              </div>
            </div>

            {/* Right: Chronological Incident Narrative */}
            <div className="webcare-attack-chain-narrative-box">
              <div>
                <div className="webcare-attack-chain-narrative-title">
                  <Sparkles size={16} color="#6366f1" />
                  <span>Synthesized Incident Narrative &amp; Storyline:</span>
                </div>
                <p className="webcare-attack-chain-narrative-text">
                  {selectedChain.narrative}
                </p>
              </div>

              <div style={{ marginTop: '16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px', fontSize: '12px', color: '#64748b' }}>
                <span>Stages Detected: <strong>{selectedChain.stages.length} of 5 kill-chain vectors</strong></span>
                <span style={{ color: '#0284c7', fontWeight: 600 }}>AES-256 encrypted rollback backup created automatically prior to eradication.</span>
              </div>
            </div>
          </div>

          {/* Interactive Kill-Chain Pipeline (MITRE ATT&CK Stages) */}
          <div style={{ padding: '24px' }}>
            <h4 className="webcare-attack-chain-stage-heading">
              <Layers size={18} color="#6366f1" />
              <span>Multi-Stage Attack Chain Graph (Temporal &amp; Spatial Correlation)</span>
            </h4>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {selectedChain.stages.map((stage, idx) => {
                const isExpanded = expandedStage === `${stage.stage_id}_${idx}`;
                const getIcon = () => {
                  switch (stage.stage_id) {
                    case 'initial_access': return <Zap size={18} color="#f59e0b" />;
                    case 'execution_staging': return <FileCode size={18} color="#ef4444" />;
                    case 'persistence': return <Database size={18} color="#8b5cf6" />;
                    case 'privilege_escalation': return <UserCheck size={18} color="#ec4899" />;
                    case 'c2_beacon': return <Radio size={18} color="#06b6d4" />;
                    default: return <AlertTriangle size={18} color="#64748b" />;
                  }
                };

                return (
                  <div
                    key={idx}
                    style={{
                      border: '1px solid #e2e8f0',
                      borderRadius: '10px',
                      overflow: 'hidden',
                      background: stage.status === 'breached' ? '#ffffff' : '#f8fafc',
                      borderLeft: `4px solid ${stage.status === 'breached' ? '#ef4444' : '#cbd5e1'}`
                    }}
                  >
                    <div
                      style={{
                        padding: '14px 18px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        cursor: 'pointer',
                        userSelect: 'none'
                      }}
                      onClick={() => setExpandedStage(isExpanded ? null : `${stage.stage_id}_${idx}`)}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <div style={{
                          width: '34px',
                          height: '34px',
                          borderRadius: '8px',
                          background: '#f1f5f9',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center'
                        }}>
                          {getIcon()}
                        </div>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ fontSize: '11px', fontWeight: 800, textTransform: 'uppercase', color: '#64748b' }}>
                              Stage {idx + 1}: {stage.stage_name}
                            </span>
                            <span style={{
                              fontSize: '10px',
                              fontWeight: 700,
                              padding: '1px 6px',
                              borderRadius: '4px',
                              background: stage.status === 'breached' ? '#fee2e2' : '#e2e8f0',
                              color: stage.status === 'breached' ? '#b91c1c' : '#475569'
                            }}>
                              {stage.status.toUpperCase()}
                            </span>
                          </div>
                          <div style={{ fontSize: '14px', fontWeight: 700, color: '#1e293b', marginTop: '2px' }}>
                            {stage.title}
                          </div>
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#64748b' }}>
                        {isExpanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
                      </div>
                    </div>

                    {isExpanded && (
                      <div style={{
                        padding: '14px 18px 16px 64px',
                        borderTop: '1px solid #f1f5f9',
                        background: '#fafafa',
                        fontSize: '13px',
                        color: '#475569',
                        lineHeight: 1.6
                      }}>
                        <div style={{ marginBottom: '6px' }}>
                          <strong>Technical Evidence &amp; Trace:</strong>
                        </div>
                        <div className="webcare-attack-chain-trace-box">
                          {stage.details}
                        </div>
                        <div style={{ marginTop: '8px', fontSize: '12px', color: '#64748b' }}>
                          Target Item Type: <code>{stage.item_type}</code> &bull; Identifier: <code>{stage.item_id}</code>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Expert 1-on-1 Assistance Banner (Solo Freelancer) */}
          <div className="webcare-attack-chain-expert-banner">
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div className="webcare-attack-chain-expert-icon">
                <Phone size={18} />
              </div>
              <div>
                <div className="webcare-attack-chain-expert-title">
                  Need Direct 1-on-1 Incident Response for This Attack Chain?
                </div>
                <div className="webcare-attack-chain-expert-desc">
                  Connect directly with Mir Alamin (WebCare Pro) to thoroughly audit server logs, trace root-cause intrusion vectors, and ensure zero backdoors remain.
                </div>
              </div>
            </div>

            {onNavigateToSupport && (
              <button
                type="button"
                className="webcare-btn"
                onClick={onNavigateToSupport}
                style={{
                  background: 'linear-gradient(135deg, #0284c7 0%, #2563eb 100%)',
                  color: '#ffffff',
                  border: 'none',
                  fontSize: '12px',
                  fontWeight: 700,
                  padding: '8px 16px',
                  borderRadius: '8px',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
              >
                <span>Connect With Mir Alamin Directly</span>
                <ArrowUpRight size={13} />
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
