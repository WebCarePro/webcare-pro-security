import { useState, useEffect } from '@wordpress/element';
import {
  Layers,
  Activity,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  RefreshCw,
  Terminal,
  FileCode,
  Globe,
  Radio,
  ArrowRight,
  Fingerprint,
  ChevronRight,
  ChevronDown,
  Lock,
  ExternalLink,
  Zap,
  Clock
} from 'lucide-react';

interface ThreatCorrelationHierarchyCardProps {
  apiRequest: (options: any) => Promise<any>;
  onNavigateToContainment?: () => void;
  onNavigateToEradication?: () => void;
}

export const ThreatCorrelationHierarchyCard: React.FC<ThreatCorrelationHierarchyCardProps> = ({
  apiRequest,
  onNavigateToContainment,
  onNavigateToEradication,
}) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [data, setData] = useState<any>(null);
  const [activeTier, setActiveTier] = useState<number>(4); // Default to Hypotheses
  const [expandedItems, setExpandedItems] = useState<{ [key: string]: boolean }>({});
  const [executingAction, setExecutingAction] = useState<string | null>(null);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  const fetchHierarchy = async () => {
    setLoading(true);
    setActionFeedback(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/correlation/hierarchy',
        method: 'GET',
      });
      if (res?.success) {
        setData(res);
      }
    } catch (err) {
      console.error('Failed to fetch threat correlation hierarchy:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHierarchy();
  }, []);

  const toggleExpand = (id: string) => {
    setExpandedItems(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const handleExecuteOutcome = async (outcome: any) => {
    setExecutingAction(outcome.action_id);
    setActionFeedback(null);
    try {
      const res = await apiRequest({
        path: outcome.endpoint,
        method: outcome.method || 'POST',
        data: outcome.payload || {},
      });
      if (res?.success) {
        setActionFeedback(res.message || 'Action executed successfully.');
        setTimeout(() => {
          fetchHierarchy();
          setActionFeedback(null);
        }, 2000);
      } else {
        setActionFeedback(res?.message || 'Action failed.');
      }
    } catch (err: any) {
      setActionFeedback(err?.message || 'Failed to trigger containment action.');
    } finally {
      setExecutingAction(null);
    }
  };

  const hierarchy = data?.hierarchy || {};
  const counts = data?.counts || { facts: 0, indicators: 0, correlations: 0, hypotheses: 0, outcomes: 0 };

  const tiers = [
    { num: 1, label: 'Facts', desc: 'Concrete observed events & raw signatures', count: counts.facts, icon: Terminal, color: '#64748b' },
    { num: 2, label: 'Indicators', desc: 'Contextualized threat signals', count: counts.indicators, icon: Radio, color: '#0284c7' },
    { num: 3, label: 'Correlations', desc: 'Multi-signal converging clusters', count: counts.correlations, icon: Layers, color: '#7c3aed' },
    { num: 4, label: 'Hypotheses', desc: 'Synthesized attack kill-chains', count: counts.hypotheses, icon: Activity, color: '#ea580c' },
    { num: 5, label: 'Outcomes', desc: 'Actionable containment roadmap', count: counts.outcomes, icon: Zap, color: '#10b981' },
  ];

  return (
    <div className="webcare-waf-table-card" style={{ padding: '24px' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px', marginBottom: '24px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ width: '38px', height: '38px', borderRadius: '10px', background: 'rgba(99, 102, 241, 0.14)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#6366f1' }}>
              <Layers size={22} />
            </div>
            <div>
              <h2 style={{ fontSize: '18px', fontWeight: 700, margin: 0, color: 'var(--webcare-text-title, #0f172a)' }}>
                Unified Threat Correlation & Telemetry Hierarchy
              </h2>
              <p style={{ margin: 0, fontSize: '13px', color: 'var(--webcare-text-muted, #64748b)' }}>
                Multi-engine intelligence synthesizing raw system facts into correlated attack kill-chains and atomic containment plans.
              </p>
            </div>
          </div>
        </div>

        <button
          type="button"
          className="webcare-btn webcare-btn-secondary"
          onClick={fetchHierarchy}
          disabled={loading}
          style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
        >
          <RefreshCw size={14} className={loading ? 'webcare-spin' : ''} />
          <span>{loading ? 'Correlating Signals...' : 'Refresh Telemetry'}</span>
        </button>
      </div>

      {actionFeedback && (
        <div style={{ padding: '12px 16px', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', color: '#10b981', fontSize: '13px', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <CheckCircle2 size={16} />
          <span>{actionFeedback}</span>
        </div>
      )}

      {/* 5-Tier Telemetry Flow Navigator */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px', marginBottom: '24px' }}>
        {tiers.map((t) => {
          const Icon = t.icon;
          const isActive = activeTier === t.num;
          return (
            <div
              key={t.num}
              onClick={() => setActiveTier(t.num)}
              style={{
                cursor: 'pointer',
                borderRadius: '12px',
                padding: '16px',
                background: isActive ? 'var(--webcare-bg-surface, #f8fafc)' : 'var(--webcare-bg-card, #ffffff)',
                border: isActive ? `2px solid ${t.color}` : '1px solid var(--webcare-border, #e2e8f0)',
                boxShadow: isActive ? `0 4px 14px ${t.color}25` : 'none',
                transition: 'all 0.2s ease',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                <span style={{ fontSize: '11px', fontWeight: 700, color: t.color, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Tier {t.num}
                </span>
                <span style={{ fontSize: '16px', fontWeight: 800, color: t.color }}>
                  {t.count}
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                <Icon size={16} color={t.color} />
                <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                  {t.label}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', lineHeight: 1.3 }}>
                {t.desc}
              </div>
            </div>
          );
        })}
      </div>

      {/* Tier Detail Body */}
      <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)', borderRadius: '12px', padding: '20px' }}>
        {/* TIER 4: HYPOTHESES (DEFAULT EXECUTIVE VIEW) */}
        {activeTier === 4 && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
              <Activity size={18} color="#ea580c" />
              <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Tier 4: Synthesized Attack Kill-Chain Hypotheses
              </h3>
            </div>

            {(!hierarchy.tier_4_hypotheses || hierarchy.tier_4_hypotheses.length === 0) ? (
              <p style={{ color: 'var(--webcare-text-muted, #64748b)', fontSize: '13px' }}>No active kill-chain hypotheses synthesized.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                {hierarchy.tier_4_hypotheses.map((hyp: any, idx: number) => {
                  const isCritical = hyp.severity === 'critical';
                  return (
                    <div
                      key={hyp.hypothesis_id || idx}
                      className="webcare-firewall-rule-card"
                      style={{
                        padding: '18px',
                        borderLeft: `4px solid ${isCritical ? '#dc2626' : hyp.severity === 'safe' ? '#10b981' : '#f59e0b'}`,
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '10px', marginBottom: '12px' }}>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                            <span style={{ fontSize: '15px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                              {hyp.title}
                            </span>
                            <span
                              className={`webcare-badge-pill ${
                                isCritical ? 'webcare-badge-danger' : hyp.severity === 'safe' ? 'webcare-badge-clean' : 'webcare-badge-warning'
                              }`}
                            >
                              {hyp.severity.toUpperCase()}
                            </span>
                            <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                              Confidence: <strong>{hyp.confidence}%</strong>
                            </span>
                          </div>
                        </div>

                        {hyp.blast_radius > 0 && (
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'rgba(239, 68, 68, 0.1)', padding: '4px 10px', borderRadius: '6px', border: '1px solid rgba(239, 68, 68, 0.25)' }}>
                            <AlertTriangle size={13} color="#dc2626" />
                            <span style={{ fontSize: '12px', fontWeight: 700, color: '#dc2626' }}>
                              Blast Radius Exposure: {hyp.blast_radius}%
                            </span>
                          </div>
                        )}
                      </div>

                      <p style={{ margin: '0 0 14px', fontSize: '13px', color: 'var(--webcare-text-secondary, #334155)', lineHeight: 1.5 }}>
                        {hyp.narrative}
                      </p>

                      {/* Kill Chain Pathway Nodes */}
                      {hyp.kill_chain && hyp.kill_chain.length > 0 && (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap', background: 'var(--webcare-bg-deep, #090d16)', padding: '10px 14px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)' }}>
                          <span style={{ fontSize: '11px', fontWeight: 600, color: '#94a3b8', textTransform: 'uppercase', marginRight: '4px' }}>
                            Kill Chain Path:
                          </span>
                          {hyp.kill_chain.map((stage: string, sIdx: number) => (
                            <span key={sIdx} style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                              <span style={{ fontSize: '12px', fontWeight: 600, color: '#38bdf8', background: 'rgba(56, 189, 248, 0.14)', padding: '2px 8px', borderRadius: '4px' }}>
                                {stage}
                              </span>
                              {sIdx < hyp.kill_chain.length - 1 && (
                                <ArrowRight size={12} color="#64748b" />
                              )}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* TIER 5: OUTCOMES (ACTIONABLE ROADMAP) */}
        {activeTier === 5 && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
              <Zap size={18} color="#10b981" />
              <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Tier 5: Confirmed Outcomes & Actionable Containment Roadmap
              </h3>
            </div>

            {(!hierarchy.tier_5_outcomes || hierarchy.tier_5_outcomes.length === 0) ? (
              <p style={{ color: 'var(--webcare-text-muted, #64748b)', fontSize: '13px' }}>No active containment actions required.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {hierarchy.tier_5_outcomes.map((out: any) => (
                  <div
                    key={out.action_id}
                    className="webcare-firewall-rule-card"
                    style={{ padding: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                        <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                          {out.title}
                        </span>
                        <span
                          className={`webcare-badge-pill ${
                            out.priority === 'P0_IMMEDIATE' ? 'webcare-badge-danger' : 'webcare-badge-info'
                          }`}
                        >
                          {out.priority}
                        </span>
                      </div>
                      <p style={{ margin: 0, fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                        {out.description}
                      </p>
                    </div>

                    <button
                      type="button"
                      className={`webcare-btn ${out.priority === 'P0_IMMEDIATE' ? 'webcare-btn-danger' : 'webcare-btn-primary'}`}
                      onClick={() => handleExecuteOutcome(out)}
                      disabled={executingAction === out.action_id}
                      style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                    >
                      {executingAction === out.action_id ? (
                        <>
                          <RefreshCw size={13} className="webcare-spin" />
                          <span>Executing...</span>
                        </>
                      ) : (
                        <>
                          <Zap size={13} />
                          <span>Trigger Action</span>
                        </>
                      )}
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* TIER 3: CORRELATIONS */}
        {activeTier === 3 && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
              <Layers size={18} color="#7c3aed" />
              <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Tier 3: Multi-Signal Correlation Clusters
              </h3>
            </div>

            {(!hierarchy.tier_3_correlations || hierarchy.tier_3_correlations.length === 0) ? (
              <p style={{ color: 'var(--webcare-text-muted, #64748b)', fontSize: '13px' }}>No multi-signal clusters detected yet. Signals remain isolated.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {hierarchy.tier_3_correlations.map((corr: any) => (
                  <div key={corr.correlation_id} className="webcare-firewall-rule-card" style={{ padding: '16px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                        {corr.description}
                      </span>
                      <span className="webcare-badge-pill webcare-badge-danger">
                        {corr.type} ({corr.confidence}% confidence)
                      </span>
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', fontFamily: 'monospace' }}>
                      Target Entity: {corr.entity}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* TIER 2: INDICATORS */}
        {activeTier === 2 && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
              <Radio size={18} color="#0284c7" />
              <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Tier 2: Contextualized Threat Indicators
              </h3>
            </div>

            {(!hierarchy.tier_2_indicators || hierarchy.tier_2_indicators.length === 0) ? (
              <p style={{ color: 'var(--webcare-text-muted, #64748b)', fontSize: '13px' }}>No active threat indicators found.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {hierarchy.tier_2_indicators.map((ind: any) => (
                  <div key={ind.indicator_id} className="webcare-firewall-rule-card" style={{ padding: '14px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                      <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                        {ind.summary}
                      </span>
                      <span className="webcare-badge-pill webcare-badge-warning">
                        {ind.category}
                      </span>
                    </div>
                    <div style={{ display: 'flex', gap: '12px', fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                      <span>Target: <code style={{ color: '#0284c7' }}>{ind.target || '/'}</code></span>
                      {ind.client_ip && <span>IP: <code>{ind.client_ip}</code></span>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* TIER 1: FACTS */}
        {activeTier === 1 && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
              <Terminal size={18} color="#64748b" />
              <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Tier 1: Concrete Observed Facts (Raw Telemetry)
              </h3>
            </div>

            {(!hierarchy.tier_1_facts || hierarchy.tier_1_facts.length === 0) ? (
              <p style={{ color: 'var(--webcare-text-muted, #64748b)', fontSize: '13px' }}>No raw adverse telemetry facts recorded.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {hierarchy.tier_1_facts.map((fact: any) => {
                  const isExpanded = !!expandedItems[fact.fact_id];
                  return (
                    <div key={fact.fact_id} className="webcare-firewall-rule-card" style={{ padding: '14px' }}>
                      <div
                        onClick={() => toggleExpand(fact.fact_id)}
                        style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                          <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)' }}>
                            [{fact.source.toUpperCase()}] {fact.detail}
                          </span>
                        </div>
                        <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                          {new Date(fact.timestamp * 1000).toLocaleTimeString()}
                        </span>
                      </div>

                      {isExpanded && fact.evidence && (
                        <div style={{ marginTop: '10px', paddingTop: '10px', borderTop: '1px solid var(--webcare-border, #e2e8f0)' }}>
                          <pre style={{ background: '#090d16', color: '#38bdf8', padding: '10px', borderRadius: '6px', fontSize: '11px', margin: 0, overflowX: 'auto', fontFamily: 'monospace' }}>
                            {fact.evidence}
                          </pre>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatCorrelationHierarchyCard;
