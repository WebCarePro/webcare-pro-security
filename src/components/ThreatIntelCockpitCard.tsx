import { useState, useEffect } from '@wordpress/element';
import {
  Globe,
  Shield,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Search,
  Activity,
  Layers,
  Database,
  Lock,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  Info,
  Server,
  Zap,
  Loader2,
  Clock,
  Sparkles,
  Flame,
  Radio
} from 'lucide-react';

interface ThreatFeed {
  id: string;
  name: string;
  provider: string;
  url: string;
  description: string;
  type: string;
  weight: number;
  limit: number;
}

interface ConsensusBeacon {
  beacon_id: string;
  beacon_hash: string;
  masked_subnet: string;
  attack_vector: string;
  category: string;
  timestamp: number;
  formatted_time: string;
}

interface TopSubnet {
  rank: number;
  subnet: string;
  count: number;
}

interface ReputationFactor {
  factor: string;
  weight: string;
  description: string;
  severity: string;
}

interface ReputationAssessment {
  ip: string;
  reputation_score: number;
  risk_tier: 'clean' | 'suspicious' | 'high' | 'critical';
  risk_label: string;
  is_blacklisted: boolean;
  is_tor_node: boolean;
  honeytoken_hit: boolean;
  lockout_hit: boolean;
  factors: ReputationFactor[];
  recommendation: 'allow' | 'monitor' | 'rate_limit' | 'block' | 'edge_block';
  assessed_at: string;
}

interface ThreatIntelTelemetry {
  network_enabled: boolean;
  drop_threats_enabled: boolean;
  last_sync: string;
  total_active_ips: number;
  tor_exit_nodes_count: number;
  consensus_beacons: ConsensusBeacon[];
  total_beacons_logged: number;
  top_attacking_subnets: TopSubnet[];
  feeds: Record<string, ThreatFeed>;
  recent_checks: ReputationAssessment[];
}

interface ThreatIntelCockpitCardProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  clientIp?: string;
}

export const ThreatIntelCockpitCard = ({ apiRequest, clientIp }: ThreatIntelCockpitCardProps) => {
  const [telemetry, setTelemetry] = useState<ThreatIntelTelemetry | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [syncing, setSyncing] = useState<boolean>(false);
  const [syncFeedback, setSyncFeedback] = useState<string | null>(null);

  // Reputation Scorer State
  const [checkIpInput, setCheckIpInput] = useState<string>('');
  const [assessing, setAssessing] = useState<boolean>(false);
  const [currentAssessment, setCurrentAssessment] = useState<ReputationAssessment | null>(null);
  const [scoreError, setScoreError] = useState<string | null>(null);

  const fetchTelemetry = async () => {
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/threat-intel/network',
        method: 'GET',
      });
      if (res && res.success && res.telemetry) {
        setTelemetry(res.telemetry);
      }
    } catch {
      // Graceful fallback
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTelemetry();
  }, []);

  const handleSyncFeeds = async () => {
    setSyncing(true);
    setSyncFeedback(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/threat-intel/sync',
        method: 'POST',
      });
      if (res && res.success) {
        setSyncFeedback(res.message || 'Threat intelligence network synchronized successfully.');
        if (res.telemetry) {
          setTelemetry(res.telemetry);
        } else {
          await fetchTelemetry();
        }
      }
    } catch (err: any) {
      setSyncFeedback(err?.message || 'Error communicating with external threat feeds.');
    } finally {
      setSyncing(false);
    }
  };

  const handleCheckReputation = async (targetIp?: string) => {
    const ipToCheck = (targetIp || checkIpInput || clientIp || '127.0.0.1').trim();
    if (!ipToCheck) return;

    setAssessing(true);
    setScoreError(null);
    try {
      const res = await apiRequest({
        path: `/webcare-pro-security/v1/threat-intel/reputation-check?ip=${encodeURIComponent(ipToCheck)}`,
        method: 'GET',
      });
      if (res && res.success && res.assessment) {
        setCurrentAssessment(res.assessment);
        // Refresh telemetry to show recent checks
        fetchTelemetry();
      } else {
        setScoreError('Failed to retrieve reputation score.');
      }
    } catch (err: any) {
      setScoreError(err?.message || 'Network error evaluating IP reputation.');
    } finally {
      setAssessing(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Hero Banner */}
      <div
        className="webcare-dark-hero"
        style={{
          background: 'linear-gradient(135deg, #090d16 0%, #0369a1 100%)',
          border: '1px solid rgba(2, 132, 199, 0.4)',
          borderRadius: '14px',
          padding: '24px',
          color: '#ffffff',
          position: 'relative',
          boxShadow: '0 8px 24px rgba(15, 23, 42, 0.3)'
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(56, 189, 248, 0.25)',
              border: '1px solid rgba(56, 189, 248, 0.45)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#38bdf8',
              boxShadow: '0 0 20px rgba(56, 189, 248, 0.3)'
            }}>
              <Globe size={26} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <h2 style={{ margin: 0, fontSize: '20px', fontWeight: 800, color: '#ffffff' }}>
                  Decentralized Threat Intelligence Network &amp; Reputation Scorer
                </h2>
                <span style={{
                  fontSize: '11px',
                  fontWeight: 800,
                  textTransform: 'uppercase',
                  padding: '3px 10px',
                  borderRadius: '999px',
                  background: 'rgba(56, 189, 248, 0.2)',
                  color: '#bae6fd',
                  border: '1px solid rgba(56, 189, 248, 0.35)'
                }}>
                  Pillar 5 &bull; Multi-Feed Intelligence
                </span>
              </div>
              <p style={{ margin: '6px 0 0 0', fontSize: '13px', color: '#e0f2fe', maxWidth: '780px' }}>
                Continuous real-time aggregation across 4 global community feeds (Ipsum L1/L2, Blocklist.de, Tor Exits). Scores incoming traffic with a 0–100% multi-dimensional reputation engine and broadcasts privacy-preserving consensus attack telemetry.
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              type="button"
              className="webcare-btn"
              onClick={handleSyncFeeds}
              disabled={syncing}
              style={{
                background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
                color: '#ffffff',
                border: 'none',
                padding: '9px 18px',
                fontSize: '13px',
                fontWeight: 700,
                borderRadius: '8px',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                cursor: syncing ? 'not-allowed' : 'pointer',
                boxShadow: '0 2px 10px rgba(2, 132, 199, 0.4)'
              }}
            >
              <RefreshCw size={15} className={syncing ? 'webcare-spin-icon' : ''} />
              <span>{syncing ? 'Synchronizing Feeds...' : 'Sync Threat Feeds Now'}</span>
            </button>
          </div>
        </div>

        {/* 4 Summary KPI Tiles */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '14px',
          marginTop: '22px',
          paddingTop: '20px',
          borderTop: '1px solid rgba(255, 255, 255, 0.1)'
        }}>
          <div style={{ background: 'rgba(255, 255, 255, 0.05)', padding: '12px 16px', borderRadius: '10px', border: '1px solid rgba(255, 255, 255, 0.1)' }}>
            <div style={{ fontSize: '11px', color: '#bae6fd', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Database size={13} color="#38bdf8" /> Active Threat IP Pool
            </div>
            <div style={{ fontSize: '22px', fontWeight: 900, color: '#f8fafc', marginTop: '4px', fontFamily: 'monospace' }}>
              {telemetry?.total_active_ips ? telemetry.total_active_ips.toLocaleString() : 'Loading...'}
            </div>
            <span style={{ fontSize: '11px', color: '#94a3b8' }}>Ingested across 4 feeds</span>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.05)', padding: '12px 16px', borderRadius: '10px', border: '1px solid rgba(255, 255, 255, 0.1)' }}>
            <div style={{ fontSize: '11px', color: '#bae6fd', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Radio size={13} color="#fbbf24" /> Tor Exit Relays Tracked
            </div>
            <div style={{ fontSize: '22px', fontWeight: 900, color: '#fbbf24', marginTop: '4px', fontFamily: 'monospace' }}>
              {telemetry?.tor_exit_nodes_count ? telemetry.tor_exit_nodes_count.toLocaleString() : '0'}
            </div>
            <span style={{ fontSize: '11px', color: '#94a3b8' }}>Tor Project registry</span>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.05)', padding: '12px 16px', borderRadius: '10px', border: '1px solid rgba(255, 255, 255, 0.1)' }}>
            <div style={{ fontSize: '11px', color: '#bae6fd', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Activity size={13} color="#34d399" /> Consensus Beacons
            </div>
            <div style={{ fontSize: '22px', fontWeight: 900, color: '#f8fafc', marginTop: '4px', fontFamily: 'monospace' }}>
              {telemetry?.total_beacons_logged ?? 0}
            </div>
            <span style={{ fontSize: '11px', color: '#94a3b8' }}>Anonymous attack vectors</span>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.05)', padding: '12px 16px', borderRadius: '10px', border: '1px solid rgba(255, 255, 255, 0.1)' }}>
            <div style={{ fontSize: '11px', color: '#bae6fd', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <ShieldCheck size={13} color="#a78bfa" /> Threat Shield Mode
            </div>
            <div style={{ fontSize: '15px', fontWeight: 800, color: telemetry?.drop_threats_enabled ? '#34d399' : '#fb923c', marginTop: '6px' }}>
              {telemetry?.drop_threats_enabled ? 'Active Zero-Tolerance Drop' : 'Monitoring Only'}
            </div>
            <span style={{ fontSize: '11px', color: '#94a3b8' }}>Last sync: {telemetry?.last_sync || 'Today'}</span>
          </div>
        </div>
      </div>

      {/* Sync Feedback Alert */}
      {syncFeedback && (
        <div style={{
          padding: '12px 18px',
          borderRadius: '10px',
          background: '#ecfdf5',
          border: '1px solid #a7f3d0',
          color: '#065f46',
          fontSize: '13px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          fontWeight: 600
        }}>
          <CheckCircle2 size={16} />
          <span>{syncFeedback}</span>
        </div>
      )}

      {/* SECTION 1: Multi-Factor IP Reputation Diagnostic Scorer */}
      <div className="webcare-firewall-card" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px', marginBottom: '18px' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Search size={18} color="#0284c7" /> Live Multi-Factor IP Reputation Diagnostic Scorer
            </h3>
            <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)' }}>
              Assess any IP address in real time against community threat lists (+60), Tor exit relays (+25), Honey-Token decoy violations (+40), and brute-force lockouts (+30).
            </p>
          </div>

          {clientIp && (
            <button
              type="button"
              className="webcare-btn webcare-action-btn-clean"
              style={{ fontSize: '12px', padding: '5px 12px' }}
              onClick={() => {
                setCheckIpInput(clientIp);
                handleCheckReputation(clientIp);
              }}
            >
              Score My IP ({clientIp})
            </button>
          )}
        </div>

        {/* Input Bar */}
        <div style={{ display: 'flex', gap: '10px', maxWidth: '640px', flexWrap: 'wrap' }}>
          <input
            type="text"
            className="webcare-input"
            placeholder="Enter IPv4 or IPv6 (e.g. 185.220.101.5 or 198.51.100.4)"
            value={checkIpInput}
            onChange={(e) => setCheckIpInput(e.target.value)}
            style={{ flex: 1, minWidth: '260px', fontFamily: 'monospace' }}
          />
          <button
            type="button"
            className="webcare-btn"
            onClick={() => handleCheckReputation()}
            disabled={assessing || !checkIpInput.trim()}
            style={{
              background: '#0284c7',
              color: '#ffffff',
              border: 'none',
              padding: '8px 18px',
              fontSize: '13px',
              fontWeight: 700,
              borderRadius: '6px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            {assessing ? <Loader2 size={14} className="webcare-spin-icon" /> : <Zap size={14} />}
            <span>Calculate Reputation</span>
          </button>
        </div>

        {scoreError && (
          <div style={{ marginTop: '12px', color: '#dc2626', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <AlertTriangle size={15} />
            <span>{scoreError}</span>
          </div>
        )}

        {/* Assessment Result Card */}
        {currentAssessment && (
          <div
            className="webcare-firewall-callout"
            style={{
              marginTop: '20px',
              padding: '18px 22px',
              borderRadius: '10px',
              border: currentAssessment.risk_tier === 'critical'
                ? '1px solid #fca5a5'
                : currentAssessment.risk_tier === 'high'
                ? '1px solid #fed7aa'
                : currentAssessment.risk_tier === 'suspicious'
                ? '1px solid #fde68a'
                : '1px solid #a7f3d0'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span style={{ fontSize: '15px', fontWeight: 800, fontFamily: 'monospace' }}>
                  IP: {currentAssessment.ip}
                </span>

                <span
                  className={
                    currentAssessment.risk_tier === 'critical'
                      ? 'webcare-badge-pill webcare-badge-danger'
                      : currentAssessment.risk_tier === 'high'
                      ? 'webcare-badge-pill webcare-badge-warning'
                      : currentAssessment.risk_tier === 'suspicious'
                      ? 'webcare-badge-pill webcare-badge-info'
                      : 'webcare-badge-pill webcare-badge-clean'
                  }
                  style={{ textTransform: 'uppercase', fontWeight: 800 }}
                >
                  {currentAssessment.risk_label}
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>Recommended Action:</span>
                <span style={{
                  fontSize: '11px',
                  fontWeight: 800,
                  padding: '3px 10px',
                  borderRadius: '6px',
                  background: currentAssessment.recommendation === 'edge_block' || currentAssessment.recommendation === 'block' ? '#fee2e2' : '#f0fdf4',
                  color: currentAssessment.recommendation === 'edge_block' || currentAssessment.recommendation === 'block' ? '#991b1b' : '#166534',
                  textTransform: 'uppercase'
                }}>
                  {currentAssessment.recommendation.replace('_', ' ')}
                </span>
              </div>
            </div>

            {/* Score Meter Bar */}
            <div style={{ marginBottom: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', fontWeight: 700, marginBottom: '6px' }}>
                <span>Multi-Factor Threat Score</span>
                <span style={{
                  color: currentAssessment.reputation_score >= 75 ? '#dc2626' : currentAssessment.reputation_score >= 50 ? '#ea580c' : currentAssessment.reputation_score >= 25 ? '#d97706' : '#10b981'
                }}>
                  {currentAssessment.reputation_score}% / 100%
                </span>
              </div>
              <div style={{ height: '8px', background: 'var(--webcare-bg-deep, #e2e8f0)', borderRadius: '999px', overflow: 'hidden' }}>
                <div
                  style={{
                    height: '100%',
                    width: `${currentAssessment.reputation_score}%`,
                    background: currentAssessment.reputation_score >= 75
                      ? 'linear-gradient(90deg, #ea580c 0%, #dc2626 100%)'
                      : currentAssessment.reputation_score >= 50
                      ? 'linear-gradient(90deg, #f59e0b 0%, #ea580c 100%)'
                      : currentAssessment.reputation_score >= 25
                      ? '#d97706'
                      : '#10b981',
                    borderRadius: '999px',
                    transition: 'width 0.4s ease'
                  }}
                />
              </div>
            </div>

            {/* Factor Breakdown */}
            <div>
              <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '8px' }}>
                Evaluation Breakdown &amp; Evidence:
              </div>
              {currentAssessment.factors.length === 0 ? (
                <div style={{ fontSize: '12.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  ✓ Clean baseline: No matches found across threat feeds, Tor registries, or local honey-token traps.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {currentAssessment.factors.map((f, i) => (
                    <div
                      key={i}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '6px 10px',
                        background: 'var(--webcare-bg-surface, rgba(0,0,0,0.02))',
                        borderRadius: '6px',
                        fontSize: '12px'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontWeight: 700 }}>{f.factor}</span>
                        <span style={{ color: 'var(--webcare-text-muted, #64748b)' }}>— {f.description}</span>
                      </div>
                      <span style={{
                        fontWeight: 800,
                        color: f.weight === 'Override' ? '#16a34a' : '#dc2626',
                        fontFamily: 'monospace'
                      }}>
                        {f.weight}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* SECTION 2: Attack Consensus Hash Ring & Top Subnets */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '20px' }}>
        {/* Consensus Ring */}
        <div className="webcare-firewall-card" style={{ padding: '22px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
            <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Activity size={16} color="#7c3aed" /> Attack Consensus Hash Ring
            </h4>
            <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
              Privacy-Preserving SHA-256
            </span>
          </div>

          <p style={{ margin: '0 0 14px 0', fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.45 }}>
            Anonymized telemetry hashed via <code style={{ color: '#7c3aed' }}>sha256(subnet + vector)</code>. Telemetry tracks botnet velocity without exposing your site URL or client data.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '280px', overflowY: 'auto' }}>
            {(!telemetry?.consensus_beacons || telemetry.consensus_beacons.length === 0) ? (
              <div style={{ padding: '20px', textAlign: 'center', color: 'var(--webcare-text-muted, #64748b)', fontSize: '12.5px' }}>
                No attack consensus beacons recorded yet. Beacons are automatically emitted when WAF drops exploits.
              </div>
            ) : (
              telemetry.consensus_beacons.map((b) => (
                <div
                  key={b.beacon_id}
                  className="webcare-firewall-rule-card"
                  style={{
                    padding: '8px 12px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                    fontSize: '11.5px'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <strong style={{ color: '#7c3aed' }}>{b.beacon_id}</strong>
                    <span style={{ color: 'var(--webcare-text-muted, #64748b)', fontSize: '10.5px' }}>{b.formatted_time}</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
                    <span style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>{b.attack_vector}</span>
                    <code style={{ fontSize: '10.5px', color: '#0284c7' }}>{b.masked_subnet}</code>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Top Attacking Subnets */}
        <div className="webcare-firewall-card" style={{ padding: '22px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
            <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Flame size={16} color="#ea580c" /> Top Attacking Recon Subnets
            </h4>
            <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
              Correlated Subnet Density
            </span>
          </div>

          <p style={{ margin: '0 0 14px 0', fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.45 }}>
            Subnets displaying repeated exploit probes, credential bruteforcing, or automated honey-token violations.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {(!telemetry?.top_attacking_subnets || telemetry.top_attacking_subnets.length === 0) ? (
              <div style={{ padding: '20px', textAlign: 'center', color: 'var(--webcare-text-muted, #64748b)', fontSize: '12.5px' }}>
                ✓ Clean subnet telemetry: No high-density attacking subnets detected in recent activity.
              </div>
            ) : (
              telemetry.top_attacking_subnets.map((sub) => (
                <div
                  key={sub.subnet}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '10px 14px',
                    background: 'var(--webcare-bg-surface, rgba(0,0,0,0.02))',
                    borderRadius: '8px',
                    border: '1px solid var(--webcare-border, #e2e8f0)'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span style={{
                      width: '22px',
                      height: '22px',
                      borderRadius: '50%',
                      background: '#ea580c',
                      color: '#ffffff',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '11px',
                      fontWeight: 800
                    }}>
                      {sub.rank}
                    </span>
                    <code style={{ fontSize: '12.5px', fontWeight: 700, color: '#0284c7' }}>
                      {sub.subnet}
                    </code>
                  </div>

                  <span style={{ fontSize: '12px', fontWeight: 700, color: '#dc2626' }}>
                    {sub.count} Probes Intercepted
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* SECTION 3: Community Threat Intelligence Feeds Registry */}
      <div className="webcare-firewall-card" style={{ padding: '22px' }}>
        <h4 style={{ margin: '0 0 14px 0', fontSize: '15px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Layers size={16} color="#0284c7" /> Active Community Threat Feeds Registry
        </h4>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px' }}>
          {telemetry?.feeds && Object.entries(telemetry.feeds).map(([key, feed]) => (
            <div
              key={key}
              className="webcare-firewall-rule-card"
              style={{
                padding: '14px 16px',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px',
                border: '1px solid var(--webcare-border, #e2e8f0)'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '6px' }}>
                <strong style={{ fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                  {feed.name}
                </strong>
                <span className="webcare-smart-shield-pill-detected-emerald" style={{ fontSize: '10px' }}>
                  ACTIVE
                </span>
              </div>

              <div style={{ fontSize: '11px', color: '#0284c7', fontWeight: 600 }}>
                Provider: {feed.provider}
              </div>

              <p style={{ margin: 0, fontSize: '11.5px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.4 }}>
                {feed.description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
