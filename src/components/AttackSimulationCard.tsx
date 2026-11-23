import { useState, useEffect } from '@wordpress/element';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Gauge,
  ChevronRight,
  Info,
  Layers,
  Terminal,
} from 'lucide-react';

interface AttackSimulationCardProps {
  apiRequest: (options: any) => Promise<any>;
}

export const AttackSimulationCard = ({ apiRequest }: AttackSimulationCardProps) => {
  const [report, setReport] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [running, setRunning] = useState<boolean>(false);
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [expandedVector, setExpandedVector] = useState<string | null>(null);

  const fetchLatestReport = async () => {
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/security/drill-results',
        method: 'GET',
      });
      if (res?.success && res.report) {
        setReport(res.report);
      }
    } catch (err) {
      console.error('Failed to fetch drill results:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLatestReport();
  }, []);

  const handleRunDrill = async () => {
    setRunning(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/security/run-drill',
        method: 'POST',
      });
      if (res?.success && res.report) {
        setReport(res.report);
      }
    } catch (err) {
      console.error('Failed to run attack simulation drill:', err);
    } finally {
      setRunning(false);
    }
  };

  const vectors = report?.vectors || [];
  const filteredVectors = filterCategory === 'all'
    ? vectors
    : vectors.filter((v: any) => v.category === filterCategory);

  const categories = Array.from(new Set(vectors.map((v: any) => v.category))) as string[];

  const getGradeBadgeStyle = (grade: string) => {
    switch (grade) {
      case 'A+':
      case 'A':
        return { background: 'rgba(16, 185, 129, 0.16)', color: '#10b981', border: '1px solid rgba(16, 185, 129, 0.4)' };
      case 'B':
        return { background: 'rgba(217, 119, 6, 0.16)', color: '#d97706', border: '1px solid rgba(217, 119, 6, 0.4)' };
      case 'C':
        return { background: 'rgba(234, 88, 12, 0.16)', color: '#ea580c', border: '1px solid rgba(234, 88, 12, 0.4)' };
      default:
        return { background: 'rgba(220, 38, 38, 0.16)', color: '#dc2626', border: '1px solid rgba(220, 38, 38, 0.4)' };
    }
  };

  return (
    <div
      className="webcare-waf-table-card"
      style={{
        padding: '24px',
        borderRadius: '16px',
        backgroundColor: 'var(--webcare-bg-panel, #ffffff)',
        border: '1px solid var(--webcare-border, #e2e8f0)',
        boxShadow: '0 4px 20px -2px rgba(0,0,0,0.05)',
      }}
    >
      {/* 1. Header Section */}
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
          marginBottom: '22px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div
            style={{
              width: '46px',
              height: '46px',
              borderRadius: '12px',
              background: 'linear-gradient(135deg, rgba(79, 70, 229, 0.15) 0%, rgba(99, 102, 241, 0.08) 100%)',
              border: '1px solid rgba(99, 102, 241, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}
          >
            <Zap size={24} color="#4f46e5" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <h2
                style={{
                  margin: 0,
                  fontSize: '18px',
                  fontWeight: 800,
                  color: 'var(--webcare-text-title, var(--webcare-text-primary, #0f172a))',
                  letterSpacing: '-0.02em',
                }}
              >
                Safe Attack Simulation Drill
              </h2>
              <span
                style={{
                  padding: '2px 8px',
                  borderRadius: '6px',
                  fontSize: '11px',
                  fontWeight: 700,
                  background: 'rgba(99, 102, 241, 0.1)',
                  color: '#4f46e5',
                  border: '1px solid rgba(99, 102, 241, 0.25)',
                }}
              >
                Red Team Lite
              </span>
            </div>
            <p
              style={{
                margin: '4px 0 0 0',
                fontSize: '13px',
                color: 'var(--webcare-text-secondary, #475569)',
                lineHeight: 1.5,
              }}
            >
              Dispatches safe, token-authenticated synthetic attack vectors (SQLi, LFI, XSS, Recon, AI Prompt-Injection) directly against your origin WAF to empirically measure defensibility.
            </p>
          </div>
        </div>

        <button
          onClick={handleRunDrill}
          disabled={running}
          style={{
            background: 'linear-gradient(135deg, #4f46e5 0%, #4338ca 100%)',
            color: '#ffffff',
            border: 'none',
            padding: '10px 20px',
            borderRadius: '10px',
            fontSize: '13px',
            fontWeight: 700,
            cursor: running ? 'not-allowed' : 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            boxShadow: '0 4px 14px rgba(79, 70, 229, 0.3)',
            transition: 'all 0.15s ease',
          }}
        >
          <RefreshCw size={16} className={running ? 'webcare-spin' : ''} />
          {running ? 'Running Simulation...' : 'Launch Security Drill'}
        </button>
      </div>

      {/* 2. Key Defensibility Metrics (If Report Exists) */}
      {report && (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '14px',
            marginBottom: '24px',
          }}
        >
          {/* Score & Grade */}
          <div
            style={{
              padding: '16px 20px',
              borderRadius: '12px',
              background: 'var(--webcare-bg-surface, #f8fafc)',
              border: '1px solid var(--webcare-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                WAF Defensibility
              </div>
              <div style={{ fontSize: '24px', fontWeight: 800, color: 'var(--webcare-text-title, var(--webcare-text-primary, #0f172a))', marginTop: '2px' }}>
                {report.score}%
              </div>
            </div>
            <div
              style={{
                width: '42px',
                height: '42px',
                borderRadius: '10px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '18px',
                fontWeight: 800,
                ...getGradeBadgeStyle(report.grade),
              }}
            >
              {report.grade}
            </div>
          </div>

          {/* Intercept Ratio */}
          <div
            style={{
              padding: '16px 20px',
              borderRadius: '12px',
              background: 'var(--webcare-bg-surface, #f8fafc)',
              border: '1px solid var(--webcare-border, #e2e8f0)',
            }}
          >
            <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Interception Ratio
            </div>
            <div style={{ fontSize: '20px', fontWeight: 800, color: '#10b981', marginTop: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <ShieldCheck size={20} />
              <span>{report.intercepted_count} / {report.total_vectors} Shielded</span>
            </div>
          </div>

          {/* Average Latency */}
          <div
            style={{
              padding: '16px 20px',
              borderRadius: '12px',
              background: 'var(--webcare-bg-surface, #f8fafc)',
              border: '1px solid var(--webcare-border, #e2e8f0)',
            }}
          >
            <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Avg Interception Latency
            </div>
            <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--webcare-text-title, var(--webcare-text-primary, #0f172a))', marginTop: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Clock size={18} color="#0284c7" />
              <span>{report.avg_latency_ms} ms</span>
            </div>
          </div>

          {/* Execution Time */}
          <div
            style={{
              padding: '16px 20px',
              borderRadius: '12px',
              background: 'var(--webcare-bg-surface, #f8fafc)',
              border: '1px solid var(--webcare-border, #e2e8f0)',
            }}
          >
            <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Last Drill Run
            </div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, var(--webcare-text-primary, #0f172a))', marginTop: '6px' }}>
              {new Date(report.executed_at * 1000).toLocaleTimeString()} ({new Date(report.executed_at * 1000).toLocaleDateString()})
            </div>
          </div>
        </div>
      )}

      {/* 3. Category Filter Pills */}
      {categories.length > 0 && (
        <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', flexWrap: 'wrap' }}>
          <button
            onClick={() => setFilterCategory('all')}
            className="webcare-btn-micro"
            style={{
              background: filterCategory === 'all' ? '#4f46e5' : 'var(--webcare-bg-surface, #f8fafc)',
              color: filterCategory === 'all' ? '#ffffff' : 'var(--webcare-text-secondary, #475569)',
              border: '1px solid var(--webcare-border, #e2e8f0)',
              borderRadius: '6px',
              padding: '4px 10px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            All Vectors ({vectors.length})
          </button>
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setFilterCategory(cat)}
              className="webcare-btn-micro"
              style={{
                background: filterCategory === cat ? '#4f46e5' : 'var(--webcare-bg-surface, #f8fafc)',
                color: filterCategory === cat ? '#ffffff' : 'var(--webcare-text-secondary, #475569)',
                border: '1px solid var(--webcare-border, #e2e8f0)',
                borderRadius: '6px',
                padding: '4px 10px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              {cat}
            </button>
          ))}
        </div>
      )}

      {/* 4. Vectors Interactive Table */}
      {filteredVectors.length > 0 ? (
        <div style={{ overflowX: 'auto', border: '1px solid var(--webcare-border, #e2e8f0)', borderRadius: '12px' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
            <thead>
              <tr style={{ background: 'var(--webcare-bg-surface, #f8fafc)', borderBottom: '1px solid var(--webcare-border, #e2e8f0)' }}>
                <th style={{ padding: '12px 16px', fontWeight: 700, color: 'var(--webcare-text-secondary, #475569)' }}>Vector Name & Category</th>
                <th style={{ padding: '12px 16px', fontWeight: 700, color: 'var(--webcare-text-secondary, #475569)' }}>Status</th>
                <th style={{ padding: '12px 16px', fontWeight: 700, color: 'var(--webcare-text-secondary, #475569)' }}>Rule Triggered</th>
                <th style={{ padding: '12px 16px', fontWeight: 700, color: 'var(--webcare-text-secondary, #475569)' }}>Latency</th>
                <th style={{ padding: '12px 16px', fontWeight: 700, color: 'var(--webcare-text-secondary, #475569)', textAlign: 'right' }}>Details</th>
              </tr>
            </thead>
            <tbody>
              {filteredVectors.map((v: any) => {
                const isExpanded = expandedVector === v.id;
                return (
                  <>
                    <tr
                      key={v.id}
                      style={{
                        borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
                        backgroundColor: 'var(--webcare-bg-panel, #ffffff)',
                        cursor: 'pointer',
                      }}
                      onClick={() => setExpandedVector(isExpanded ? null : v.id)}
                    >
                      <td style={{ padding: '14px 16px' }}>
                        <div style={{ fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                          {v.name}
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
                          {v.category}
                        </div>
                      </td>

                      <td style={{ padding: '14px 16px' }}>
                        {v.intercepted ? (
                          <span
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '5px',
                              padding: '3px 8px',
                              borderRadius: '6px',
                              fontSize: '11px',
                              fontWeight: 700,
                              background: 'rgba(16, 185, 129, 0.12)',
                              color: '#059669',
                              border: '1px solid rgba(16, 185, 129, 0.3)',
                            }}
                          >
                            <CheckCircle2 size={12} />
                            Shielded (Blocked)
                          </span>
                        ) : (
                          <span
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '5px',
                              padding: '3px 8px',
                              borderRadius: '6px',
                              fontSize: '11px',
                              fontWeight: 700,
                              background: 'rgba(239, 68, 68, 0.12)',
                              color: '#dc2626',
                              border: '1px solid rgba(239, 68, 68, 0.3)',
                            }}
                          >
                            <XCircle size={12} />
                            Bypassed (Open)
                          </span>
                        )}
                      </td>

                      <td style={{ padding: '14px 16px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                        <code style={{ fontSize: '11px', color: '#0284c7' }}>
                          {v.rule_id || 'N/A'}
                        </code>
                        <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginLeft: '6px' }}>
                          (HTTP {v.status_code})
                        </span>
                      </td>

                      <td style={{ padding: '14px 16px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                        {v.latency_ms} ms
                      </td>

                      <td style={{ padding: '14px 16px', textAlign: 'right' }}>
                        <span style={{ fontSize: '12px', color: '#4f46e5', fontWeight: 600 }}>
                          {isExpanded ? 'Hide Forensics' : 'Inspect'}
                        </span>
                      </td>
                    </tr>

                    {/* Expandable Forensic Drawer */}
                    {isExpanded && (
                      <tr className="webcare-waf-expanded-row" key={`${v.id}-drawer`}>
                        <td colSpan={5} style={{ padding: '16px 20px', background: 'var(--webcare-bg-surface, #f8fafc)', borderBottom: '1px solid var(--webcare-border, #e2e8f0)' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                            <div>
                              <strong style={{ fontSize: '12px', color: 'var(--webcare-text-primary, #0f172a)' }}>Simulation Mechanics:</strong>
                              <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>{v.description}</p>
                            </div>
                            <div>
                              <strong style={{ fontSize: '12px', color: '#dc2626' }}>Security Impact If Unshielded:</strong>
                              <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>{v.risk_if_open}</p>
                            </div>
                            <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                              Diagnostics: {v.details}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div
          style={{
            padding: '40px 20px',
            textAlign: 'center',
            background: 'var(--webcare-bg-surface, #f8fafc)',
            borderRadius: '12px',
            border: '1px dashed var(--webcare-border, #cbd5e1)',
          }}
        >
          <Zap size={32} color="#94a3b8" style={{ margin: '0 auto 10px' }} />
          <h4 style={{ margin: 0, fontSize: '15px', color: 'var(--webcare-text-title, var(--webcare-text-primary, #0f172a))' }}>
            No Security Drill Executed Yet
          </h4>
          <p style={{ margin: '4px 0 16px 0', fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)' }}>
            Launch a safe Red Team drill above to empirically test and score your origin WAF against synthetic attack probes.
          </p>
          <button
            onClick={handleRunDrill}
            disabled={running}
            className="webcare-btn-primary"
            style={{ padding: '8px 18px', borderRadius: '8px', fontSize: '13px', fontWeight: 600 }}
          >
            Run Initial Drill
          </button>
        </div>
      )}

      {/* Footnote */}
      <div style={{ marginTop: '16px', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
        <Info size={14} color="#64748b" />
        <span>
          Drill probes carry an ephemeral 120s HMAC token (<code>X-WEBCARE-Drill-Token</code>). Probes test live regexes and filters without auto-banning the server loopback IP.
        </span>
      </div>
    </div>
  );
};
