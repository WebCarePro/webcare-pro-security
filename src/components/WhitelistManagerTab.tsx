import React, { useState, useEffect } from 'react';
import { ShieldCheck, RefreshCw, CheckCircle2, AlertTriangle, Trash2, Key, FileCode, Clock } from 'lucide-react';
import { showConfirm } from '../utils/dialog';

interface WhitelistRule {
  id: string;
  rule_type: 'file_hash' | 'file_path' | 'issue_type';
  target_path: string;
  file_hash: string;
  issue_type: string;
  engine: string;
  duration: string;
  reason: string;
  created_by: string;
  created_at: string;
  expires_at: number | null;
  status: 'active' | 'expired' | 'revoked';
}

interface WhitelistManagerTabProps {
  apiRequest: (options: any) => Promise<any>;
  onRefreshFindings?: () => void;
}

export const WhitelistManagerTab: React.FC<WhitelistManagerTabProps> = ({
  apiRequest,
  onRefreshFindings,
}) => {
  const [rules, setRules] = useState<WhitelistRule[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [filter, setFilter] = useState<'all' | 'active' | 'expired'>('active');
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const fetchRules = async () => {
    setLoading(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/whitelist/rules',
        method: 'GET',
      });
      if (res?.success && Array.isArray(res?.rules)) {
        setRules(res.rules);
      }
    } catch (err) {
      console.error('Failed to fetch whitelist rules:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleRevoke = async (ruleId: string) => {
    const confirmed = await showConfirm({
      title: 'Revoke Whitelist Rule',
      message: 'Are you sure you want to revoke this whitelist rule? This finding will immediately be re-flagged on subsequent scans.',
      confirmLabel: 'Revoke Rule',
      variant: 'warning',
    });
    if (!confirmed) {
      return;
    }

    setRevokingId(ruleId);
    setMsg(null);

    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/whitelist/remove',
        method: 'POST',
        data: { id: ruleId },
      });

      if (res?.success) {
        setMsg({ type: 'success', text: 'Whitelist rule revoked successfully.' });
        fetchRules();
        if (onRefreshFindings) {
          onRefreshFindings();
        }
      } else {
        setMsg({ type: 'error', text: res?.message || 'Failed to revoke rule.' });
      }
    } catch (err: any) {
      setMsg({ type: 'error', text: err?.message || 'Network error while revoking rule.' });
    } finally {
      setRevokingId(null);
    }
  };

  const filteredRules = rules.filter((r) => {
    if (filter === 'active') return r.status === 'active';
    if (filter === 'expired') return r.status === 'expired';
    return true;
  });

  return (
    <div
      className="webcare-forensics-subcard webcare-forensics-whitelist"
      style={{ display: 'flex', flexDirection: 'column', gap: '20px', padding: 0, background: 'transparent', border: 'none', boxShadow: 'none' }}
    >
      {/* Top Header Banner Card */}
      <div className="webcare-forensics-hero" style={{ padding: '24px 28px', marginBottom: 0 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div
              style={{
                width: '46px',
                height: '46px',
                borderRadius: '12px',
                background: 'rgba(16, 185, 129, 0.15)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                color: '#34d399',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}
            >
              <ShieldCheck size={26} />
            </div>
            <div>
              <h2 className="webcare-forensics-title" style={{ margin: 0, fontSize: '20px' }}>
                Whitelist &amp; False-Positive Suppression
              </h2>
              <p className="webcare-forensics-desc">
                Cryptographically locked file exclusions with SHA-256 tamper detection, expiration timers, and audit reasons
              </p>
            </div>
          </div>

          <div>
            <button
              type="button"
              onClick={() => fetchRules()}
              className="webcare-btn webcare-forensics-btn-refresh"
            >
              <RefreshCw size={14} className={loading ? 'webcare-spin' : ''} />
              <span>Refresh Rules</span>
            </button>
          </div>
        </div>

        {/* Stats Row */}
        <div className="webcare-forensics-kpi-grid" style={{ marginTop: '20px', paddingTop: '20px' }}>
          <div className="webcare-forensics-kpi-card">
            <span className="webcare-forensics-kpi-label">Active Rules</span>
            <div className="webcare-forensics-kpi-val" style={{ color: '#0284c7', marginTop: '4px' }}>
              {rules.filter((r) => r.status === 'active').length}
            </div>
          </div>
          <div className="webcare-forensics-kpi-card">
            <span className="webcare-forensics-kpi-label">SHA-256 Hash Locked</span>
            <div className="webcare-forensics-kpi-val" style={{ color: '#059669', marginTop: '4px' }}>
              {rules.filter((r) => r.rule_type === 'file_hash' && r.status === 'active').length}
            </div>
          </div>
          <div className="webcare-forensics-kpi-card">
            <span className="webcare-forensics-kpi-label">Expired / Review</span>
            <div className="webcare-forensics-kpi-val" style={{ color: '#d97706', marginTop: '4px' }}>
              {rules.filter((r) => r.status === 'expired').length}
            </div>
          </div>
        </div>
      </div>

      {msg && (
        <div
          style={{
            padding: '12px 16px',
            borderRadius: '10px',
            fontSize: '13px',
            fontWeight: 600,
            background: msg.type === 'success' ? '#ecfdf5' : '#fef2f2',
            border: msg.type === 'success' ? '1px solid #a7f3d0' : '1px solid #fecaca',
            color: msg.type === 'success' ? '#047857' : '#b91c1c',
          }}
        >
          {msg.text}
        </div>
      )}

      {/* Filter Tabs */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px',
          borderBottom: '1px solid #e2e8f0',
          paddingBottom: '12px',
        }}
      >
        <div style={{ display: 'flex', gap: '8px' }}>
          {(['active', 'all', 'expired'] as const).map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setFilter(tab)}
              className={`webcare-forensics-filter-btn ${filter === tab ? 'active' : ''}`}
            >
              {tab === 'active' ? 'Active Rules' : tab === 'expired' ? 'Expired' : 'All Rules'}
            </button>
          ))}
        </div>
        <span style={{ fontSize: '12px', color: '#64748b', fontFamily: 'monospace' }}>
          Showing {filteredRules.length} rule{filteredRules.length === 1 ? '' : 's'}
        </span>
      </div>

      {/* Rules List */}
      {loading ? (
        <div style={{ padding: '60px 0', textAlign: 'center', color: '#64748b', fontSize: '14px' }}>
          <RefreshCw size={24} className="webcare-spin" style={{ margin: '0 auto 10px', display: 'block', color: '#0284c7' }} />
          Loading whitelist rules...
        </div>
      ) : filteredRules.length === 0 ? (
        <div
          style={{
            padding: '50px 24px',
            textAlign: 'center',
            borderRadius: '12px',
            background: '#ffffff',
            border: '1px solid #e2e8f0',
          }}
        >
          <ShieldCheck size={36} color="#94a3b8" style={{ margin: '0 auto 12px', display: 'block' }} />
          <p style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: '#334155' }}>
            No whitelist rules found matching this filter.
          </p>
          <p style={{ margin: '6px 0 0 0', fontSize: '13px', color: '#64748b' }}>
            To whitelist a finding, click <strong>"Whitelist / Ignore"</strong> on any scan finding card.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {filteredRules.map((rule) => {
            const isHash = rule.rule_type === 'file_hash';
            const isExpired = rule.status === 'expired';

            return (
              <div
                key={rule.id}
                className="webcare-forensics-rule-card"
                style={{
                  opacity: isExpired ? 0.75 : 1,
                }}
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', flex: 1, minWidth: '260px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <span
                      style={{
                        fontSize: '11px',
                        fontWeight: 700,
                        padding: '2px 8px',
                        borderRadius: '6px',
                        border: '1px solid',
                        textTransform: 'uppercase',
                        letterSpacing: '0.4px',
                        background: isHash ? '#e0f2fe' : rule.rule_type === 'file_path' ? '#ede9fe' : '#f1f5f9',
                        borderColor: isHash ? '#bae6fd' : rule.rule_type === 'file_path' ? '#ddd6fe' : '#cbd5e1',
                        color: isHash ? '#0369a1' : rule.rule_type === 'file_path' ? '#6d28d9' : '#475569',
                      }}
                    >
                      {isHash ? 'SHA-256 Hash Lock' : rule.rule_type === 'file_path' ? 'File Path' : 'Issue Signature'}
                    </span>

                    <span
                      style={{
                        fontSize: '11px',
                        fontWeight: 700,
                        padding: '2px 8px',
                        borderRadius: '6px',
                        background: isExpired ? '#fef3c7' : '#ecfdf5',
                        border: isExpired ? '1px solid #fde68a' : '1px solid #a7f3d0',
                        color: isExpired ? '#92400e' : '#047857',
                      }}
                    >
                      {isExpired ? 'Expired' : 'Active'}
                    </span>

                    <span style={{ fontSize: '12px', color: '#94a3b8', fontFamily: 'monospace' }}>
                      Engine: <strong className="webcare-forensics-text-primary">{rule.engine}</strong>
                    </span>

                    <span style={{ fontSize: '12px', color: '#94a3b8', fontFamily: 'monospace' }}>
                      Duration: <strong className="webcare-forensics-text-primary">{rule.duration.replace('_', ' ')}</strong>
                    </span>
                  </div>

                  <div className="webcare-forensics-text-primary" style={{ fontFamily: 'monospace', fontSize: '13px', fontWeight: 700, wordBreak: 'break-all' }}>
                    {rule.target_path || '(Global Issue Suppression)'}
                  </div>

                  {rule.file_hash && (
                    <div style={{ fontSize: '11px', color: '#94a3b8', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                      SHA-256: <span style={{ color: '#38bdf8' }}>{rule.file_hash}</span>
                    </div>
                  )}

                  <div className="webcare-forensics-rule-reason">
                    <strong>Administrative Reason:</strong> {rule.reason}
                  </div>

                  <div style={{ fontSize: '11px', color: '#94a3b8', display: 'flex', gap: '14px', flexWrap: 'wrap' }}>
                    <span>Author: <strong style={{ color: '#64748b' }}>{rule.created_by}</strong></span>
                    <span>Created: <strong style={{ color: '#64748b' }}>{rule.created_at}</strong></span>
                    {rule.expires_at && (
                      <span>Expires: <strong style={{ color: '#64748b' }}>{new Date(rule.expires_at * 1000).toLocaleDateString()}</strong></span>
                    )}
                  </div>
                </div>

                <div>
                  <button
                    type="button"
                    onClick={() => handleRevoke(rule.id)}
                    disabled={revokingId === rule.id}
                    className="webcare-btn"
                    style={{
                      background: '#fff1f2',
                      color: '#be123c',
                      border: '1px solid #fecdd3',
                      padding: '7px 14px',
                      borderRadius: '8px',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: revokingId === rule.id ? 'not-allowed' : 'pointer',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '5px',
                    }}
                  >
                    <Trash2 size={13} />
                    <span>{revokingId === rule.id ? 'Revoking...' : 'Revoke Rule'}</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
