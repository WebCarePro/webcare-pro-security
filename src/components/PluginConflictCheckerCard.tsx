import React, { useState } from 'react';
import { CheckCircle2, AlertCircle, Info, RefreshCw, ShieldCheck, ArrowRight } from 'lucide-react';

interface ConflictItem {
  id: string;
  severity: 'attention' | 'info';
  plugin_name: string;
  plugin_file: string;
  category: string;
  plain_title: string;
  extended_details: string;
  recommended_action: string;
  target_page?: string;
  target_tab?: string;
}

interface ConflictCheckResult {
  success: boolean;
  status: 'clean' | 'attention';
  headline: string;
  summary: string;
  checked_plugins_count: number;
  attention_count: number;
  conflicts: ConflictItem[];
  checked_at_gmt: string;
}

interface PluginConflictCheckerCardProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
}

export const PluginConflictCheckerCard: React.FC<PluginConflictCheckerCardProps> = ({ apiRequest }) => {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ConflictCheckResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleRunCheck = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiRequest({ path: '/system/conflict-check', method: 'POST' });
      if (res && res.success) {
        setResult(res as ConflictCheckResult);
      } else {
        setError(res?.message || 'Unable to complete the compatibility check right now.');
      }
    } catch (err: any) {
      setError(err?.message || 'Unable to complete the compatibility check right now.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="webcare-firewall-section-group"
      style={{
        marginTop: '20px',
        padding: '22px',
        borderRadius: '14px',
        border: '1px solid var(--webcare-border, #e2e8f0)',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '16px', flexWrap: 'wrap' }}>
        <div style={{ maxWidth: '680px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
            <ShieldCheck size={18} style={{ color: 'var(--webcare-accent-indigo, #4f46e5)' }} />
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
              Plugin Compatibility &amp; Conflict Check
            </h3>
          </div>
          <p style={{ margin: 0, fontSize: '13.5px', lineHeight: 1.55, color: 'var(--webcare-text-secondary, #475569)' }}>
            Gently checks your active plugins and server preload settings to make sure everything works smoothly alongside WebCare Pro Security &amp; Firewall. Read-only — we never modify other plugins&apos; settings.
          </p>
        </div>

        <button
          type="button"
          onClick={handleRunCheck}
          disabled={loading}
          className="button button-primary"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '8px 16px',
            borderRadius: '8px',
            fontWeight: 600,
            background: '#4f46e5',
            borderColor: '#4338ca',
            cursor: loading ? 'not-allowed' : 'pointer',
          }}
        >
          <RefreshCw size={15} className={loading ? 'webcare-spin' : ''} />
          <span>{loading ? 'Checking Compatibility...' : result ? 'Re-run Conflict Check' : 'Run Conflict Check'}</span>
        </button>
      </div>

      {error && (
        <div
          style={{
            marginTop: '16px',
            padding: '12px 14px',
            borderRadius: '8px',
            background: 'var(--webcare-badge-danger-bg, #fef2f2)',
            border: '1px solid var(--webcare-badge-danger-border, #fecaca)',
            color: 'var(--webcare-badge-danger-text, #dc2626)',
            fontSize: '13px',
          }}
        >
          {error}
        </div>
      )}

      {result && (
        <div style={{ marginTop: '18px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div
            className="webcare-firewall-rule-card"
            style={{
              padding: '16px',
              borderRadius: '10px',
              border: '1px solid var(--webcare-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'flex-start',
              gap: '12px',
            }}
          >
            {result.status === 'clean' ? (
              <CheckCircle2 size={20} style={{ color: '#10b981', flexShrink: 0, marginTop: '2px' }} />
            ) : (
              <AlertCircle size={20} style={{ color: '#d97706', flexShrink: 0, marginTop: '2px' }} />
            )}
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: '14.5px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                {result.headline}
              </div>
              <div style={{ fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '4px', lineHeight: 1.5 }}>
                {result.summary}
              </div>
              <div style={{ fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '6px' }}>
                Checked {result.checked_plugins_count} active plugins • {result.checked_at_gmt} UTC
              </div>
            </div>
          </div>

          {result.conflicts.map((item) => (
            <div
              key={item.id}
              className="webcare-firewall-rule-card"
              style={{
                padding: '16px',
                borderRadius: '10px',
                border: '1px solid var(--webcare-border, #e2e8f0)',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  {item.severity === 'attention' ? (
                    <AlertCircle size={16} style={{ color: '#d97706', flexShrink: 0 }} />
                  ) : (
                    <Info size={16} style={{ color: '#4f46e5', flexShrink: 0 }} />
                  )}
                  <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                    {item.plain_title}
                  </span>
                </div>
                <span className="webcare-firewall-role-chip" style={{ fontSize: '11px', fontWeight: 600 }}>
                  {item.category}
                </span>
              </div>

              <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.55, color: 'var(--webcare-text-secondary, #475569)' }}>
                {item.extended_details}
              </p>

              <div
                style={{
                  padding: '10px 12px',
                  borderRadius: '8px',
                  background: 'var(--webcare-bg-surface, #f1f5f9)',
                  fontSize: '12.5px',
                  color: 'var(--webcare-text-primary, #0f172a)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  gap: '12px',
                  flexWrap: 'wrap',
                }}
              >
                <span>
                  <strong>What to do:</strong> {item.recommended_action}
                </span>
                {item.target_page && (
                  <a
                    href={`admin.php?page=${item.target_page}${item.target_tab ? `&tab=${item.target_tab}` : ''}`}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                      fontSize: '12px',
                      fontWeight: 600,
                      color: '#4f46e5',
                      textDecoration: 'none',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    <span>Open Setting</span>
                    <ArrowRight size={13} />
                  </a>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
