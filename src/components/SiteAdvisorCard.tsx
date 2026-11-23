import React, { useState, useEffect } from 'react';
import { showConfirm } from '../utils/dialog';
import {
  Sparkles,
  ShieldCheck,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Loader2,
  Info,
  ChevronRight,
  ExternalLink,
  Layers,
  ShoppingBag,
  FileText,
  Palette,
  Users,
  GraduationCap,
  X
} from 'lucide-react';

interface SiteAdvisorCardProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  onSettingsUpdated?: () => void;
}

export const SiteAdvisorCard: React.FC<SiteAdvisorCardProps> = ({ apiRequest, onSettingsUpdated }) => {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [applying, setApplying] = useState<boolean>(false);
  const [rollingBack, setRollingBack] = useState<boolean>(false);
  const [modalOpen, setModalOpen] = useState<boolean>(false);
  const [selectedKeys, setSelectedKeys] = useState<{ [key: string]: boolean }>({});
  const [notice, setNotice] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);

  const loadAdvisorData = async () => {
    try {
      setLoading(true);
      const res = await apiRequest({ path: '/site-advisor', method: 'GET' });
      if (res && res.profile && res.recommendations) {
        setData(res);

        // Pre-select actionable recommendations by default
        const initialSelections: { [key: string]: boolean } = {};
        Object.entries(res.recommendations).forEach(([key, rec]: [string, any]) => {
          if (
            rec.state === 'recommended_to_enable' ||
            rec.state === 'monitor_first' ||
            rec.state === 'stale_exemption'
          ) {
            initialSelections[key] = true;
          }
        });
        setSelectedKeys(initialSelections);
      }
    } catch (err: any) {
      console.error('Failed to load Site Advisor data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAdvisorData();
  }, []);

  const handleApply = async () => {
    try {
      setApplying(true);
      setNotice(null);

      const approvedPayload: { [key: string]: any } = {};
      Object.entries(selectedKeys).forEach(([key, isSelected]) => {
        if (isSelected && data?.recommendations[key]?.proposed_value !== undefined) {
          approvedPayload[key] = data.recommendations[key].proposed_value;
        }
      });

      const res = await apiRequest({
        path: '/site-advisor/apply',
        method: 'POST',
        data: { approved: approvedPayload }
      });

      if (res && res.success) {
        setNotice({ type: 'success', message: res.message });
        setModalOpen(false);
        loadAdvisorData();
        if (onSettingsUpdated) onSettingsUpdated();
      } else {
        setNotice({ type: 'error', message: res?.message || 'Failed to apply recommendations.' });
      }
    } catch (err: any) {
      setNotice({ type: 'error', message: err?.message || 'Network error applying recommendations.' });
    } finally {
      setApplying(false);
    }
  };

  const handleRollback = async () => {
    const confirmed = await showConfirm({
      title: 'Rollback Site Advisor',
      message: 'Are you sure you want to rollback Site Advisor changes to your previous baseline configuration?',
      confirmLabel: 'Rollback Baseline',
      variant: 'warning',
    });
    if (!confirmed) {
      return;
    }

    try {
      setRollingBack(true);
      setNotice(null);

      const res = await apiRequest({
        path: '/site-advisor/rollback',
        method: 'POST'
      });

      if (res && res.success) {
        setNotice({ type: 'success', message: res.message });
        loadAdvisorData();
        if (onSettingsUpdated) onSettingsUpdated();
      } else {
        setNotice({ type: 'error', message: res?.message || 'Failed to rollback settings.' });
      }
    } catch (err: any) {
      setNotice({ type: 'error', message: err?.message || 'Network error executing rollback.' });
    } finally {
      setRollingBack(false);
    }
  };

  if (loading && !data) {
    return (
      <div className="webcare-firewall-card" style={{ padding: '20px', marginBottom: '20px', textAlign: 'center' }}>
        <Loader2 size={24} className="webcare-spin-icon" style={{ margin: '0 auto 8px auto', color: '#4f46e5' }} />
        <span style={{ fontSize: '13px', color: '#64748b' }}>Analyzing site architecture &amp; firewall policies...</span>
      </div>
    );
  }

  if (!data) return null;

  const { profile, metrics, recommendations, snapshot } = data;
  const capabilities = profile?.capabilities || {};
  const theme = profile?.theme || {};

  const actionableRecs = Object.entries(recommendations).filter(([_, rec]: [string, any]) =>
    rec.state === 'recommended_to_enable' ||
    rec.state === 'monitor_first' ||
    rec.state === 'stale_exemption' ||
    rec.state === 'compatibility_review' ||
    rec.state === 'needs_configuration'
  );

  return (
    <div className="webcare-site-advisor-card">
      {/* Top Banner & Title */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px', marginBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div
            style={{
              width: '40px',
              height: '40px',
              borderRadius: '10px',
              background: 'linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#ffffff',
              boxShadow: '0 2px 8px rgba(79, 70, 229, 0.25)'
            }}
          >
            <Sparkles size={20} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h3 className="webcare-site-advisor-title">
                Smart Site Advisor &amp; Stack Archetype Intelligence
              </h3>
              <span className="webcare-site-advisor-pill-local">
                Local Telemetry
              </span>
            </div>
            <p className="webcare-site-advisor-desc">
              Context-aware security recommendations tailored to your detected theme, active plugin stack, and proxy architecture.
            </p>
          </div>
        </div>

        {/* Primary Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {snapshot && (
            <button
              type="button"
              className="webcare-site-advisor-undo-btn"
              onClick={handleRollback}
              disabled={rollingBack}
              title={`Revert to baseline snapshot saved at ${snapshot.created_at}`}
            >
              {rollingBack ? <Loader2 size={13} className="webcare-spin-icon" /> : <RotateCcw size={13} />}
              {rollingBack ? 'Reverting...' : 'Undo Advisor Baseline'}
            </button>
          )}

          <button
            type="button"
            className="webcare-btn webcare-btn-primary"
            onClick={() => setModalOpen(true)}
            style={{
              fontSize: '12px',
              padding: '7px 16px',
              borderRadius: '6px',
              background: '#4f46e5',
              color: '#ffffff',
              border: 'none',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              fontWeight: 600,
              boxShadow: '0 2px 6px rgba(79, 70, 229, 0.2)'
            }}
          >
            <Sliders size={13} />
            Review Recommendations ({metrics.recommended_count + metrics.stale_count + metrics.monitor_count})
          </button>
        </div>
      </div>

      {notice && (
        <div
          style={{
            padding: '10px 14px',
            borderRadius: '8px',
            marginBottom: '14px',
            fontSize: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '8px',
            background: notice.type === 'success' ? '#ecfdf5' : '#fef2f2',
            color: notice.type === 'success' ? '#065f46' : '#991b1b',
            border: `1px solid ${notice.type === 'success' ? '#a7f3d0' : '#fecaca'}`
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {notice.type === 'success' ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />}
            <span>{notice.message}</span>
          </div>
          <button
            type="button"
            onClick={() => setNotice(null)}
            style={{
              background: 'transparent',
              border: 'none',
              cursor: 'pointer',
              color: 'inherit',
              padding: '2px',
              display: 'flex',
              alignItems: 'center',
              opacity: 0.7
            }}
            title="Dismiss notice"
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* Stack Archetype & Capability Badges */}
      <div className="webcare-site-advisor-stack-strip">
        <span className="webcare-site-advisor-stack-label">
          Detected Stack:
        </span>

        {/* Theme badge */}
        <span className="webcare-site-advisor-theme-badge">
          <Palette size={13} color="#6366f1" />
          {theme.name || 'Theme'}
          <span style={{ fontSize: '10px', opacity: 0.8, fontWeight: 500 }}>({theme.vendor_label || 'WP Directory'})</span>
        </span>

        {/* Capabilities */}
        {capabilities.commerce?.detected && (
          <span className="webcare-badge-pill webcare-badge-success" style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
            <ShoppingBag size={13} /> E-Commerce Active
          </span>
        )}

        {capabilities.forms?.detected && (
          <span className="webcare-badge-pill webcare-badge-success" style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
            <FileText size={13} /> Form System
          </span>
        )}

        {capabilities.builder?.detected && (
          <span className="webcare-badge-pill webcare-badge-info" style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
            <Layers size={13} /> Visual Builder
          </span>
        )}

        {capabilities.membership?.detected && (
          <span className="webcare-badge-pill webcare-badge-purple" style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
            <Users size={13} /> Membership
          </span>
        )}

        {capabilities.lms?.detected && (
          <span className="webcare-badge-pill webcare-badge-warning" style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
            <GraduationCap size={13} /> LMS / Education
          </span>
        )}
      </div>

      {/* Metric Counters Strip */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '10px' }}>
        <div className="webcare-site-advisor-metric-card">
          <span className="webcare-site-advisor-metric-label">Active Protections</span>
          <span style={{ fontSize: '16px', fontWeight: 700, color: '#10b981' }}>{metrics.protected_count} Enabled</span>
        </div>

        <div className="webcare-site-advisor-metric-card">
          <span className="webcare-site-advisor-metric-label">Recommended</span>
          <span style={{ fontSize: '16px', fontWeight: 700, color: metrics.recommended_count > 0 ? '#6366f1' : 'var(--webcare-text-muted, #64748b)' }}>
            {metrics.recommended_count} Rules
          </span>
        </div>

        <div className="webcare-site-advisor-metric-card">
          <span className="webcare-site-advisor-metric-label">Monitor Mode</span>
          <span style={{ fontSize: '16px', fontWeight: 700, color: '#0284c7' }}>{metrics.monitor_count} Policies</span>
        </div>

        <div className="webcare-site-advisor-metric-card">
          <span className="webcare-site-advisor-metric-label">Active Exemptions</span>
          <span style={{ fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-secondary, #475569)' }}>{metrics.exemption_count} Mode</span>
        </div>

        {metrics.stale_count > 0 && (
          <div className="webcare-site-advisor-metric-stale">
            <span style={{ fontSize: '11px', color: '#f59e0b', display: 'block' }}>Stale Exemptions</span>
            <span style={{ fontSize: '16px', fontWeight: 700, color: '#f59e0b' }}>{metrics.stale_count} Removable</span>
          </div>
        )}
      </div>

      {/* Review Recommendations Diff Modal */}
      {modalOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(9, 13, 22, 0.75)',
            backdropFilter: 'blur(4px)',
            zIndex: 99999,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '20px'
          }}
        >
          <div className="webcare-site-advisor-modal">
            {/* Modal Header */}
            <div className="webcare-site-advisor-modal-header">
              <div>
                <h3 className="webcare-site-advisor-title">
                  Site Advisor Security Policy Review
                </h3>
                <span className="webcare-site-advisor-desc">
                  Review and customize recommended adjustments. A reversible configuration snapshot is automatically generated.
                </span>
              </div>
              <button
                type="button"
                onClick={() => setModalOpen(false)}
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  color: 'var(--webcare-text-muted, #64748b)',
                  padding: '4px'
                }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Body: Recommendations List */}
            <div style={{ padding: '20px 24px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {actionableRecs.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '40px 20px', color: '#10b981' }}>
                  <ShieldCheck size={48} style={{ margin: '0 auto 12px auto' }} />
                  <h4 style={{ margin: '0 0 6px 0', fontSize: '16px' }}>All Security Protections Aligned!</h4>
                  <p style={{ margin: 0, fontSize: '13px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    Your current firewall configuration perfectly matches your active theme and plugin stack. No adjustments needed.
                  </p>
                </div>
              ) : (
                actionableRecs.map(([key, rec]: [string, any]) => {
                  const isChecked = !!selectedKeys[key];
                  const isStale = rec.state === 'stale_exemption';
                  const isExemption = rec.type === 'compatibility_exemption';

                  return (
                    <div
                      key={key}
                      className="webcare-site-advisor-rec-item"
                      style={{
                        border: isStale ? '1px solid rgba(249, 115, 22, 0.4)' : (isExemption ? '1px solid var(--webcare-border, rgba(255,255,255,0.08))' : '1px solid rgba(99, 102, 241, 0.4)'),
                        background: isStale ? 'rgba(249, 115, 22, 0.08)' : undefined
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={(e) => setSelectedKeys({ ...selectedKeys, [key]: e.target.checked })}
                        style={{ marginTop: '3px', cursor: 'pointer' }}
                        id={`rec-${key}`}
                      />
                      <div style={{ flex: 1 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '4px' }}>
                          <label
                            htmlFor={`rec-${key}`}
                            style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)', cursor: 'pointer' }}
                          >
                            {rec.title}
                          </label>

                          {/* State pill */}
                          {isStale && (
                            <span className="webcare-badge-pill webcare-badge-warning">
                              Stale Exemption (Recommend Disable)
                            </span>
                          )}
                          {rec.state === 'recommended_to_enable' && (
                            <span className="webcare-badge-pill webcare-badge-success">
                              Recommended to Enable
                            </span>
                          )}
                          {rec.state === 'monitor_first' && (
                            <span className="webcare-badge-pill webcare-badge-info">
                              Monitor Mode First
                            </span>
                          )}
                          {rec.state === 'compatibility_review' && (
                            <span className="webcare-badge-pill webcare-badge-neutral">
                              Compatibility Exemption
                            </span>
                          )}
                        </div>

                        <p style={{ margin: '0 0 6px 0', fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.4 }}>
                          {rec.description}
                        </p>

                        <div className="webcare-site-advisor-rec-justification">
                          <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>Technical Justification:</strong> {rec.notes || rec.security_benefit}
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Modal Footer */}
            <div className="webcare-site-advisor-modal-footer">
              <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                All changes create an instant, conflict-aware rollback snapshot.
              </span>
              <div style={{ display: 'flex', gap: '10px' }}>
                <button
                  type="button"
                  className="webcare-site-advisor-undo-btn"
                  onClick={() => setModalOpen(false)}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="webcare-btn webcare-btn-primary"
                  onClick={handleApply}
                  disabled={applying || Object.values(selectedKeys).filter(Boolean).length === 0}
                  style={{
                    fontSize: '12px',
                    padding: '7px 16px',
                    borderRadius: '6px',
                    background: '#4f46e5',
                    color: '#ffffff',
                    border: 'none',
                    fontWeight: 600,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}
                >
                  {applying ? <Loader2 size={13} className="webcare-spin-icon" /> : <CheckCircle2 size={13} />}
                  {applying ? 'Applying Changes...' : `Apply Selected (${Object.values(selectedKeys).filter(Boolean).length})`}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
