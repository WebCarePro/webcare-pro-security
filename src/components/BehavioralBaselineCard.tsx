import React, { useState, useEffect } from 'react';
import { Zap, Activity, RefreshCw, CheckCircle2, AlertTriangle, ShieldCheck, Clock, FileCode } from 'lucide-react';

interface BehavioralBaselineCardProps {
  apiRequest: (options: any) => Promise<any>;
}

export const BehavioralBaselineCard: React.FC<BehavioralBaselineCardProps> = ({ apiRequest }) => {
  const [baselineData, setBaselineData] = useState<any>(null);
  const [auditResult, setAuditResult] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [calibrating, setCalibrating] = useState<boolean>(false);
  const [auditing, setAuditing] = useState<boolean>(false);
  const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const fetchStatus = async () => {
    setLoading(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/baseline/status',
        method: 'GET',
      });
      if (res?.success) {
        setBaselineData(res.baseline);
      }
    } catch (err) {
      console.error('Failed to fetch baseline status:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleCalibrate = async () => {
    setCalibrating(true);
    setMsg(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/baseline/calibrate',
        method: 'POST',
      });
      if (res?.success) {
        setMsg({ type: 'success', text: res.message || 'Behavioral baseline calibrated successfully!' });
        fetchStatus();
      } else {
        setMsg({ type: 'error', text: res?.message || 'Calibration failed.' });
      }
    } catch (err: any) {
      setMsg({ type: 'error', text: err?.message || 'Network error during baseline calibration.' });
    } finally {
      setCalibrating(false);
    }
  };

  const runAudit = async () => {
    setAuditing(true);
    setMsg(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/baseline/audit',
        method: 'POST',
      });
      if (res?.success) {
        setAuditResult(res);
      } else {
        setMsg({ type: 'error', text: res?.message || 'Deviation audit failed.' });
      }
    } catch (err: any) {
      setMsg({ type: 'error', text: err?.message || 'Network error during deviation audit.' });
    } finally {
      setAuditing(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const calibrated = Boolean(baselineData);

  return (
    <div className="webcare-card webcare-forensics-subcard">
      {/* Header */}
      <div className="webcare-forensics-subcard-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div
            style={{
              width: '44px',
              height: '44px',
              borderRadius: '10px',
              background: 'var(--webcare-status-clean-soft, rgba(16, 185, 129, 0.15))',
              border: '1px solid var(--webcare-status-clean-border, rgba(16, 185, 129, 0.3))',
              color: 'var(--webcare-status-clean, #059669)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}
          >
            <Zap size={22} color="var(--webcare-status-clean, #059669)" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <h3 className="webcare-forensics-subcard-title">
                Autonomous Behavioral Baseline Engine
              </h3>
              <span
                className={`webcare-badge-pill ${calibrated ? 'webcare-badge-clean' : 'webcare-badge-warning'}`}
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                }}
              >
                {calibrated ? 'Active Baseline' : 'Uncalibrated'}
              </span>
            </div>
            <p className="webcare-forensics-subcard-desc">
              Snapshots critical hooks, cron jobs, drop-ins, and high-entropy code to detect covert implants
            </p>
          </div>
        </div>

        {/* Actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {calibrated && (
            <button
              type="button"
              onClick={runAudit}
              disabled={auditing}
              className="webcare-btn"
              style={{
                background: '#f8fafc',
                color: '#0f172a',
                border: '1px solid #cbd5e1',
                padding: '7px 14px',
                borderRadius: '8px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: auditing ? 'not-allowed' : 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
              }}
            >
              <Activity size={14} className={auditing ? 'webcare-spin' : ''} color="#0284c7" />
              <span>{auditing ? 'Auditing...' : 'Audit Deviations'}</span>
            </button>
          )}

          <button
            type="button"
            onClick={handleCalibrate}
            disabled={calibrating}
            className="webcare-btn"
            style={{
              background: '#0284c7',
              color: '#ffffff',
              border: '1px solid #0369a1',
              padding: '7px 16px',
              borderRadius: '8px',
              fontSize: '12px',
              fontWeight: 700,
              cursor: calibrating ? 'not-allowed' : 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              boxShadow: '0 2px 4px rgba(2, 132, 199, 0.25)',
            }}
          >
            <RefreshCw size={13} className={calibrating ? 'webcare-spin' : ''} />
            <span>{calibrated ? 'Re-Calibrate Baseline' : 'Calibrate Baseline Now'}</span>
          </button>
        </div>
      </div>

      {msg && (
        <div
          style={{
            marginBottom: '16px',
            padding: '12px 16px',
            borderRadius: '8px',
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

      {/* Metrics Row */}
      {calibrated && (
        <div className="webcare-forensics-kpi-grid" style={{ marginTop: 0, paddingTop: 0, borderTop: 'none', marginBottom: '18px' }}>
          <div className="webcare-forensics-kpi-card">
            <span className="webcare-forensics-kpi-label">Tracked Hooks</span>
            <div className="webcare-forensics-kpi-val" style={{ color: '#0284c7', marginTop: '4px' }}>
              {auditResult?.live_metrics?.tracked_hooks ?? Object.keys(baselineData?.hooks || {}).length}
            </div>
            <span className="webcare-forensics-kpi-sub">Core filters & actions</span>
          </div>

          <div className="webcare-forensics-kpi-card">
            <span className="webcare-forensics-kpi-label">Crontab Jobs</span>
            <div className="webcare-forensics-kpi-val" style={{ color: '#059669', marginTop: '4px' }}>
              {auditResult?.live_metrics?.crons_count ?? (baselineData?.cron || []).length}
            </div>
            <span className="webcare-forensics-kpi-sub">Scheduled background events</span>
          </div>

          <div className="webcare-forensics-kpi-card">
            <span className="webcare-forensics-kpi-label">Drop-Ins & MU</span>
            <div className="webcare-forensics-kpi-val" style={{ color: '#7c3aed', marginTop: '4px' }}>
              {auditResult?.live_metrics?.dropins_count ?? 0}
            </div>
            <span className="webcare-forensics-kpi-sub">Early execution files</span>
          </div>

          <div className="webcare-forensics-kpi-card">
            <span className="webcare-forensics-kpi-label">Baseline Health</span>
            <div
              className="webcare-forensics-kpi-val"
              style={{
                marginTop: '4px',
                color: (auditResult?.health_score ?? 100) >= 90 ? '#10b981' : (auditResult?.health_score ?? 100) >= 70 ? '#f59e0b' : '#ef4444',
              }}
            >
              {auditResult?.health_score ?? 100}%
            </div>
            <span className="webcare-forensics-kpi-sub">
              {auditResult?.deviations_count ? `${auditResult.deviations_count} deviation(s)` : 'Zero deviations detected'}
            </span>
          </div>
        </div>
      )}

      {/* Deviations List */}
      {auditResult?.deviations && auditResult.deviations.length > 0 && (
        <div style={{ marginTop: '16px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ fontSize: '12px', fontWeight: 700, color: '#b91c1c', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <AlertTriangle size={15} color="#dc2626" />
            <span>Live Behavioral Deviations Detected ({auditResult.deviations.length})</span>
          </div>

          {auditResult.deviations.map((dev: any, idx: number) => (
            <div
              key={idx}
              style={{
                background: '#fff1f2',
                border: '1px solid #fecdd3',
                borderRadius: '8px',
                padding: '12px 14px',
                fontSize: '12px',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 700, color: '#9f1239' }}>{dev.title}</span>
                <span style={{ fontSize: '10px', fontWeight: 700, padding: '2px 6px', borderRadius: '4px', background: '#fee2e2', color: '#991b1b', textTransform: 'uppercase' }}>
                  {dev.severity}
                </span>
              </div>
              <p style={{ margin: 0, color: '#334155' }}>{dev.description}</p>
              {dev.added && dev.added.length > 0 && (
                <div style={{ background: 'var(--webcare-bg-card, #ffffff)', padding: '6px 10px', borderRadius: '6px', border: '1px solid #fecdd3', fontFamily: 'monospace', fontSize: '11px', color: '#be123c' }}>
                  <strong>Added Callbacks: </strong>{dev.added.join(', ')}
                </div>
              )}
              <div style={{ fontSize: '11px', color: '#64748b' }}>
                <strong>Recommendation: </strong>{dev.recommendation}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Footer Info */}
      {calibrated && baselineData && (
        <div
          style={{
            marginTop: '16px',
            paddingTop: '12px',
            borderTop: '1px solid #f1f5f9',
            fontSize: '11px',
            color: '#64748b',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '8px',
          }}
        >
          <span>Baseline Calibrated: <strong>{baselineData.calibrated_at}</strong> by <strong>{baselineData.calibrated_by}</strong></span>
          <span>WordPress: <strong>{baselineData.wp_version}</strong> &bull; PHP: <strong>{baselineData.php_version}</strong></span>
        </div>
      )}
    </div>
  );
};
