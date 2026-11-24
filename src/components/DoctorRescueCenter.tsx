import { useState, useEffect } from '@wordpress/element';
import {
  Stethoscope,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Download,
  Play,
  RotateCw,
  Clock,
  Cpu,
  Layers,
  FileKey,
  Server,
  Zap,
  Loader2,
  ExternalLink
} from 'lucide-react';

interface DoctorCheck {
  id: string;
  title: string;
  category: string;
  status: 'pass' | 'warn' | 'fail';
  severity: string;
  message: string;
  current: string;
  required: string;
}

interface DoctorReport {
  score: number;
  summary: {
    total: number;
    passed: number;
    warnings: number;
    failures: number;
  };
  checks: DoctorCheck[];
  safe_mode: {
    paused: boolean;
    paused_until: number;
    seconds_remaining: number;
    rearm_at_gmt: string | null;
  };
  generated_at: string;
}

interface DoctorRescueCenterProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
}

export const DoctorRescueCenter = ({ apiRequest }: DoctorRescueCenterProps) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [report, setReport] = useState<DoctorReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [safeModeSeconds, setSafeModeSeconds] = useState<number>(0);

  const fetchDoctorData = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiRequest({ path: '/system/doctor', method: 'GET' });
      if (res?.success && res?.report) {
        setReport(res.report);
        if (res.report.safe_mode?.paused) {
          setSafeModeSeconds(res.report.safe_mode.seconds_remaining || 900);
        } else {
          setSafeModeSeconds(0);
        }
      } else {
        setError(res?.message || 'Failed to load Doctor diagnostic report.');
      }
    } catch (err: any) {
      setError(err?.message || 'Network error fetching diagnostic telemetry.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDoctorData();
  }, []);

  // Safe mode countdown ticker
  useEffect(() => {
    if (safeModeSeconds <= 0) return;
    const timer = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return;
      setSafeModeSeconds((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          fetchDoctorData();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [safeModeSeconds]);

  const handleToggleSafeMode = async (action: 'pause' | 'resume') => {
    setBusyAction(`safe_mode_${action}`);
    setActionNotice(null);
    try {
      const res = await apiRequest({
        path: '/system/safe-mode',
        method: 'POST',
        data: { action },
      });
      if (res?.success) {
        setActionNotice({
          type: 'success',
          text: res.message || (action === 'pause' ? 'Safe Mode activated for 15 minutes.' : 'Strict Firewall resumed cleanly.'),
        });
        if (action === 'pause') {
          setSafeModeSeconds(res.seconds_remaining || 900);
        } else {
          setSafeModeSeconds(0);
        }
        await fetchDoctorData();
      } else {
        setActionNotice({ type: 'error', text: res?.message || 'Failed to update Safe Mode state.' });
      }
    } catch (err: any) {
      setActionNotice({ type: 'error', text: err?.message || 'Failed to toggle Safe Mode.' });
    } finally {
      setBusyAction(null);
    }
  };

  const handleExportDiagnostics = async () => {
    setBusyAction('export_diagnostic');
    setActionNotice(null);
    try {
      const res = await apiRequest({ path: '/system/diagnostic-export', method: 'GET' });
      if (res?.success && res?.bundle) {
        const jsonStr = JSON.stringify(res.bundle, null, 2);
        const blob = new Blob([jsonStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `webcare-pro-diagnostic-${new Date().toISOString().slice(0, 10)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        setActionNotice({ type: 'success', text: 'DLP-redacted diagnostic bundle exported successfully.' });
      } else {
        setActionNotice({ type: 'error', text: res?.message || 'Failed to generate diagnostic export.' });
      }
    } catch (err: any) {
      setActionNotice({ type: 'error', text: err?.message || 'Failed to export diagnostic bundle.' });
    } finally {
      setBusyAction(null);
    }
  };

  const formatSeconds = (sec: number) => {
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return `${m}:${s < 10 ? '0' : ''}${s}`;
  };

  const isSafeModeActive = safeModeSeconds > 0;

  return (
    <div className="webcare-doctor-rescue-wrap" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Banner & Header */}
      <div
        className="webcare-firewall-rule-card"
        style={{
          padding: '24px',
          borderRadius: '14px',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div
              style={{
                width: '46px',
                height: '46px',
                borderRadius: '12px',
                background: 'rgba(79, 70, 229, 0.12)',
                color: '#4f46e5',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}
            >
              <Stethoscope size={24} />
            </div>
            <div>
              <h2 style={{ margin: 0, fontSize: '19px', fontWeight: 800, color: 'var(--webcare-text-title)' }}>
                Doctor &amp; Rescue Center
              </h2>
              <p style={{ margin: '3px 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary)' }}>
                Deep runtime diagnosis, 1-click 15-minute Safe Mode for plugin conflict testing, and DLP-redacted telemetry export.
              </p>
            </div>
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button
              type="button"
              className="webcare-btn"
              onClick={fetchDoctorData}
              disabled={loading}
              title="Refresh diagnostic checks"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '8px 14px',
                borderRadius: '8px',
                fontSize: '12.5px',
                fontWeight: 600,
                background: 'var(--webcare-bg-surface)',
                color: 'var(--webcare-text-primary)',
                border: '1px solid var(--webcare-border-standard)',
                cursor: 'pointer',
              }}
            >
              <RotateCw size={14} className={loading ? 'webcare-spin' : ''} />
              <span>Refresh Doctor</span>
            </button>

            <button
              type="button"
              className="webcare-btn"
              onClick={handleExportDiagnostics}
              disabled={busyAction === 'export_diagnostic'}
              title="Export complete diagnostic JSON redacted of passwords, tokens, and private IPs"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '8px 14px',
                borderRadius: '8px',
                fontSize: '12.5px',
                fontWeight: 600,
                background: 'rgba(14, 165, 233, 0.1)',
                color: '#0284c7',
                border: '1px solid rgba(14, 165, 233, 0.3)',
                cursor: 'pointer',
              }}
            >
              {busyAction === 'export_diagnostic' ? <Loader2 size={14} className="webcare-spin" /> : <Download size={14} />}
              <span>Export Diagnostic JSON</span>
            </button>
          </div>
        </div>

        {/* Action Notice Banner */}
        {actionNotice && (
          <div
            style={{
              padding: '10px 14px',
              borderRadius: '8px',
              fontSize: '13px',
              fontWeight: 600,
              background: actionNotice.type === 'success' ? 'var(--webcare-status-clean-soft)' : 'var(--webcare-status-critical-soft)',
              color: actionNotice.type === 'success' ? 'var(--webcare-status-clean)' : 'var(--webcare-status-critical)',
              border: `1px solid ${actionNotice.type === 'success' ? 'var(--webcare-status-clean-border)' : 'var(--webcare-status-critical-border)'}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <span>{actionNotice.text}</span>
            <button
              type="button"
              onClick={() => setActionNotice(null)}
              style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'inherit', fontWeight: 700 }}
            >
              ✕
            </button>
          </div>
        )}

        {/* 1-Click Safe Mode Banner */}
        <div
          style={{
            padding: '16px 20px',
            borderRadius: '10px',
            background: isSafeModeActive ? 'rgba(245, 158, 11, 0.08)' : 'var(--webcare-bg-surface)',
            border: `1px solid ${isSafeModeActive ? 'rgba(245, 158, 11, 0.35)' : 'var(--webcare-border-standard)'}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '14px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div
              style={{
                width: '38px',
                height: '38px',
                borderRadius: '8px',
                background: isSafeModeActive ? 'rgba(245, 158, 11, 0.2)' : 'rgba(79, 70, 229, 0.1)',
                color: isSafeModeActive ? '#d97706' : '#4f46e5',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              {isSafeModeActive ? <Clock size={20} /> : <Zap size={20} />}
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '14px', fontWeight: 800, color: 'var(--webcare-text-title)' }}>
                  1-Click Safe Mode (15-Minute Observe-Only Pause)
                </span>
                <span
                  style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: '9999px',
                    background: isSafeModeActive ? 'var(--webcare-status-warn-soft)' : 'var(--webcare-status-clean-soft)',
                    color: isSafeModeActive ? 'var(--webcare-status-warn)' : 'var(--webcare-status-clean)',
                    border: `1px solid ${isSafeModeActive ? 'var(--webcare-status-warn-border)' : 'var(--webcare-status-clean-border)'}`,
                  }}
                >
                  {isSafeModeActive ? `Active · ${formatSeconds(safeModeSeconds)} Remaining` : 'Strict Protection Active'}
                </span>
              </div>
              <p style={{ margin: '3px 0 0', fontSize: '12px', color: 'var(--webcare-text-secondary)' }}>
                {isSafeModeActive
                  ? 'Firewall blocks are temporarily held in Monitor Mode. Requests are logged but not blocked. Re-arms automatically when timer expires.'
                  : 'Need to test a checkout conflict or plugin update? Pause blocking for 15 minutes without deactivating the plugin.'}
              </p>
            </div>
          </div>

          <div>
            {isSafeModeActive ? (
              <button
                type="button"
                className="webcare-btn"
                onClick={() => handleToggleSafeMode('resume')}
                disabled={busyAction === 'safe_mode_resume'}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '9px 18px',
                  borderRadius: '8px',
                  fontSize: '13px',
                  fontWeight: 700,
                  background: '#10b981',
                  color: '#ffffff',
                  border: 'none',
                  cursor: 'pointer',
                  boxShadow: '0 2px 6px rgba(16, 185, 129, 0.3)',
                }}
              >
                {busyAction === 'safe_mode_resume' ? <Loader2 size={15} className="webcare-spin" /> : <ShieldCheck size={15} />}
                <span>Resume Strict Protection Now</span>
              </button>
            ) : (
              <button
                type="button"
                className="webcare-btn"
                onClick={() => handleToggleSafeMode('pause')}
                disabled={busyAction === 'safe_mode_pause'}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '9px 18px',
                  borderRadius: '8px',
                  fontSize: '13px',
                  fontWeight: 700,
                  background: 'rgba(245, 158, 11, 0.12)',
                  color: '#d97706',
                  border: '1px solid rgba(245, 158, 11, 0.4)',
                  cursor: 'pointer',
                }}
              >
                {busyAction === 'safe_mode_pause' ? <Loader2 size={15} className="webcare-spin" /> : <Play size={15} />}
                <span>Activate 15m Safe Mode</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Main Diagnostic Findings Card */}
      <div
        className="webcare-firewall-rule-card"
        style={{
          padding: '24px',
          borderRadius: '14px',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--webcare-border-standard)', paddingBottom: '14px' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 800, color: 'var(--webcare-text-title)' }}>
              Core Infrastructure Health Checks
            </h3>
            <p style={{ margin: '2px 0 0', fontSize: '12.5px', color: 'var(--webcare-text-secondary)' }}>
              Live verification equivalent to <code style={{ color: 'var(--webcare-text-accent)' }}>wp webcare doctor</code>.
            </p>
          </div>

          {report && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--webcare-text-secondary)', fontWeight: 700 }}>
                  Readiness Score
                </div>
                <div
                  style={{
                    fontSize: '20px',
                    fontWeight: 900,
                    color: report.score >= 85 ? 'var(--webcare-status-clean)' : (report.score >= 60 ? 'var(--webcare-status-warn)' : 'var(--webcare-status-critical)'),
                  }}
                >
                  {report.score}%
                </div>
              </div>
            </div>
          )}
        </div>

        {loading && (
          <div style={{ padding: '36px', textAlign: 'center', color: 'var(--webcare-text-secondary)' }}>
            <Loader2 size={24} className="webcare-spin" style={{ margin: '0 auto 10px', display: 'block' }} />
            <span>Running deep diagnostic telemetry audits...</span>
          </div>
        )}

        {error && (
          <div
            style={{
              padding: '14px',
              borderRadius: '8px',
              background: 'var(--webcare-status-critical-soft)',
              color: 'var(--webcare-status-critical)',
              border: '1px solid var(--webcare-status-critical-border)',
              fontSize: '13px',
              fontWeight: 600,
            }}
          >
            {error}
          </div>
        )}

        {report && !loading && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {report.checks.map((check) => {
              const isPass = check.status === 'pass';
              const isWarn = check.status === 'warn';
              return (
                <div
                  key={check.id}
                  style={{
                    padding: '14px 18px',
                    borderRadius: '10px',
                    background: 'var(--webcare-bg-surface)',
                    border: `1px solid ${isPass ? 'var(--webcare-border-standard)' : (isWarn ? 'var(--webcare-status-warn-border)' : 'var(--webcare-status-critical-border)')}`,
                    display: 'flex',
                    alignItems: 'flex-start',
                    justifyContent: 'space-between',
                    gap: '14px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', flex: 1 }}>
                    <div style={{ marginTop: '2px', flexShrink: 0 }}>
                      {isPass && <CheckCircle2 size={18} color="var(--webcare-status-clean)" />}
                      {isWarn && <AlertTriangle size={18} color="var(--webcare-status-warn)" />}
                      {!isPass && !isWarn && <XCircle size={18} color="var(--webcare-status-critical)" />}
                    </div>

                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px', flexWrap: 'wrap' }}>
                        <span style={{ fontSize: '13.5px', fontWeight: 700, color: 'var(--webcare-text-title)' }}>
                          {check.title}
                        </span>
                        <span
                          className={`webcare-badge-pill ${
                            isPass
                              ? 'webcare-badge-clean'
                              : (isWarn ? 'webcare-badge-warn' : 'webcare-badge-danger')
                          }`}
                          style={{
                            fontSize: '11px',
                            fontWeight: 800,
                            letterSpacing: '0.05em',
                            padding: '3px 10px',
                            boxShadow: isPass
                              ? '0 1px 3px rgba(16, 185, 129, 0.15)'
                              : (isWarn ? '0 1px 3px rgba(245, 158, 11, 0.15)' : '0 1px 3px rgba(239, 68, 68, 0.15)'),
                          }}
                        >
                          {isPass && <CheckCircle2 size={12} strokeWidth={2.5} />}
                          {isWarn && <AlertTriangle size={12} strokeWidth={2.5} />}
                          {!isPass && !isWarn && <XCircle size={12} strokeWidth={2.5} />}
                          {check.status.toUpperCase()}
                        </span>
                      </div>

                      <p style={{ margin: '4px 0 0', fontSize: '12.5px', color: 'var(--webcare-text-secondary)', lineHeight: 1.4 }}>
                        {check.message}
                      </p>

                      <div style={{ marginTop: '6px', fontSize: '11.5px', color: 'var(--webcare-text-secondary)', fontFamily: 'var(--font-mono, monospace)' }}>
                        <span style={{ fontWeight: 600 }}>Detected:</span> {check.current} &nbsp;|&nbsp; <span style={{ fontWeight: 600 }}>Target:</span> {check.required}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

export default DoctorRescueCenter;
