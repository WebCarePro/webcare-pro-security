import { useState, useEffect } from '@wordpress/element';
import {
  Wrench,
  X,
  CheckCircle2,
  PauseCircle,
  PlayCircle,
  ShieldCheck,
  Clock,
  Loader2,
  AlertTriangle,
  RefreshCw,
} from 'lucide-react';
import { apiRequest } from '../utils/api';

interface RescueAssistantModalProps {
  isOpen: boolean;
  onClose: () => void;
  onPauseChange?: (pauseStatus: any) => void;
}

export const RescueAssistantModal = ({
  isOpen,
  onClose,
  onPauseChange,
}: RescueAssistantModalProps) => {
  const [loading, setLoading] = useState(false);
  const [recentBlocks, setRecentBlocks] = useState<any[]>([]);
  const [trustedActions, setTrustedActions] = useState<any[]>([]);
  const [pauseStatus, setPauseStatus] = useState<any>(null);
  const [secondsLeft, setSecondsLeft] = useState<number>(0);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Close on Escape key press
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  const loadRescueStatus = async () => {
    setLoading(true);
    try {
      const res = await apiRequest({ path: '/rescue/status?minutes=15', method: 'GET' });
      if (res?.success) {
        setRecentBlocks(Array.isArray(res.recent_blocks) ? res.recent_blocks : []);
        setTrustedActions(Array.isArray(res.trusted_actions) ? res.trusted_actions : []);
        setPauseStatus(res.pause_status || null);
        setSecondsLeft(res.pause_status?.seconds_remaining || 0);
        if (onPauseChange) {
          onPauseChange(res.pause_status);
        }
      }
    } catch (err: any) {
      setFeedback({ type: 'error', text: err?.message || 'Unable to load recent firewall events.' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      setFeedback(null);
      loadRescueStatus();
    }
  }, [isOpen]);

  useEffect(() => {
    if (!pauseStatus?.paused || secondsLeft <= 0) return;
    const timer = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return;
      setSecondsLeft((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(timer);
  }, [pauseStatus?.paused, secondsLeft]);

  if (!isOpen) return null;

  const formatCountdown = (secs: number) => {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  };

  const handleTrustAction = async (blockItem: any, idx: number) => {
    const key = `trust-${idx}`;
    setBusyAction(key);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/rescue/trust-action',
        method: 'POST',
        data: {
          type: blockItem?.trust_target?.type || 'uri',
          value: blockItem?.trust_target?.value || '',
          rule_id: blockItem?.rule_id || blockItem?.trust_target?.rule_id || '',
          label: blockItem?.detected_component || blockItem?.trust_target?.label || '',
          ip: blockItem?.ip_address || '',
        },
      });
      if (res?.success) {
        setFeedback({ type: 'success', text: res.message || 'Action trusted & unblocked cleanly.' });
        setTrustedActions(Array.isArray(res.trusted_actions) ? res.trusted_actions : []);
        setRecentBlocks((prev) => prev.filter((_, i) => i !== idx));
      } else {
        setFeedback({ type: 'error', text: res?.message || 'Failed to allow action.' });
      }
    } catch (err: any) {
      setFeedback({ type: 'error', text: err?.message || 'Failed to save trusted action.' });
    } finally {
      setBusyAction(null);
    }
  };

  const handlePause15m = async () => {
    setBusyAction('pause');
    setFeedback(null);
    try {
      const res = await apiRequest({ path: '/rescue/pause-15m', method: 'POST' });
      if (res?.success) {
        setPauseStatus(res);
        setSecondsLeft(res.seconds_remaining || 900);
        setFeedback({ type: 'success', text: res.message });
        if (onPauseChange) {
          onPauseChange(res);
        }
      }
    } catch (err: any) {
      setFeedback({ type: 'error', text: err?.message || 'Failed to activate 15-minute Test Mode.' });
    } finally {
      setBusyAction(null);
    }
  };

  const handleResume = async () => {
    setBusyAction('resume');
    setFeedback(null);
    try {
      const res = await apiRequest({ path: '/rescue/resume', method: 'POST' });
      if (res?.success) {
        setPauseStatus(res);
        setSecondsLeft(0);
        setFeedback({ type: 'success', text: res.message });
        if (onPauseChange) {
          onPauseChange(res);
        }
      }
    } catch (err: any) {
      setFeedback({ type: 'error', text: err?.message || 'Failed to resume strict firewall.' });
    } finally {
      setBusyAction(null);
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(9, 13, 22, 0.72)',
        backdropFilter: 'blur(4px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 99999,
        padding: '20px',
      }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: '680px',
          maxHeight: '88vh',
          display: 'flex',
          flexDirection: 'column',
          borderRadius: '16px',
          background: 'var(--webcare-bg-panel, #ffffff)',
          border: '1px solid var(--webcare-border, #e2e8f0)',
          boxShadow: '0 24px 48px rgba(0, 0, 0, 0.35)',
          overflow: 'hidden',
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: '18px 22px',
            borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
            background: 'var(--webcare-bg-surface, #f8fafc)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div
              style={{
                width: '40px',
                height: '40px',
                borderRadius: '10px',
                background: 'var(--webcare-status-warn-soft)',
                color: 'var(--webcare-status-warn)',
                border: '1px solid var(--webcare-status-warn-border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}
            >
              <Wrench size={20} />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
                Something Not Working? 1-Click Fix My Site
              </h3>
              <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                Automatically scans recent blocks and translates them into plain English — fix compatibility in one click without turning off security.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            aria-label="Close Rescue Assistant"
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--webcare-text-muted, #64748b)',
              cursor: 'pointer',
              padding: '4px',
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: '20px 22px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Active Pause Countdown Banner */}
          {pauseStatus?.paused && secondsLeft > 0 && (
            <div
              style={{
                padding: '14px 16px',
                borderRadius: '10px',
                background: 'var(--webcare-status-warn-soft)',
                border: '1px solid var(--webcare-status-warn-border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '12px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Clock size={18} color="var(--webcare-status-warn)" />
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 800, color: 'var(--webcare-status-warn)' }}>
                    Test Mode Active — Strict Firewall Paused ({formatCountdown(secondsLeft)} left)
                  </div>
                  <div style={{ fontSize: '11.5px', color: 'var(--webcare-text-secondary, #475569)' }}>
                    Logging continues silently. Strict blocking re-arms automatically when the timer reaches 00:00.
                  </div>
                </div>
              </div>

              <button
                type="button"
                onClick={handleResume}
                disabled={busyAction === 'resume'}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '7px 14px',
                  borderRadius: '8px',
                  border: 'none',
                  background: '#059669',
                  color: '#ffffff',
                  fontSize: '12px',
                  fontWeight: 700,
                  cursor: 'pointer',
                }}
              >
                <PlayCircle size={14} />
                <span>Resume Strict Protection</span>
              </button>
            </div>
          )}

          {feedback && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: '8px',
                fontSize: '12.5px',
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                background: feedback.type === 'success' ? 'var(--webcare-status-clean-soft)' : 'var(--webcare-status-critical-soft)',
                color: feedback.type === 'success' ? 'var(--webcare-status-clean)' : 'var(--webcare-status-critical)',
                border: `1px solid ${feedback.type === 'success' ? 'var(--webcare-status-clean-border)' : 'var(--webcare-status-critical-border)'}`,
              }}
            >
              {feedback.type === 'success' ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />}
              <span>{feedback.text}</span>
            </div>
          )}

          {/* Last 15 Minutes Plain-English Block Analysis */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
              <span style={{ fontSize: '13px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
                Last 15 Minutes Activity Check ({recentBlocks.length})
              </span>
              <button
                type="button"
                onClick={loadRescueStatus}
                disabled={loading}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '5px',
                  padding: '4px 10px',
                  borderRadius: '6px',
                  border: '1px solid var(--webcare-border-form, #cbd5e1)',
                  background: 'var(--webcare-bg-surface, #f8fafc)',
                  color: 'var(--webcare-text-secondary, #475569)',
                  fontSize: '11px',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                <RefreshCw size={12} className={loading ? 'webcare-spin' : ''} />
                <span>Refresh</span>
              </button>
            </div>

            {loading ? (
              <div style={{ padding: '24px', textAlign: 'center', color: 'var(--webcare-text-muted, #64748b)', fontSize: '12.5px' }}>
                <Loader2 size={18} className="webcare-spin" style={{ verticalAlign: 'middle', marginRight: '8px' }} />
                Checking the last 15 minutes of security logs...
              </div>
            ) : recentBlocks.length === 0 ? (
              <div
                style={{
                  padding: '16px',
                  borderRadius: '10px',
                  background: 'var(--webcare-status-clean-soft)',
                  border: '1px solid var(--webcare-status-clean-border)',
                  color: 'var(--webcare-status-clean)',
                  fontSize: '12.5px',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                }}
              >
                <ShieldCheck size={18} />
                <span>
                  No features, plugins, or checkout requests were blocked in the last 15 minutes. If an external webhook or page save is still failing, click “Pause Strict Firewall Rules for 15 Minutes” below to test cleanly.
                </span>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {recentBlocks.map((item, idx) => (
                  <div
                    key={`${item.incident_id || idx}`}
                    style={{
                      padding: '14px 16px',
                      borderRadius: '10px',
                      background: 'var(--webcare-bg-surface, #f8fafc)',
                      border: '1px solid var(--webcare-border, #e2e8f0)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      flexWrap: 'wrap',
                      gap: '12px',
                    }}
                  >
                    <div style={{ flex: 1, minWidth: '240px' }}>
                      <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                        {item.plain_english}
                      </div>
                      <div style={{ fontSize: '11px', fontFamily: 'monospace', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                        {item.request_method} {item.request_uri} {item.rule_id ? `• [${item.rule_id}]` : ''}
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleTrustAction(item, idx)}
                      disabled={busyAction === `trust-${idx}`}
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        padding: '8px 14px',
                        borderRadius: '8px',
                        border: 'none',
                        background: '#059669',
                        color: '#ffffff',
                        fontSize: '12px',
                        fontWeight: 700,
                        cursor: 'pointer',
                      }}
                    >
                      {busyAction === `trust-${idx}` ? <Loader2 size={13} className="webcare-spin" /> : <CheckCircle2 size={14} />}
                      <span>Trust &amp; Allow This Action Permanently</span>
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {trustedActions.length > 0 && (
            <div style={{ paddingTop: '6px' }}>
              <div style={{ fontSize: '11.5px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', marginBottom: '6px' }}>
                Permanently Trusted Actions ({trustedActions.length}):
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                {trustedActions.map((ta, i) => (
                  <span
                    key={ta.id || i}
                    style={{
                      fontSize: '11px',
                      fontWeight: 600,
                      padding: '3px 9px',
                      borderRadius: '6px',
                      background: 'var(--webcare-status-info-soft)',
                      color: 'var(--webcare-status-info)',
                      border: '1px solid var(--webcare-status-info-border)',
                    }}
                  >
                    ✓ {ta.label || ta.value}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '14px 22px',
            borderTop: '1px solid var(--webcare-border, #e2e8f0)',
            background: 'var(--webcare-bg-surface, #f8fafc)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '10px',
          }}
        >
          <span style={{ fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
            Test Mode switches blocking to Monitor-Only for 15 minutes and re-arms itself automatically.
          </span>

          {!pauseStatus?.paused ? (
            <button
              type="button"
              onClick={handlePause15m}
              disabled={busyAction === 'pause'}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '9px 16px',
                borderRadius: '8px',
                border: '1px solid var(--webcare-status-warn-border)',
                background: 'var(--webcare-status-warn-soft)',
                color: 'var(--webcare-status-warn)',
                fontSize: '12px',
                fontWeight: 700,
                cursor: 'pointer',
              }}
            >
              {busyAction === 'pause' ? <Loader2 size={14} className="webcare-spin" /> : <PauseCircle size={15} />}
              <span>Pause Strict Firewall Rules for 15 Minutes (Test Mode)</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '8px 16px',
                borderRadius: '8px',
                border: '1px solid var(--webcare-border-form, #cbd5e1)',
                background: 'var(--webcare-bg-panel, #ffffff)',
                color: 'var(--webcare-text-primary, #1e293b)',
                fontSize: '12px',
                fontWeight: 700,
                cursor: 'pointer',
              }}
            >
              Done
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
