import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Users,
  FileCode,
  CheckCircle2,
  XCircle,
  Loader2,
  Activity,
  Zap,
  Info,
  Clock,
  UserCheck,
  Server
} from 'lucide-react';

interface EmergencyContainmentCardProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
}

export const EmergencyContainmentCard: React.FC<EmergencyContainmentCardProps> = ({ apiRequest }) => {
  const [status, setStatus] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [reason, setReason] = useState<string>('Suspected active breach / rogue credential containment');
  const [maintenanceEnabled, setMaintenanceEnabled] = useState<boolean>(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [confirmModal, setConfirmModal] = useState<'activate' | 'deactivate' | null>(null);

  const fetchStatus = async () => {
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/containment/status',
        method: 'GET',
      });
      if (res?.success && res.status) {
        setStatus(res.status);
      }
    } catch (err) {
      console.error('Failed to fetch containment status:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleToggle = async (action: 'activate' | 'deactivate') => {
    setActionLoading(true);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/containment/toggle',
        method: 'POST',
        data: {
          action,
          reason,
          maintenance_enabled: maintenanceEnabled,
        },
      });

      if (res?.success) {
        setFeedback({
          type: 'success',
          message: res.message || (action === 'activate' ? 'Emergency Containment Protocol activated successfully.' : 'Containment Protocol deactivated.'),
        });
        await fetchStatus();
        setConfirmModal(null);
      } else {
        setFeedback({
          type: 'error',
          message: res?.message || 'Operation failed.',
        });
      }
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || 'Failed to toggle containment mode.',
      });
    } finally {
      setActionLoading(false);
    }
  };

  const isActive = !!status?.active;

  if (loading) {
    return (
      <div className="webcare-card" style={{ padding: '40px', textAlign: 'center' }}>
        <Loader2 size={32} className="webcare-spin-icon" style={{ margin: '0 auto 12px' }} />
        <p style={{ color: 'var(--webcare-text-muted)' }}>Querying containment sentinel telemetry...</p>
      </div>
    );
  }

  return (
    <div className="webcare-containment-card-container">
      {/* Feedback Banner */}
      {feedback && (
        <div
          className={`webcare-alert-banner ${feedback.type === 'success' ? 'webcare-alert-success' : 'webcare-alert-danger'}`}
          style={{ marginBottom: '20px' }}
        >
          {feedback.type === 'success' ? <CheckCircle2 size={18} /> : <AlertTriangle size={18} />}
          <span>{feedback.message}</span>
        </div>
      )}

      {/* Hero Header Card */}
      <div
        className="webcare-card"
        style={{
          borderLeft: isActive ? '6px solid #dc2626' : '6px solid #10b981',
          marginBottom: '24px',
          background: isActive
            ? 'linear-gradient(135deg, rgba(239, 68, 68, 0.08) 0%, rgba(220, 38, 38, 0.02) 100%)'
            : 'var(--webcare-bg-panel, #ffffff)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div
              style={{
                width: '56px',
                height: '56px',
                borderRadius: '14px',
                background: isActive ? 'rgba(239, 68, 68, 0.16)' : 'rgba(16, 185, 129, 0.12)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}
            >
              {isActive ? <ShieldAlert size={32} color="#dc2626" /> : <ShieldCheck size={32} color="#10b981" />}
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <h2 style={{ margin: 0, fontSize: '20px', fontWeight: 800 }}>
                  Emergency Incident Containment Protocol
                </h2>
                <span
                  className="webcare-badge-pill"
                  style={{
                    background: isActive ? '#fef2f2' : '#ecfdf5',
                    color: isActive ? '#dc2626' : '#059669',
                    border: `1px solid ${isActive ? '#fecaca' : '#a7f3d0'}`,
                    fontWeight: 700,
                    fontSize: '11px',
                    letterSpacing: '0.04em',
                    textTransform: 'uppercase',
                  }}
                >
                  {isActive ? '● LOCKDOWN ACTIVE' : '○ DEFENSE READY'}
                </span>
              </div>
              <p style={{ margin: '6px 0 0', color: 'var(--webcare-text-secondary)', fontSize: '13px' }}>
                Instantly freeze the blast radius of active security incidents, stop attackers from modifying PHP files, and terminate compromised sessions.
              </p>
            </div>
          </div>

          <div>
            {isActive ? (
              <button
                type="button"
                className="webcare-btn"
                style={{
                  background: '#10b981',
                  color: '#ffffff',
                  fontWeight: 700,
                  padding: '10px 20px',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  borderRadius: '10px',
                }}
                onClick={() => setConfirmModal('deactivate')}
              >
                <CheckCircle2 size={16} />
                <span>Deactivate Lockdown</span>
              </button>
            ) : (
              <button
                type="button"
                className="webcare-btn"
                style={{
                  background: '#dc2626',
                  color: '#ffffff',
                  fontWeight: 700,
                  padding: '10px 20px',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  borderRadius: '10px',
                }}
                onClick={() => setConfirmModal('activate')}
              >
                <ShieldAlert size={16} />
                <span>Activate Emergency Lockdown</span>
              </button>
            )}
          </div>
        </div>

        {/* Live Active Incident Telemetry Strip */}
        {isActive && (
          <div
            style={{
              marginTop: '20px',
              padding: '14px 18px',
              borderRadius: '10px',
              background: 'rgba(239, 68, 68, 0.08)',
              border: '1px solid rgba(239, 68, 68, 0.25)',
              display: 'flex',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '16px',
              fontSize: '13px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <UserCheck size={15} color="#dc2626" />
              <span>Activated by: <strong>{status.activated_by_name || 'Administrator'}</strong></span>
            </div>
            {status.activated_at && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Clock size={15} color="#dc2626" />
                <span>Timestamp: <strong>{new Date(status.activated_at * 1000).toLocaleString()}</strong></span>
              </div>
            )}
            {status.reason && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Info size={15} color="#dc2626" />
                <span>Justification: <em>"{status.reason}"</em></span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 4 Defense Vector Guard Rails Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px', marginBottom: '24px' }}>
        {/* Guard 1: Filesystem Freeze */}
        <div className="webcare-card" style={{ padding: '18px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '8px',
                background: isActive ? 'rgba(239, 68, 68, 0.12)' : 'rgba(79, 70, 229, 0.08)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <FileCode size={18} color={isActive ? '#dc2626' : '#4f46e5'} />
            </div>
            <div>
              <div style={{ fontWeight: 700, fontSize: '14px' }}>Filesystem Freeze</div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted)' }}>DISALLOW_FILE_EDIT / MODS</div>
            </div>
          </div>
          <p style={{ margin: 0, fontSize: '12px', color: 'var(--webcare-text-secondary)', lineHeight: 1.5 }}>
            Blocks plugin/theme file editors in wp-admin, preventing web shell editing and malicious code uploads.
          </p>
          <div style={{ marginTop: '12px', fontSize: '12px', fontWeight: 700, color: isActive ? '#dc2626' : '#10b981' }}>
            {isActive ? '🔒 RUNTIME LOCKED' : '○ Standby'}
          </div>
        </div>

        {/* Guard 2: Session Liquidation */}
        <div className="webcare-card" style={{ padding: '18px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '8px',
                background: isActive ? 'rgba(239, 68, 68, 0.12)' : 'rgba(79, 70, 229, 0.08)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Users size={18} color={isActive ? '#dc2626' : '#4f46e5'} />
            </div>
            <div>
              <div style={{ fontWeight: 700, fontSize: '14px' }}>Session Termination</div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted)' }}>WP_Session_Tokens Purge</div>
            </div>
          </div>
          <p style={{ margin: 0, fontSize: '12px', color: 'var(--webcare-text-secondary)', lineHeight: 1.5 }}>
            Destroys all active WordPress login sessions across all users except the current acting administrator.
          </p>
          <div style={{ marginTop: '12px', fontSize: '12px', fontWeight: 700, color: isActive ? '#dc2626' : '#10b981' }}>
            {isActive ? `🚨 PURGED (${status?.sessions_purged || 0})` : '○ Standby'}
          </div>
        </div>

        {/* Guard 3: Upload Demotion */}
        <div className="webcare-card" style={{ padding: '18px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '8px',
                background: isActive ? 'rgba(239, 68, 68, 0.12)' : 'rgba(79, 70, 229, 0.08)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Lock size={18} color={isActive ? '#dc2626' : '#4f46e5'} />
            </div>
            <div>
              <div style={{ fontWeight: 700, fontSize: '14px' }}>Capability Demotion</div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted)' }}>upload_files & install_plugins</div>
            </div>
          </div>
          <p style={{ margin: 0, fontSize: '12px', color: 'var(--webcare-text-secondary)', lineHeight: 1.5 }}>
            Filters WordPress capabilities via <code>user_has_cap</code>, revoking file uploads from editors, authors, and compromised accounts.
          </p>
          <div style={{ marginTop: '12px', fontSize: '12px', fontWeight: 700, color: isActive ? '#dc2626' : '#10b981' }}>
            {isActive ? '🛡️ FILTER ENFORCED' : '○ Standby'}
          </div>
        </div>

        {/* Guard 4: Public Maintenance */}
        <div className="webcare-card" style={{ padding: '18px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '8px',
                background: isActive ? 'rgba(239, 68, 68, 0.12)' : 'rgba(79, 70, 229, 0.08)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Server size={18} color={isActive ? '#dc2626' : '#4f46e5'} />
            </div>
            <div>
              <div style={{ fontWeight: 700, fontSize: '14px' }}>Public Maintenance</div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted)' }}>HTTP 503 Maintenance Page</div>
            </div>
          </div>
          <p style={{ margin: 0, fontSize: '12px', color: 'var(--webcare-text-secondary)', lineHeight: 1.5 }}>
            Optionally renders a secure, unbranded maintenance response to public visitors while allowing administrators to remediate.
          </p>
          <div style={{ marginTop: '12px', fontSize: '12px', fontWeight: 700, color: status?.maintenance_enabled ? '#dc2626' : '#64748b' }}>
            {status?.maintenance_enabled ? '⚠️ PUBLIC 503 ACTIVE' : '○ Pass-through'}
          </div>
        </div>
      </div>

      {/* Confirmation Modal */}
      {confirmModal && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(9, 13, 22, 0.8)',
            backdropFilter: 'blur(6px)',
            zIndex: 999999,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '20px',
          }}
        >
          <div
            className="webcare-card"
            style={{
              maxWidth: '520px',
              width: '100%',
              padding: '28px',
              border: confirmModal === 'activate' ? '1px solid rgba(239, 68, 68, 0.4)' : '1px solid rgba(16, 185, 129, 0.4)',
              boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.45)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <div
                style={{
                  width: '44px',
                  height: '44px',
                  borderRadius: '10px',
                  background: confirmModal === 'activate' ? 'rgba(239, 68, 68, 0.16)' : 'rgba(16, 185, 129, 0.16)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                }}
              >
                {confirmModal === 'activate' ? <ShieldAlert size={24} color="#dc2626" /> : <ShieldCheck size={24} color="#10b981" />}
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 800 }}>
                  {confirmModal === 'activate' ? 'Confirm Emergency Site Lockdown' : 'Deactivate Containment Protocol'}
                </h3>
                <p style={{ margin: '2px 0 0', color: 'var(--webcare-text-secondary)', fontSize: '13px' }}>
                  {confirmModal === 'activate'
                    ? 'Immediately isolate this WordPress instance from further modifications.'
                    : 'Restore regular administrative permissions and allow file modifications.'}
                </p>
              </div>
            </div>

            {confirmModal === 'activate' && (
              <div style={{ marginBottom: '18px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 700, marginBottom: '6px' }}>
                  Incident Justification & Note (Logged to Audit Vault):
                </label>
                <input
                  type="text"
                  className="webcare-input"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  style={{ width: '100%', padding: '10px 14px', borderRadius: '8px' }}
                  placeholder="e.g. Investigating unexpected admin account injection"
                />

                <div style={{ marginTop: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <input
                    type="checkbox"
                    id="chkMaintenance"
                    checked={maintenanceEnabled}
                    onChange={(e) => setMaintenanceEnabled(e.target.checked)}
                  />
                  <label htmlFor="chkMaintenance" style={{ fontSize: '13px', cursor: 'pointer' }}>
                    Also display secure 503 Maintenance Page to public visitors
                  </label>
                </div>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px' }}>
              <button
                type="button"
                className="webcare-btn"
                style={{ background: 'var(--webcare-bg-surface)', color: 'var(--webcare-text-primary)' }}
                onClick={() => setConfirmModal(null)}
                disabled={actionLoading}
              >
                Cancel
              </button>
              <button
                type="button"
                className="webcare-btn"
                style={{
                  background: confirmModal === 'activate' ? '#dc2626' : '#10b981',
                  color: '#ffffff',
                  fontWeight: 700,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
                onClick={() => handleToggle(confirmModal)}
                disabled={actionLoading}
              >
                {actionLoading && <Loader2 size={14} className="webcare-spin-icon" />}
                <span>{confirmModal === 'activate' ? 'Confirm & Engage Lockdown' : 'Restore Normal Operations'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default EmergencyContainmentCard;
