import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  X,
  FileCode,
  Check,
  AlertTriangle,
  Lock,
  Clock,
  FileText,
  ChevronDown,
  ChevronUp,
  Sparkles,
  Loader2,
  Sliders,
} from 'lucide-react';

interface WhitelistModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  issue: {
    id?: number;
    file_path?: string;
    type?: string;
    engine?: string;
    severity?: string;
    description?: string;
  } | null;
  apiRequest: (options: any) => Promise<any>;
}

export const WhitelistModal: React.FC<WhitelistModalProps> = ({
  isOpen,
  onClose,
  onSuccess,
  issue,
  apiRequest,
}) => {
  if (!isOpen || !issue) return null;

  const filePathStr = (issue.file_path || '').trim();
  const hasTarget = Boolean(filePathStr.length > 0 && filePathStr !== 'N/A');
  const isVirtualTarget = hasTarget && /^(user:|comment:|cron:|wp_options:|table:|hook:|db_|core:|plugin:|theme:)/i.test(filePathStr);
  const isPhysicalFile = hasTarget && !isVirtualTarget;
  const isUploadsFile = isPhysicalFile && filePathStr.replace(/\\/g, '/').includes('/wp-content/uploads/');

  const defaultRuleType: 'file_hash' | 'file_path' | 'issue_type' = isPhysicalFile
    ? 'file_hash'
    : (hasTarget ? 'file_path' : 'issue_type');

  const [ruleType, setRuleType] = useState<'file_hash' | 'file_path' | 'issue_type'>(defaultRuleType);
  const [duration, setDuration] = useState<'30_days' | '90_days' | 'permanent'>('90_days');
  const [reason, setReason] = useState<string>('Verified safe customization / Suppressed by site owner');
  const [showAdvanced, setShowAdvanced] = useState<boolean>(false);
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (issue) {
      setRuleType(defaultRuleType);
      setDuration('90_days');
      setReason('Verified safe customization / Suppressed by site owner');
      setShowAdvanced(false);
      setErrorMsg(null);
    }
  }, [issue, defaultRuleType]);

  const submitRule = async (customRuleType = ruleType, customDuration = duration, customReason = reason) => {
    if (!customReason.trim()) {
      setErrorMsg('Please enter an administrative reason.');
      return;
    }

    setSubmitting(true);
    setErrorMsg(null);

    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/whitelist/add',
        method: 'POST',
        data: {
          issue_id: issue.id,
          target_path: issue.file_path || '',
          issue_type: issue.type || '*',
          engine: issue.engine || 'all',
          rule_type: customRuleType,
          duration: customDuration,
          reason: customReason,
        },
      });

      if (res?.success) {
        onSuccess();
        onClose();
      } else {
        setErrorMsg(res?.message || 'Failed to add whitelist rule.');
      }
    } catch (err: any) {
      console.error('Whitelist error:', err);
      setErrorMsg(err?.message || 'Network error while submitting whitelist rule.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleQuickWhitelist = () => {
    submitRule(defaultRuleType, '90_days', 'Verified safe customization / Suppressed by site owner');
  };

  const handleSubmitAdvanced = (e: React.FormEvent) => {
    e.preventDefault();
    submitRule(ruleType, duration, reason);
  };

  return (
    <div
      className="webcare-modal-backdrop"
      style={{
        zIndex: 9999999,
        position: 'fixed',
        inset: 0,
        background: 'rgba(15, 23, 42, 0.8)',
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '16px',
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget && !submitting) {
          onClose();
        }
      }}
    >
      <div
        className="webcare-modal-window"
        style={{
          width: '100%',
          maxWidth: '600px',
          maxHeight: '92vh',
          height: 'auto',
          background: '#090d16',
          border: '1px solid rgba(56, 189, 248, 0.3)',
          borderRadius: '16px',
          boxShadow: '0 25px 60px -15px rgba(0, 0, 0, 0.75), 0 0 25px rgba(56, 189, 248, 0.15)',
          color: '#f8fafc',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          animation: 'webcareScaleIn 0.22s cubic-bezier(0.16, 1, 0.3, 1)',
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: '18px 24px',
            background: '#0f172a',
            borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div
              style={{
                width: '42px',
                height: '42px',
                borderRadius: '10px',
                background: 'rgba(16, 185, 129, 0.15)',
                border: '1px solid rgba(16, 185, 129, 0.35)',
                color: '#34d399',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}
            >
              <ShieldCheck size={22} color="#34d399" />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.2px' }}>
                Mark Finding as Safe &amp; Whitelist
              </h3>
              <p style={{ margin: '3px 0 0 0', fontSize: '12px', color: '#94a3b8' }}>
                Suppress false-positive alert with cryptographic SHA-256 tamper defense
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={submitting}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#94a3b8',
              cursor: submitting ? 'not-allowed' : 'pointer',
              padding: '6px',
              borderRadius: '8px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.15s ease',
            }}
            title="Close modal"
          >
            <X size={20} />
          </button>
        </div>

        {/* Modal Scrollable Body */}
        <div style={{ padding: '22px 24px', overflowY: 'auto', flex: 1 }}>
          {/* Target Finding Preview Card */}
          <div
            style={{
              padding: '14px 16px',
              borderRadius: '12px',
              background: 'rgba(15, 23, 42, 0.9)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              marginBottom: '16px',
              fontSize: '12px',
              display: 'flex',
              flexDirection: 'column',
              gap: '8px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px' }}>
              <span style={{ color: '#94a3b8', fontWeight: 600 }}>{isPhysicalFile ? 'Target File:' : 'Target Item:'}</span>
              <span
                style={{
                  fontFamily: 'monospace',
                  color: '#38bdf8',
                  wordBreak: 'break-all',
                  fontWeight: 600,
                  textAlign: 'right',
                }}
              >
                {issue.file_path || '(Generic Issue)'}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px' }}>
              <span style={{ color: '#94a3b8', fontWeight: 600 }}>Threat Signature:</span>
              <span style={{ color: '#f1f5f9', fontWeight: 700, fontFamily: 'monospace' }}>
                {issue.type || 'Detection Signature'}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px' }}>
              <span style={{ color: '#94a3b8', fontWeight: 600 }}>Engine &amp; Severity:</span>
              <span style={{ color: '#cbd5e1', fontWeight: 700, textTransform: 'uppercase', fontSize: '11px' }}>
                {issue.engine || 'General'} &bull; {issue.severity || 'Medium'}
              </span>
            </div>
          </div>

          {errorMsg && (
            <div
              style={{
                marginBottom: '16px',
                padding: '12px 14px',
                borderRadius: '8px',
                background: 'rgba(239, 68, 68, 0.15)',
                border: '1px solid rgba(239, 68, 68, 0.4)',
                color: '#fca5a5',
                fontSize: '12px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <AlertTriangle size={15} color="#ef4444" style={{ flexShrink: 0 }} />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Quick 1-Click Action Card (Recommended for Non-Technical Users) */}
          <div
            style={{
              background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.12) 0%, rgba(6, 182, 212, 0.08) 100%)',
              border: '1px solid rgba(16, 185, 129, 0.3)',
              borderRadius: '12px',
              padding: '16px 18px',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
              marginBottom: '18px',
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Sparkles size={15} color="#34d399" />
                <strong style={{ fontSize: '13px', color: '#34d399' }}>
                  1-Click Recommendation: Quick Mark as Safe
                </strong>
              </div>
              <p style={{ margin: '5px 0 0 0', fontSize: '12px', color: '#94a3b8', lineHeight: 1.5 }}>
                {isUploadsFile ? (
                  <>
                    Know this code is safe? Clicking below adds its cryptographic SHA-256 hash to the local safe registry{' '}
                    <code style={{ color: '#38bdf8', fontSize: '11px' }}>verified-file-hash/uploads-whitelisted-hashes.json</code>.
                    All other identical course files across uploads (e.g. all module folders) will be{' '}
                    <strong style={{ color: '#34d399' }}>automatically recognized as safe and resolved immediately</strong>!
                  </>
                ) : isPhysicalFile ? (
                  <>
                    Know this code is safe? Clicking below suppresses this finding immediately using automated{' '}
                    <strong>SHA-256 cryptographic locking</strong>. If malware ever modifies this file in the future, the lock breaks and the scanner automatically re-flags it.
                  </>
                ) : (
                  <>
                    Know this finding is safe? Clicking below suppresses this issue for target{' '}
                    <strong style={{ color: '#38bdf8' }}>{filePathStr || 'this item'}</strong>. Future rescans will automatically recognize this suppression and keep it ignored.
                  </>
                )}
              </p>
            </div>

            <button
              type="button"
              disabled={submitting}
              onClick={handleQuickWhitelist}
              style={{
                background: 'linear-gradient(135deg, #059669 0%, #047857 100%)',
                color: '#ffffff',
                border: '1px solid #10b981',
                borderRadius: '8px',
                padding: '11px 18px',
                fontSize: '13px',
                fontWeight: 700,
                cursor: submitting ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
                boxShadow: '0 4px 12px rgba(5, 150, 105, 0.35)',
                opacity: submitting ? 0.75 : 1,
                transition: 'all 0.15s ease',
              }}
            >
              {submitting ? (
                <>
                  <Loader2 size={16} className="webcare-spin" />
                  <span>Applying Cryptographic Safe Status...</span>
                </>
              ) : (
                <>
                  <ShieldCheck size={16} />
                  <span>✓ Mark as Safe &amp; Suppress Finding</span>
                </>
              )}
            </button>
          </div>

          {/* Toggle for Advanced Options */}
          <div style={{ textAlign: 'center', marginBottom: '14px' }}>
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#38bdf8',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 12px',
                borderRadius: '6px',
                transition: 'background 0.15s ease',
              }}
            >
              <Sliders size={13} />
              <span>{showAdvanced ? 'Hide Advanced Options' : 'Show Advanced Rules & Expiration Settings'}</span>
              {showAdvanced ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            </button>
          </div>

          {/* Advanced Collapsible Settings */}
          {showAdvanced && (
            <form onSubmit={handleSubmitAdvanced} style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '10px', borderTop: '1px solid rgba(51, 65, 85, 0.6)' }}>
              {/* Rule Type Mechanism */}
              <div>
                <label
                  style={{
                    display: 'block',
                    fontSize: '12px',
                    fontWeight: 700,
                    color: '#e2e8f0',
                    marginBottom: '8px',
                  }}
                >
                  Suppression Matching Mechanism:
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '8px' }}>
                  {isPhysicalFile && (
                    <button
                      type="button"
                      onClick={() => setRuleType('file_hash')}
                      style={{
                        padding: '10px 12px',
                        borderRadius: '10px',
                        textAlign: 'left',
                        cursor: 'pointer',
                        border: ruleType === 'file_hash' ? '1px solid #38bdf8' : '1px solid #1e293b',
                        background: ruleType === 'file_hash' ? 'rgba(56, 189, 248, 0.15)' : '#0f172a',
                        color: ruleType === 'file_hash' ? '#38bdf8' : '#94a3b8',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      <div style={{ fontWeight: 700, fontSize: '12px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <span>SHA-256 Hash Lock</span>
                        <span style={{ fontSize: '9px', padding: '1px 5px', borderRadius: '4px', background: 'rgba(56, 189, 248, 0.25)', color: '#38bdf8' }}>
                          Best
                        </span>
                      </div>
                      <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '4px', lineHeight: 1.35 }}>
                        Invalidates if file modified
                      </div>
                    </button>
                  )}

                  {hasTarget && (
                    <button
                      type="button"
                      onClick={() => setRuleType('file_path')}
                      style={{
                        padding: '10px 12px',
                        borderRadius: '10px',
                        textAlign: 'left',
                        cursor: 'pointer',
                        border: ruleType === 'file_path' ? '1px solid #38bdf8' : '1px solid #1e293b',
                        background: ruleType === 'file_path' ? 'rgba(56, 189, 248, 0.15)' : '#0f172a',
                        color: ruleType === 'file_path' ? '#38bdf8' : '#94a3b8',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      <div style={{ fontWeight: 700, fontSize: '12px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <span>{isPhysicalFile ? 'Exact File Path' : 'Target Identifier'}</span>
                        {isVirtualTarget && (
                          <span style={{ fontSize: '9px', padding: '1px 5px', borderRadius: '4px', background: 'rgba(56, 189, 248, 0.25)', color: '#38bdf8' }}>
                            Best
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '4px', lineHeight: 1.35 }}>
                        {isPhysicalFile ? 'Matches path regardless of hash' : 'Matches target e.g. user, cron, or option'}
                      </div>
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={() => setRuleType('issue_type')}
                    style={{
                      padding: '10px 12px',
                      borderRadius: '10px',
                      textAlign: 'left',
                      cursor: 'pointer',
                      border: ruleType === 'issue_type' ? '1px solid #38bdf8' : '1px solid #1e293b',
                      background: ruleType === 'issue_type' ? 'rgba(56, 189, 248, 0.15)' : '#0f172a',
                      color: ruleType === 'issue_type' ? '#38bdf8' : '#94a3b8',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    <div style={{ fontWeight: 700, fontSize: '12px' }}>Issue Signature</div>
                    <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '4px', lineHeight: 1.35 }}>
                      Suppresses this rule globally
                    </div>
                  </button>
                </div>
              </div>

              {/* Duration / Lifespan */}
              <div>
                <label
                  style={{
                    display: 'block',
                    fontSize: '12px',
                    fontWeight: 700,
                    color: '#e2e8f0',
                    marginBottom: '8px',
                  }}
                >
                  Rule Lifespan &amp; Expiration:
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' }}>
                  <button
                    type="button"
                    onClick={() => setDuration('30_days')}
                    style={{
                      padding: '8px 10px',
                      borderRadius: '8px',
                      fontSize: '11.5px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      border: duration === '30_days' ? '1px solid #818cf8' : '1px solid #1e293b',
                      background: duration === '30_days' ? 'rgba(129, 140, 248, 0.18)' : '#0f172a',
                      color: duration === '30_days' ? '#a5b4fc' : '#94a3b8',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    30 Days
                  </button>
                  <button
                    type="button"
                    onClick={() => setDuration('90_days')}
                    style={{
                      padding: '8px 10px',
                      borderRadius: '8px',
                      fontSize: '11.5px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      border: duration === '90_days' ? '1px solid #818cf8' : '1px solid #1e293b',
                      background: duration === '90_days' ? 'rgba(129, 140, 248, 0.18)' : '#0f172a',
                      color: duration === '90_days' ? '#a5b4fc' : '#94a3b8',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    90 Days (Quarterly)
                  </button>
                  <button
                    type="button"
                    onClick={() => setDuration('permanent')}
                    style={{
                      padding: '8px 10px',
                      borderRadius: '8px',
                      fontSize: '11.5px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      border: duration === 'permanent' ? '1px solid #818cf8' : '1px solid #1e293b',
                      background: duration === 'permanent' ? 'rgba(129, 140, 248, 0.18)' : '#0f172a',
                      color: duration === 'permanent' ? '#a5b4fc' : '#94a3b8',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    Permanent
                  </button>
                </div>
              </div>

              {/* Administrative Reason */}
              <div>
                <label
                  style={{
                    display: 'block',
                    fontSize: '12px',
                    fontWeight: 700,
                    color: '#e2e8f0',
                    marginBottom: '8px',
                  }}
                >
                  Custom Audit Note / Reason:
                </label>
                <textarea
                  rows={2}
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  style={{
                    width: '100%',
                    boxSizing: 'border-box',
                    padding: '8px 12px',
                    fontSize: '12px',
                    fontFamily: 'inherit',
                    background: '#0f172a',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    color: '#f8fafc',
                    outline: 'none',
                    resize: 'vertical',
                  }}
                  placeholder="Explain why this finding is verified safe..."
                  required
                />
              </div>

              {/* Advanced Submit */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                <button
                  type="submit"
                  disabled={submitting}
                  style={{
                    padding: '8px 16px',
                    fontSize: '12px',
                    fontWeight: 700,
                    background: '#0284c7',
                    color: '#ffffff',
                    border: '1px solid #0369a1',
                    borderRadius: '8px',
                    cursor: submitting ? 'not-allowed' : 'pointer',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                  }}
                >
                  <ShieldCheck size={13} />
                  <span>Save Advanced Whitelist Rule</span>
                </button>
              </div>
            </form>
          )}

          {/* Modal Footer Close */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'flex-end',
              alignItems: 'center',
              paddingTop: '14px',
              marginTop: '14px',
              borderTop: '1px solid #1e293b',
            }}
          >
            <button
              type="button"
              onClick={onClose}
              disabled={submitting}
              style={{
                padding: '7px 16px',
                fontSize: '12px',
                fontWeight: 600,
                background: '#1e293b',
                color: '#cbd5e1',
                border: '1px solid #334155',
                borderRadius: '8px',
                cursor: submitting ? 'not-allowed' : 'pointer',
              }}
            >
              Cancel &amp; Keep Finding
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
