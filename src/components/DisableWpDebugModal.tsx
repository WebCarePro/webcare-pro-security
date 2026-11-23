import React from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  Lock,
  X,
  FileCode,
  CheckCircle2,
  Loader2,
  Undo2
} from 'lucide-react';
import { IssueData } from '../App';

interface DisableWpDebugModalProps {
  isOpen: boolean;
  issue: IssueData | null;
  onClose: () => void;
  onConfirm: (issue: IssueData) => Promise<void>;
  isLoading: boolean;
}

export const DisableWpDebugModal: React.FC<DisableWpDebugModalProps> = ({
  isOpen,
  issue,
  onClose,
  onConfirm,
  isLoading
}) => {
  if (!isOpen || !issue) return null;

  return (
    <div
      className="webcare-modal-backdrop"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(15, 23, 42, 0.75)',
        backdropFilter: 'blur(4px)',
        zIndex: 99999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '16px'
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget && !isLoading) onClose();
      }}
    >
      <div
        className="webcare-modal-card"
        style={{
          width: '100%',
          maxWidth: '560px',
          background: 'var(--webcare-bg-card, #ffffff)',
          color: 'var(--webcare-text-primary, #0f172a)',
          borderRadius: '12px',
          border: '1px solid var(--webcare-border-default, #e2e8f0)',
          boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.25), 0 10px 10px -5px rgba(0, 0, 0, 0.15)',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          animation: 'webcareFadeInUp 0.18s ease-out'
        }}
      >
        {/* Modal Header */}
        <div
          style={{
            padding: '18px 22px',
            borderBottom: '1px solid var(--webcare-border-default, #e2e8f0)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'var(--webcare-bg-surface, #f8fafc)'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '8px',
                background: 'rgba(5, 150, 105, 0.12)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                border: '1px solid rgba(5, 150, 105, 0.25)'
              }}
            >
              <ShieldCheck size={20} color="#059669" />
            </div>
            <div>
              <h3
                style={{
                  margin: 0,
                  fontSize: '16px',
                  fontWeight: 700,
                  color: 'var(--webcare-text-primary, #0f172a)'
                }}
              >
                Disable WordPress Debugging
              </h3>
              <span
                style={{
                  fontSize: '12px',
                  color: 'var(--webcare-text-muted, #64748b)'
                }}
              >
                Production Hardening &amp; Information Exposure Lockdown
              </span>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            disabled={isLoading}
            style={{
              background: 'transparent',
              border: 'none',
              cursor: isLoading ? 'not-allowed' : 'pointer',
              color: 'var(--webcare-text-muted, #64748b)',
              padding: '6px',
              borderRadius: '6px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}
            title="Close dialog"
          >
            <X size={18} />
          </button>
        </div>

        {/* Modal Body */}
        <div style={{ padding: '22px', fontSize: '13.5px', lineHeight: 1.55 }}>
          {/* Target File Pill */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '9px 12px',
              background: 'var(--webcare-bg-elevated, #f1f5f9)',
              borderRadius: '8px',
              marginBottom: '16px',
              border: '1px solid var(--webcare-border-default, #e2e8f0)',
              fontSize: '12.5px'
            }}
          >
            <FileCode size={15} color="#0284c7" />
            <span style={{ fontWeight: 600, color: 'var(--webcare-text-secondary, #475569)' }}>Target File:</span>
            <code
              style={{
                background: 'transparent',
                color: 'var(--webcare-text-primary, #0f172a)',
                fontFamily: 'monospace',
                fontSize: '12px',
                wordBreak: 'break-all'
              }}
            >
              {issue.file_path || 'wp-config.php'}
            </code>
          </div>

          <p style={{ margin: '0 0 14px 0', color: 'var(--webcare-text-primary, #0f172a)' }}>
            Are you sure you want to <strong>1-Click Disable WordPress Debugging</strong> in <code>wp-config.php</code>?
          </p>

          <div
            style={{
              background: 'rgba(5, 150, 105, 0.05)',
              border: '1px solid rgba(5, 150, 105, 0.25)',
              borderRadius: '8px',
              padding: '14px 16px',
              marginBottom: '16px'
            }}
          >
            <div style={{ fontWeight: 700, color: '#047857', marginBottom: '8px', fontSize: '13px' }}>
              Smart Automated Hardening Actions:
            </div>
            <ul style={{ margin: 0, paddingLeft: '18px', color: 'var(--webcare-text-secondary, #475569)', fontSize: '12.5px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <li>
                <strong>Preserves Historical Code:</strong> Safely comments out all developer debugging lines (<code>WP_DEBUG</code>, <code>WP_DEBUG_LOG</code>, <code>WP_DEBUG_DISPLAY</code>, <code>ini_set</code>, and wrapped <code>if</code> blocks).
              </li>
              <li>
                <strong>Production Lockdown:</strong> Explicitly sets <code>WP_DEBUG</code>, <code>WP_DEBUG_LOG</code>, and <code>WP_DEBUG_DISPLAY</code> to <code>false</code>.
              </li>
              <li>
                <strong>Silences Errors:</strong> Enforces <code>@ini_set('display_errors', '0')</code> to prevent leaking database credentials, stack traces, and filesystem paths.
              </li>
              <li>
                <strong>Zero-Risk Rollback:</strong> Retains a timestamped, encrypted backup in WebCare Vault for 1-click restoration if ever needed.
              </li>
            </ul>
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontSize: '11.5px',
              color: 'var(--webcare-text-muted, #64748b)'
            }}
          >
            <Lock size={13} color="#059669" />
            <span>Filesystem permissions will remain owner-restricted; OPcache will be refreshed automatically.</span>
          </div>
        </div>

        {/* Modal Footer */}
        <div
          style={{
            padding: '14px 22px',
            borderTop: '1px solid var(--webcare-border-default, #e2e8f0)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'flex-end',
            gap: '10px',
            background: 'var(--webcare-bg-surface, #f8fafc)'
          }}
        >
          <button
            type="button"
            onClick={onClose}
            disabled={isLoading}
            className="webcare-btn"
            style={{
              padding: '8px 16px',
              fontSize: '13px',
              fontWeight: 600,
              borderRadius: '7px',
              border: '1px solid var(--webcare-border-strong, #cbd5e1)',
              background: 'var(--webcare-bg-card, #ffffff)',
              color: 'var(--webcare-text-primary, #0f172a)',
              cursor: isLoading ? 'not-allowed' : 'pointer'
            }}
          >
            Cancel
          </button>

          <button
            type="button"
            onClick={() => onConfirm(issue)}
            disabled={isLoading}
            className="webcare-btn"
            style={{
              padding: '8px 18px',
              fontSize: '13px',
              fontWeight: 700,
              borderRadius: '7px',
              border: '1px solid #047857',
              background: 'linear-gradient(135deg, #059669 0%, #047857 100%)',
              color: '#ffffff',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              cursor: isLoading ? 'not-allowed' : 'pointer',
              boxShadow: '0 2px 4px rgba(5, 150, 105, 0.25)',
              transition: 'all 0.15s ease'
            }}
          >
            {isLoading ? (
              <>
                <Loader2 size={14} className="webcare-spin" /> Disabling Debugging...
              </>
            ) : (
              <>
                <ShieldCheck size={15} /> Confirm &amp; Disable Debugging
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

