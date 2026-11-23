import React, { useEffect, useRef } from 'react';
import { AlertTriangle, AlertCircle, Info, X } from 'lucide-react';

export interface ConfirmDialogProps {
  isOpen: boolean;
  title: string;
  message: string | React.ReactNode;
  targetItem?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: 'danger' | 'warning' | 'info';
  isLoading?: boolean;
  onConfirm: () => void | Promise<void>;
  onClose: () => void;
}

export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  isOpen,
  title,
  message,
  targetItem,
  confirmLabel = 'Confirm Action',
  cancelLabel = 'Cancel',
  variant = 'danger',
  isLoading = false,
  onConfirm,
  onClose,
}) => {
  const confirmBtnRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => {
        confirmBtnRef.current?.focus();
      }, 50);
    }
  }, [isOpen]);

  // Keyboard accessibility: Escape to cancel
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !isLoading) {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose, isLoading]);

  if (!isOpen) return null;

  const getVariantStyles = () => {
    switch (variant) {
      case 'warning':
        return {
          icon: <AlertTriangle size={20} color="#d97706" />,
          iconBg: 'rgba(245, 158, 11, 0.12)',
          iconBorder: 'rgba(245, 158, 11, 0.3)',
          confirmBg: '#d97706',
          confirmHover: '#b45309',
        };
      case 'info':
        return {
          icon: <Info size={20} color="#2563eb" />,
          iconBg: 'rgba(37, 99, 235, 0.12)',
          iconBorder: 'rgba(37, 99, 235, 0.3)',
          confirmBg: '#2563eb',
          confirmHover: '#1d4ed8',
        };
      case 'danger':
      default:
        return {
          icon: <AlertCircle size={20} color="#dc2626" />,
          iconBg: 'rgba(220, 38, 38, 0.12)',
          iconBorder: 'rgba(220, 38, 38, 0.3)',
          confirmBg: '#dc2626',
          confirmHover: '#b91c1c',
        };
    }
  };

  const vStyles = getVariantStyles();

  return (
    <div
      className="webcare-modal-overlay"
      onClick={() => {
        if (!isLoading) onClose();
      }}
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        zIndex: 9999999,
        background: 'rgba(15, 23, 42, 0.65)',
        backdropFilter: 'blur(5px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px',
        animation: 'webcareFadeIn 0.15s ease-out',
      }}
    >
      <div
        className="webcare-confirm-dialog-card"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: '460px',
          background: 'var(--webcare-bg-panel, #ffffff)',
          border: '1px solid var(--webcare-border-std, #e2e8f0)',
          borderRadius: '14px',
          boxShadow: '0 20px 40px -10px rgba(0, 0, 0, 0.4)',
          overflow: 'hidden',
          animation: 'webcareModalIn 0.18s cubic-bezier(0.16, 1, 0.3, 1)',
        }}
      >
        {/* Header Strip */}
        <div
          style={{
            padding: '18px 20px 14px 20px',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '14px',
          }}
        >
          <div
            style={{
              width: '40px',
              height: '40px',
              borderRadius: '10px',
              background: vStyles.iconBg,
              border: `1px solid ${vStyles.iconBorder}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
              marginTop: '2px',
            }}
          >
            {vStyles.icon}
          </div>

          <div style={{ flex: 1, minWidth: 0 }}>
            <h3
              style={{
                margin: 0,
                fontSize: '16px',
                fontWeight: 700,
                color: 'var(--webcare-text-primary, #0f172a)',
                letterSpacing: '-0.2px',
              }}
            >
              {title}
            </h3>

            <div
              style={{
                marginTop: '6px',
                fontSize: '13px',
                color: 'var(--webcare-text-secondary, #475569)',
                lineHeight: 1.5,
              }}
            >
              {message}
            </div>

            {targetItem && (
              <div
                style={{
                  marginTop: '10px',
                  padding: '8px 12px',
                  background: 'var(--webcare-bg-surface, #f8fafc)',
                  border: '1px solid var(--webcare-border-std, #e2e8f0)',
                  borderRadius: '6px',
                  fontFamily: 'monospace',
                  fontSize: '12px',
                  color: 'var(--webcare-code-text, #0284c7)',
                  wordBreak: 'break-all',
                }}
              >
                {targetItem}
              </div>
            )}
          </div>

          {!isLoading && (
            <button
              type="button"
              onClick={onClose}
              style={{
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                color: 'var(--webcare-text-muted, #64748b)',
                padding: '4px',
                borderRadius: '6px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
              aria-label="Close dialog"
            >
              <X size={18} />
            </button>
          )}
        </div>

        {/* Action Buttons Footer */}
        <div
          style={{
            padding: '12px 20px',
            background: 'var(--webcare-bg-surface, #f8fafc)',
            borderTop: '1px solid var(--webcare-border-std, #e2e8f0)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'flex-end',
            gap: '10px',
          }}
        >
          <button
            type="button"
            onClick={onClose}
            disabled={isLoading}
            className="webcare-btn-secondary"
            style={{
              padding: '8px 16px',
              fontSize: '13px',
              fontWeight: 600,
              borderRadius: '8px',
              cursor: isLoading ? 'not-allowed' : 'pointer',
              opacity: isLoading ? 0.6 : 1,
            }}
          >
            {cancelLabel}
          </button>

          <button
            ref={confirmBtnRef}
            type="button"
            onClick={() => onConfirm()}
            disabled={isLoading}
            style={{
              padding: '8px 18px',
              fontSize: '13px',
              fontWeight: 600,
              borderRadius: '8px',
              border: 'none',
              background: vStyles.confirmBg,
              color: '#ffffff',
              cursor: isLoading ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              boxShadow: '0 2px 6px rgba(0, 0, 0, 0.15)',
              transition: 'background 0.15s ease',
              opacity: isLoading ? 0.75 : 1,
            }}
          >
            {isLoading ? (
              <>
                <span className="webcare-spin" style={{ display: 'inline-block' }}>⟳</span>
                <span>Processing...</span>
              </>
            ) : (
              <span>{confirmLabel}</span>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ConfirmDialog;
