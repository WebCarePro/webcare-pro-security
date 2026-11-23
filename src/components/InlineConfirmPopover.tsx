import React, { useState, useRef, useEffect } from 'react';
import { AlertTriangle, Check, X } from 'lucide-react';

export interface InlineConfirmPopoverProps {
  buttonLabel: string | React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  question?: string;
  consequence?: string;
  buttonClass?: string;
  buttonStyle?: React.CSSProperties;
  buttonIcon?: React.ReactNode;
  variant?: 'danger' | 'warning' | 'primary';
  disabled?: boolean;
  align?: 'right' | 'left' | 'center';
  onConfirm: () => void | Promise<void>;
}

export const InlineConfirmPopover: React.FC<InlineConfirmPopoverProps> = ({
  buttonLabel,
  confirmLabel = 'Yes, Proceed',
  cancelLabel = 'Cancel',
  question = 'Are you sure?',
  consequence,
  buttonClass = 'button',
  buttonStyle = {},
  buttonIcon,
  variant = 'danger',
  disabled = false,
  align = 'right',
  onConfirm,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const popoverRef = useRef<HTMLDivElement>(null);

  // Close on Escape or click outside
  useEffect(() => {
    if (!isOpen) return;

    const handleClickOutside = (e: MouseEvent) => {
      if (popoverRef.current && !popoverRef.current.contains(e.target as Node)) {
        if (!loading) setIsOpen(false);
      }
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !loading) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen, loading]);

  const handleExecute = async () => {
    try {
      setLoading(true);
      await onConfirm();
      setIsOpen(false);
    } catch (err) {
      console.error('Inline action error:', err);
    } finally {
      setLoading(false);
    }
  };

  const getVariantStyles = () => {
    switch (variant) {
      case 'warning':
        return {
          confirmBg: '#d97706',
          confirmHover: '#b45309',
        };
      case 'primary':
        return {
          confirmBg: '#4f46e5',
          confirmHover: '#4338ca',
        };
      case 'danger':
      default:
        return {
          confirmBg: '#dc2626',
          confirmHover: '#b91c1c',
        };
    }
  };

  const vStyles = getVariantStyles();

  return (
    <div
      ref={popoverRef}
      style={{
        position: 'relative',
        display: 'inline-block',
      }}
    >
      <button
        type="button"
        disabled={disabled || loading}
        onClick={(e) => {
          e.stopPropagation();
          setIsOpen((prev) => !prev);
        }}
        className={buttonClass}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '5px',
          cursor: disabled || loading ? 'not-allowed' : 'pointer',
          ...buttonStyle,
        }}
      >
        {buttonIcon}
        <span>{buttonLabel}</span>
      </button>

      {isOpen && (
        <div
          onClick={(e) => e.stopPropagation()}
          className="webcare-inline-confirm-card"
          style={{
            position: 'absolute',
            top: 'calc(100% + 6px)',
            ...(align === 'right'
              ? { right: 0 }
              : align === 'left'
              ? { left: 0 }
              : { left: '50%', transform: 'translateX(-50%)' }),
            zIndex: 9999,
            minWidth: '240px',
            maxWidth: '300px',
            background: 'var(--webcare-bg-panel, #ffffff)',
            border: '1px solid var(--webcare-border-std, #cbd5e1)',
            borderRadius: '10px',
            boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.25)',
            padding: '12px 14px',
            animation: 'webcareModalIn 0.15s ease-out',
            textAlign: 'left',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', marginBottom: '8px' }}>
            <AlertTriangle size={16} color={vStyles.confirmBg} style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <div
                style={{
                  fontSize: '12px',
                  fontWeight: 700,
                  color: 'var(--webcare-text-primary, #0f172a)',
                  lineHeight: 1.3,
                }}
              >
                {question}
              </div>
              {consequence && (
                <div
                  style={{
                    fontSize: '11px',
                    color: 'var(--webcare-text-muted, #64748b)',
                    marginTop: '3px',
                    lineHeight: 1.35,
                  }}
                >
                  {consequence}
                </div>
              )}
            </div>
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'flex-end',
              gap: '6px',
              marginTop: '10px',
            }}
          >
            <button
              type="button"
              disabled={loading}
              onClick={() => setIsOpen(false)}
              style={{
                padding: '4px 8px',
                borderRadius: '6px',
                fontSize: '11px',
                fontWeight: 600,
                background: 'transparent',
                border: '1px solid var(--webcare-border-std, #e2e8f0)',
                color: 'var(--webcare-text-secondary, #475569)',
                cursor: loading ? 'not-allowed' : 'pointer',
              }}
            >
              {cancelLabel}
            </button>

            <button
              type="button"
              disabled={loading}
              onClick={handleExecute}
              style={{
                padding: '4px 10px',
                borderRadius: '6px',
                fontSize: '11px',
                fontWeight: 700,
                border: 'none',
                background: vStyles.confirmBg,
                color: '#ffffff',
                cursor: loading ? 'not-allowed' : 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px',
              }}
            >
              {loading ? (
                <span>Processing...</span>
              ) : (
                <>
                  <Check size={12} />
                  <span>{confirmLabel}</span>
                </>
              )}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default InlineConfirmPopover;
