import { useState, useEffect, useRef } from '@wordpress/element';
import { AlertTriangle, AlertCircle, HelpCircle, X } from 'lucide-react';

export type ModalVariant = 'danger' | 'warning' | 'primary';

export interface ConfirmModalOptions {
  title?: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: ModalVariant;
  // Prompt mode support
  isPrompt?: boolean;
  promptPlaceholder?: string;
  promptDefaultValue?: string;
}

interface ActiveModalState extends ConfirmModalOptions {
  id: string;
  resolve: (value: any) => void;
}

type ModalListener = (modal: ActiveModalState | null) => void;

class ModalEventManager {
  private listener: ModalListener | null = null;

  setListener(listener: ModalListener): void {
    this.listener = listener;
  }

  open(modal: ActiveModalState): void {
    if (this.listener) {
      this.listener(modal);
    }
  }

  close(): void {
    if (this.listener) {
      this.listener(null);
    }
  }
}

const modalEventBus = new ModalEventManager();

/**
 * Imperative confirm dialog helper returning a Promise<boolean>.
 */
export const confirmAction = (options: ConfirmModalOptions | string): Promise<boolean> => {
  const opts: ConfirmModalOptions =
    typeof options === 'string'
      ? { message: options, variant: 'primary' }
      : options;

  return new Promise<boolean>((resolve) => {
    modalEventBus.open({
      ...opts,
      id: `modal-${Date.now()}`,
      resolve: (val: boolean) => resolve(val),
    });
  });
};

/**
 * Imperative prompt dialog helper returning Promise<string | null>.
 */
export const promptAction = (
  message: string,
  defaultValue = '',
  options?: Omit<ConfirmModalOptions, 'message' | 'isPrompt' | 'promptDefaultValue'>
): Promise<string | null> => {
  return new Promise<string | null>((resolve) => {
    modalEventBus.open({
      ...options,
      message,
      isPrompt: true,
      promptDefaultValue: defaultValue,
      id: `modal-${Date.now()}`,
      resolve: (val: string | null) => resolve(val),
    });
  });
};

export const ConfirmModalHost = () => {
  const [modal, setModal] = useState<ActiveModalState | null>(null);
  const [promptValue, setPromptValue] = useState<string>('');
  const confirmBtnRef = useRef<HTMLButtonElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    modalEventBus.setListener((newModal) => {
      setModal(newModal);
      if (newModal?.isPrompt) {
        setPromptValue(newModal.promptDefaultValue || '');
      }
    });

    return () => modalEventBus.setListener(() => {});
  }, []);

  // Focus trap / auto-focus on open
  useEffect(() => {
    if (!modal) return;

    const timer = setTimeout(() => {
      if (modal.isPrompt && inputRef.current) {
        inputRef.current.focus();
        inputRef.current.select();
      } else if (confirmBtnRef.current) {
        confirmBtnRef.current.focus();
      }
    }, 50);

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        handleCancel();
      } else if (e.key === 'Enter' && modal.isPrompt) {
        e.preventDefault();
        handleConfirm();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      clearTimeout(timer);
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [modal, promptValue]);

  if (!modal) return null;

  const handleCancel = () => {
    modal.resolve(modal.isPrompt ? null : false);
    setModal(null);
  };

  const handleConfirm = () => {
    modal.resolve(modal.isPrompt ? promptValue : true);
    setModal(null);
  };

  const variant = modal.variant || 'primary';

  const getVariantStyles = () => {
    switch (variant) {
      case 'danger':
        return {
          icon: <AlertCircle size={22} style={{ color: '#ef4444' }} />,
          confirmBg: '#dc2626',
          confirmHoverBg: '#b91c1c',
          confirmText: '#ffffff',
          accentBorder: 'rgba(239, 68, 68, 0.3)',
        };
      case 'warning':
        return {
          icon: <AlertTriangle size={22} style={{ color: '#f59e0b' }} />,
          confirmBg: '#d97706',
          confirmHoverBg: '#b45309',
          confirmText: '#ffffff',
          accentBorder: 'rgba(245, 158, 11, 0.3)',
        };
      case 'primary':
      default:
        return {
          icon: <HelpCircle size={22} style={{ color: 'var(--webcare-primary, #4f46e5)' }} />,
          confirmBg: 'var(--webcare-primary, #4f46e5)',
          confirmHoverBg: '#4338ca',
          confirmText: '#ffffff',
          accentBorder: 'rgba(99, 102, 241, 0.3)',
        };
    }
  };

  const vStyles = getVariantStyles();

  return (
    <div
      className="webcare-confirm-modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="webcare-confirm-title"
      aria-describedby="webcare-confirm-desc"
      onClick={(e) => {
        if (e.target === e.currentTarget) {
          handleCancel();
        }
      }}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 999998,
        background: 'rgba(9, 13, 22, 0.65)',
        backdropFilter: 'blur(4px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px',
        animation: 'webcare-fade-in 0.15s ease-out',
      }}
    >
      <div
        className="webcare-confirm-modal-card"
        style={{
          width: '100%',
          maxWidth: '460px',
          background: 'var(--webcare-bg-panel, #ffffff)',
          border: '1px solid var(--webcare-border, #e2e8f0)',
          borderRadius: '14px',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.35)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          animation: 'webcare-modal-pop 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
        }}
      >
        {/* Header */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '16px 20px',
            borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
            background: 'var(--webcare-bg-elevated, #f8fafc)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                background: 'var(--webcare-bg-panel, #ffffff)',
                border: `1px solid ${vStyles.accentBorder}`,
              }}
            >
              {vStyles.icon}
            </div>
            <h3
              id="webcare-confirm-title"
              style={{
                margin: 0,
                fontSize: '15px',
                fontWeight: 700,
                color: 'var(--webcare-text-heading, #0f172a)',
              }}
            >
              {modal.title || (modal.isPrompt ? 'Input Required' : 'Confirmation Required')}
            </h3>
          </div>
          <button
            type="button"
            onClick={handleCancel}
            aria-label="Close dialog"
            style={{
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              padding: '4px',
              color: 'var(--webcare-text-muted, #94a3b8)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: '6px',
            }}
          >
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: '20px' }}>
          <p
            id="webcare-confirm-desc"
            style={{
              margin: '0 0 16px 0',
              fontSize: '13.5px',
              lineHeight: '1.55',
              color: 'var(--webcare-text-secondary, #475569)',
              whiteSpace: 'pre-line',
            }}
          >
            {modal.message}
          </p>

          {modal.isPrompt && (
            <input
              ref={inputRef}
              type="text"
              value={promptValue}
              onChange={(e) => setPromptValue(e.target.value)}
              placeholder={modal.promptPlaceholder || ''}
              className="webcare-input"
              style={{
                width: '100%',
                padding: '9px 12px',
                borderRadius: '8px',
                border: '1px solid var(--webcare-border-strong, #cbd5e1)',
                background: 'var(--webcare-bg-panel, #ffffff)',
                color: 'var(--webcare-text-primary, #0f172a)',
                fontSize: '13px',
                outline: 'none',
                boxSizing: 'border-box',
              }}
            />
          )}
        </div>

        {/* Footer */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'flex-end',
            gap: '10px',
            padding: '14px 20px',
            borderTop: '1px solid var(--webcare-border, #e2e8f0)',
            background: 'var(--webcare-bg-elevated, #f8fafc)',
          }}
        >
          <button
            type="button"
            onClick={handleCancel}
            className="webcare-btn-secondary"
            style={{
              padding: '8px 16px',
              borderRadius: '8px',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
              background: 'var(--webcare-bg-panel, #ffffff)',
              color: 'var(--webcare-text-primary, #0f172a)',
              border: '1px solid var(--webcare-border-strong, #cbd5e1)',
            }}
          >
            {modal.cancelLabel || 'Cancel'}
          </button>
          <button
            ref={confirmBtnRef}
            type="button"
            onClick={handleConfirm}
            style={{
              padding: '8px 18px',
              borderRadius: '8px',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
              background: vStyles.confirmBg,
              color: vStyles.confirmText,
              border: 'none',
              boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)',
              transition: 'background-color 0.15s ease',
            }}
          >
            {modal.confirmLabel || (modal.isPrompt ? 'Submit' : 'Confirm')}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ConfirmModalHost;
