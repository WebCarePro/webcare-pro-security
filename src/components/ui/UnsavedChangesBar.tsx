import React from '@wordpress/element';
import { Save, RotateCcw, AlertCircle, Loader2 } from 'lucide-react';

export interface UnsavedChangesBarProps {
  isDirty: boolean;
  isSaving?: boolean;
  onSave: () => void | Promise<void>;
  onDiscard: () => void;
  message?: string;
  saveLabel?: string;
  discardLabel?: string;
}

export const UnsavedChangesBar: React.FC<UnsavedChangesBarProps> = ({
  isDirty,
  isSaving = false,
  onSave,
  onDiscard,
  message = 'You have unsaved changes',
  saveLabel = 'Save Changes',
  discardLabel = 'Discard',
}) => {
  if (!isDirty) {
    return null;
  }

  return (
    <div
      role="region"
      aria-label="Unsaved changes notification"
      style={{
        position: 'fixed',
        bottom: '24px',
        left: '50%',
        transform: 'translateX(-50%)',
        zIndex: 99999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '18px',
        padding: '12px 20px',
        minWidth: '380px',
        maxWidth: '92vw',
        background: 'var(--webcare-bg-panel, #0f172a)',
        color: 'var(--webcare-text-title, #ffffff)',
        border: '1px solid rgba(245, 158, 11, 0.4)',
        borderRadius: '10px',
        boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.4), 0 8px 10px -6px rgba(0, 0, 0, 0.3)',
        animation: 'webcare-slide-up 0.22s cubic-bezier(0.16, 1, 0.3, 1)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <span
          style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            backgroundColor: '#f59e0b',
            boxShadow: '0 0 8px rgba(245, 158, 11, 0.8)',
            display: 'inline-block',
            flexShrink: 0,
          }}
        />
        <div style={{ fontSize: '13px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span>{message}</span>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <button
          type="button"
          onClick={onDiscard}
          disabled={isSaving}
          className="webcare-btn webcare-btn-secondary"
          style={{
            fontSize: '12.5px',
            padding: '6px 12px',
            borderRadius: '6px',
            background: 'transparent',
            color: 'var(--webcare-text-muted, #94a3b8)',
            border: '1px solid rgba(255, 255, 255, 0.15)',
            cursor: isSaving ? 'not-allowed' : 'pointer',
          }}
        >
          <RotateCcw size={13} style={{ marginRight: '4px' }} />
          <span>{discardLabel}</span>
        </button>

        <button
          type="button"
          onClick={onSave}
          disabled={isSaving}
          className="webcare-btn webcare-btn-primary"
          style={{
            fontSize: '12.5px',
            padding: '6px 16px',
            borderRadius: '6px',
            fontWeight: 600,
            background: 'var(--webcare-primary, #4f46e5)',
            color: '#ffffff',
            border: 'none',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            cursor: isSaving ? 'not-allowed' : 'pointer',
          }}
        >
          {isSaving ? <Loader2 size={13} className="webcare-spin-icon" /> : <Save size={13} />}
          <span>{isSaving ? 'Saving...' : saveLabel}</span>
        </button>
      </div>
    </div>
  );
};
