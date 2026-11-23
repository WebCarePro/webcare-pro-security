import React, { useState } from 'react';
import { Sliders, ChevronDown, ChevronUp, Terminal } from 'lucide-react';

interface DeveloperDeepDiveProps {
  title?: string;
  badge?: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}

export const DeveloperDeepDive: React.FC<DeveloperDeepDiveProps> = ({
  title = 'Developer Deep-Dive Parameters',
  badge = '100% SettingsManager Coverage',
  defaultOpen = false,
  children,
}) => {
  const [isOpen, setIsOpen] = useState<boolean>(defaultOpen);

  return (
    <div
      style={{
        marginTop: '20px',
        border: '1px solid var(--webcare-border, #e2e8f0)',
        borderRadius: '14px',
        background: 'var(--webcare-bg-surface, #f8fafc)',
        overflow: 'hidden',
        transition: 'all 0.2s ease',
      }}
    >
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        style={{
          width: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '14px 18px',
          background: 'transparent',
          border: 'none',
          cursor: 'pointer',
          textAlign: 'left',
          color: 'var(--webcare-text-primary, #0f172a)',
        }}
        aria-expanded={isOpen}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div
            style={{
              width: '28px',
              height: '28px',
              borderRadius: '8px',
              background: 'rgba(79, 70, 229, 0.08)',
              color: 'var(--webcare-primary, #4f46e5)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Sliders size={15} />
          </div>
          <div>
            <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
              {title}
            </span>
            <span
              style={{
                marginLeft: '10px',
                fontSize: '10px',
                fontWeight: 600,
                padding: '2px 8px',
                borderRadius: '9999px',
                background: 'rgba(79, 70, 229, 0.08)',
                color: 'var(--webcare-primary, #4f46e5)',
                border: '1px solid rgba(79, 70, 229, 0.2)',
              }}
            >
              {badge}
            </span>
          </div>
        </div>

        <div style={{ color: 'var(--webcare-text-muted, #64748b)', display: 'flex', alignItems: 'center', gap: '4px' }}>
          <span style={{ fontSize: '11px', fontWeight: 600 }}>{isOpen ? 'Collapse' : 'Expand'}</span>
          {isOpen ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </div>
      </button>

      {isOpen && (
        <div
          style={{
            padding: '18px',
            borderTop: '1px solid var(--webcare-border, #e2e8f0)',
            background: 'var(--webcare-bg-panel, #ffffff)',
          }}
        >
          {children}
        </div>
      )}
    </div>
  );
};
