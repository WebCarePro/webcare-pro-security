import React from 'react';
import { Sun, Moon, Zap, Sliders, Download, Upload } from 'lucide-react';
import WebCareBrandLogo from '../WebCareBrandLogo';

interface WizardTopBarProps {
  mode: 'express' | 'developer';
  onToggleMode: (mode: 'express' | 'developer') => void;
  themeMode: 'dark' | 'light';
  onToggleTheme: () => void;
  onOpenBlueprint: () => void;
}

export const WizardTopBar: React.FC<WizardTopBarProps> = ({
  mode,
  onToggleMode,
  themeMode,
  onToggleTheme,
  onOpenBlueprint,
}) => {
  return (
    <header
      className="webcare-wizard-header"
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '16px 24px',
        background: 'var(--webcare-bg-panel, #ffffff)',
        borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
        borderRadius: '18px 18px 0 0',
        flexWrap: 'wrap',
        gap: '16px',
        width: '100%',
        boxSizing: 'border-box',
      }}
    >
      {/* Brand & Subtitle */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <WebCareBrandLogo size={36} />
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h1
              style={{
                margin: 0,
                fontSize: '18px',
                fontWeight: 800,
                color: 'var(--webcare-text-primary, #0f172a)',
                letterSpacing: '-0.02em',
                lineHeight: 1.2,
              }}
            >
              WebCare Pro Setup Studio
            </h1>
            <span
              style={{
                fontSize: '10px',
                fontWeight: 700,
                padding: '2px 7px',
                borderRadius: '9999px',
                background: 'rgba(79, 70, 229, 0.08)',
                color: 'var(--webcare-primary, #4f46e5)',
                border: '1px solid rgba(79, 70, 229, 0.2)',
              }}
            >
              v{((window as any).webcareScannerSettings?.version) || '2.12.0'}
            </span>
          </div>
          <p
            style={{
              margin: '2px 0 0 0',
              fontSize: '11px',
              color: 'var(--webcare-text-secondary, #475569)',
              fontWeight: 500,
            }}
          >
            Senior Linux SysAdmin &amp; WordPress Security Architecture • Direct 1-on-1 Tuning
          </p>
        </div>
      </div>

      {/* Mode Switcher + Blueprint + Theme Toggle */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
        {/* Mode Selector Pill */}
        <div
          style={{
            display: 'inline-flex',
            padding: '3px',
            background: 'var(--webcare-bg-surface, #f8fafc)',
            border: '1px solid var(--webcare-border, #e2e8f0)',
            borderRadius: '12px',
          }}
        >
          <button
            type="button"
            onClick={() => onToggleMode('express')}
            style={{
              padding: '6px 12px',
              fontSize: '12px',
              fontWeight: 700,
              borderRadius: '9px',
              border: 'none',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              transition: 'all 0.18s ease',
              background: mode === 'express' ? 'var(--webcare-primary, #4f46e5)' : 'transparent',
              color: mode === 'express' ? '#ffffff' : 'var(--webcare-text-secondary, #475569)',
              boxShadow: mode === 'express' ? '0 2px 6px rgba(79, 70, 229, 0.3)' : 'none',
            }}
          >
            <Zap size={13} /> ⚡ Express (6 Steps)
          </button>
          <button
            type="button"
            onClick={() => onToggleMode('developer')}
            style={{
              padding: '6px 12px',
              fontSize: '12px',
              fontWeight: 700,
              borderRadius: '9px',
              border: 'none',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              transition: 'all 0.18s ease',
              background: mode === 'developer' ? 'var(--webcare-primary, #4f46e5)' : 'transparent',
              color: mode === 'developer' ? '#ffffff' : 'var(--webcare-text-secondary, #475569)',
              boxShadow: mode === 'developer' ? '0 2px 6px rgba(79, 70, 229, 0.3)' : 'none',
            }}
          >
            <Sliders size={13} /> 🛠️ Developer Full-Control (14 Steps)
          </button>
        </div>

        {/* Blueprint Action Button */}
        <button
          type="button"
          onClick={onOpenBlueprint}
          style={{
            padding: '7px 12px',
            fontSize: '12px',
            fontWeight: 600,
            borderRadius: '10px',
            border: '1px solid var(--webcare-border, #e2e8f0)',
            background: 'var(--webcare-bg-surface, #f8fafc)',
            color: 'var(--webcare-text-primary, #0f172a)',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
          title="Export or Import Agency Configuration Blueprint (.json)"
        >
          <Download size={13} />
          <span>Blueprint</span>
        </button>

        {/* Theme Toggle Button */}
        <button
          type="button"
          onClick={onToggleTheme}
          style={{
            padding: '7px 10px',
            borderRadius: '10px',
            border: '1px solid var(--webcare-border, #e2e8f0)',
            background: 'var(--webcare-bg-surface, #f8fafc)',
            color: 'var(--webcare-text-primary, #0f172a)',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
          title={themeMode === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
        >
          {themeMode === 'dark' ? <Sun size={15} color="#f59e0b" /> : <Moon size={15} color="#4f46e5" />}
        </button>
      </div>
    </header>
  );
};
