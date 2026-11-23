import React from 'react';
import {
  Layers,
  Shield,
  Zap,
  Globe,
  Lock,
  Radar,
  Bell,
  CheckCircle2,
  Check,
  Server,
  Terminal,
  Activity,
  HardDrive,
  FileText,
  UserCheck
} from 'lucide-react';
import { WizardPostureScore, PostureBreakdown } from './WizardPostureScore';

export interface StepDefinition {
  num: number;
  label: string;
  phaseId: number;
  icon: React.ReactNode;
  isAutoTuned?: boolean;
}

interface WizardNavigationRailProps {
  currentStep: number;
  mode: 'express' | 'developer';
  onSelectStep: (stepNum: number) => void;
  configuredSteps: Set<number>;
  postureScore: number;
  controlsArmed: number;
  postureBreakdown?: PostureBreakdown[];
  detectedEcosystems?: string[];
}

export const WizardNavigationRail: React.FC<WizardNavigationRailProps> = ({
  currentStep,
  mode,
  onSelectStep,
  configuredSteps,
  postureScore,
  controlsArmed,
  postureBreakdown,
  detectedEcosystems = [],
}) => {
  const hasWoo = detectedEcosystems.includes('woocommerce');

  // Developer 14 Steps Definitions
  const developerSteps: StepDefinition[] = [
    { num: 1, label: 'Stack & Archetype', phaseId: 1, icon: <Layers size={14} />, isAutoTuned: true },
    { num: 2, label: 'PHP Gate & Telemetry', phaseId: 1, icon: <Server size={14} /> },
    { num: 3, label: 'Behavioral Scan & WAF', phaseId: 1, icon: <Radar size={14} />, isAutoTuned: true },
    { num: 4, label: 'Zero-Lockout & IP Safety', phaseId: 1, icon: <UserCheck size={14} />, isAutoTuned: true },
    { num: 5, label: 'Core WAF & Micro-WAF', phaseId: 2, icon: <Shield size={14} /> },
    { num: 6, label: 'CAF 2.0 & Woo Armor', phaseId: 2, icon: <Zap size={14} />, isAutoTuned: hasWoo },
    { num: 7, label: 'Outbound Egress & SMTP', phaseId: 2, icon: <Activity size={14} /> },
    { num: 8, label: 'Webhook Bypass & SEO Bots', phaseId: 2, icon: <FileText size={14} /> },
    { num: 9, label: 'Cloudflare Edge "4 + 1"', phaseId: 2, icon: <Globe size={14} /> },
    { num: 10, label: 'Login, 2FA & Passkeys', phaseId: 3, icon: <Lock size={14} /> },
    { num: 11, label: 'Server Armor & Headers', phaseId: 3, icon: <HardDrive size={14} /> },
    { num: 12, label: '14-Pass Malware & Safety', phaseId: 4, icon: <Radar size={14} /> },
    { num: 13, label: 'AI Copilot & SOC Alerts', phaseId: 4, icon: <Bell size={14} /> },
    { num: 14, label: 'Cryptographic Launch', phaseId: 4, icon: <CheckCircle2 size={14} /> },
  ];

  // Express 6 Steps Definitions
  const expressSteps: StepDefinition[] = [
    { num: 1, label: 'Archetype & Zero-Lockout', phaseId: 1, icon: <Shield size={14} />, isAutoTuned: true },
    { num: 2, label: 'PHP Gate & Pre-Boot Shield', phaseId: 1, icon: <Server size={14} /> },
    { num: 3, label: 'Behavioral Intelligence WAF', phaseId: 1, icon: <Radar size={14} />, isAutoTuned: true },
    { num: 4, label: 'Edge Defense & E-Commerce', phaseId: 2, icon: <Globe size={14} />, isAutoTuned: hasWoo },
    { num: 5, label: 'Identity & Malware Engine', phaseId: 3, icon: <Lock size={14} /> },
    { num: 6, label: 'Alerts & 1-Click Launch', phaseId: 4, icon: <CheckCircle2 size={14} /> },
  ];

  const phases = [
    { id: 1, name: 'Phase 1: Foundation' },
    { id: 2, name: 'Phase 2: Perimeter WAF' },
    { id: 3, name: 'Phase 3: Identity & OS' },
    { id: 4, name: 'Phase 4: Scanner & SOC' },
  ];

  const stepsToRender = mode === 'express' ? expressSteps : developerSteps;

  return (
    <aside
      style={{
        width: '280px',
        flexShrink: 0,
        background: 'var(--webcare-bg-surface, #f8fafc)',
        borderRight: '1px solid var(--webcare-border, #e2e8f0)',
        padding: '20px 16px',
        display: 'flex',
        flexDirection: 'column',
        gap: '20px',
        height: '100%',
        boxSizing: 'border-box',
      }}
    >
      {/* Navigation Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 4px' }}>
        <span
          style={{
            fontSize: '11px',
            fontWeight: 800,
            textTransform: 'uppercase',
            letterSpacing: '0.08em',
            color: 'var(--webcare-text-muted, #64748b)',
          }}
        >
          {mode === 'express' ? '⚡ Express Roadmap' : '🛠️ Studio Navigation Rail'}
        </span>
        <span
          style={{
            fontSize: '10px',
            fontWeight: 700,
            color: 'var(--webcare-primary, #4f46e5)',
            background: 'rgba(79, 70, 229, 0.08)',
            padding: '2px 6px',
            borderRadius: '6px',
          }}
        >
          Step {currentStep} of {stepsToRender.length}
        </span>
      </div>

      {/* Interactive Free-Jump Stepper List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', flex: 1, overflowY: 'auto' }}>
        {mode === 'developer' ? (
          phases.map((phase) => {
            const phaseSteps = developerSteps.filter((s) => s.phaseId === phase.id);
            return (
              <div key={phase.id} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div
                  style={{
                    fontSize: '10px',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    letterSpacing: '0.05em',
                    color: 'var(--webcare-text-muted, #94a3b8)',
                    padding: '4px 8px',
                  }}
                >
                  {phase.name}
                </div>
                {phaseSteps.map((s) => {
                  const isActive = currentStep === s.num;
                  const isDone = configuredSteps.has(s.num) || s.num < currentStep;

                  return (
                    <button
                      key={s.num}
                      type="button"
                      onClick={() => onSelectStep(s.num)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '8px 10px',
                        borderRadius: '10px',
                        border: isActive
                          ? '1px solid var(--webcare-primary, #4f46e5)'
                          : '1px solid transparent',
                        background: isActive
                          ? 'var(--webcare-bg-panel, #ffffff)'
                          : 'transparent',
                        cursor: 'pointer',
                        textAlign: 'left',
                        transition: 'all 0.15s ease',
                        boxShadow: isActive ? '0 2px 8px rgba(79, 70, 229, 0.12)' : 'none',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                        <div
                          style={{
                            width: '24px',
                            height: '24px',
                            borderRadius: '7px',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            flexShrink: 0,
                            background: isActive
                              ? 'var(--webcare-primary, #4f46e5)'
                              : isDone
                              ? 'rgba(16, 185, 129, 0.12)'
                              : 'var(--webcare-bg-elevated, #f1f5f9)',
                            color: isActive ? '#ffffff' : isDone ? '#10b981' : 'var(--webcare-text-muted, #64748b)',
                          }}
                        >
                          {isDone && !isActive ? <Check size={13} /> : s.icon}
                        </div>
                        <span
                          style={{
                            fontSize: '12px',
                            fontWeight: isActive ? 700 : 500,
                            color: isActive
                              ? 'var(--webcare-primary, #4f46e5)'
                              : 'var(--webcare-text-primary, #0f172a)',
                            whiteSpace: 'nowrap',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                          }}
                        >
                          {s.num}. {s.label}
                        </span>
                      </div>

                      {/* Status Badges */}
                      {s.isAutoTuned && (
                        <span
                          style={{
                            fontSize: '9px',
                            fontWeight: 700,
                            padding: '1px 5px',
                            borderRadius: '9999px',
                            background: 'rgba(245, 158, 11, 0.12)',
                            color: '#d97706',
                            border: '1px solid rgba(245, 158, 11, 0.25)',
                            flexShrink: 0,
                          }}
                          title="Auto-calibrated based on active WordPress ecosystem"
                        >
                          Auto
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            );
          })
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {expressSteps.map((s) => {
              const isActive = currentStep === s.num;
              const isDone = configuredSteps.has(s.num) || s.num < currentStep;

              return (
                <button
                  key={s.num}
                  type="button"
                  onClick={() => onSelectStep(s.num)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '10px 12px',
                    borderRadius: '12px',
                    border: isActive
                      ? '1px solid var(--webcare-primary, #4f46e5)'
                      : '1px solid transparent',
                    background: isActive
                      ? 'var(--webcare-bg-panel, #ffffff)'
                      : 'transparent',
                    cursor: 'pointer',
                    textAlign: 'left',
                    transition: 'all 0.15s ease',
                    boxShadow: isActive ? '0 2px 8px rgba(79, 70, 229, 0.12)' : 'none',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0 }}>
                    <div
                      style={{
                        width: '28px',
                        height: '28px',
                        borderRadius: '8px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        flexShrink: 0,
                        background: isActive
                          ? 'var(--webcare-primary, #4f46e5)'
                          : isDone
                          ? 'rgba(16, 185, 129, 0.12)'
                          : 'var(--webcare-bg-elevated, #f1f5f9)',
                        color: isActive ? '#ffffff' : isDone ? '#10b981' : 'var(--webcare-text-muted, #64748b)',
                      }}
                    >
                      {isDone && !isActive ? <Check size={14} /> : s.icon}
                    </div>
                    <span
                      style={{
                        fontSize: '12px',
                        fontWeight: isActive ? 700 : 500,
                        color: isActive
                          ? 'var(--webcare-primary, #4f46e5)'
                          : 'var(--webcare-text-primary, #0f172a)',
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                      }}
                    >
                      {s.num}. {s.label}
                    </span>
                  </div>

                  {s.isAutoTuned && (
                    <span
                      style={{
                        fontSize: '9px',
                        fontWeight: 700,
                        padding: '1px 5px',
                        borderRadius: '9999px',
                        background: 'rgba(245, 158, 11, 0.12)',
                        color: '#d97706',
                        border: '1px solid rgba(245, 158, 11, 0.25)',
                      }}
                    >
                      Auto
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Pinned Security Posture Score Meter */}
      <div style={{ marginTop: 'auto', paddingTop: '8px' }}>
        <WizardPostureScore
          score={postureScore}
          controlsArmed={controlsArmed}
          breakdown={postureBreakdown}
        />
      </div>
    </aside>
  );
};
