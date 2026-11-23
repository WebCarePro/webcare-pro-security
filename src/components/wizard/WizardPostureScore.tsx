import React from 'react';
import { ShieldCheck, ShieldAlert, Award } from 'lucide-react';

export interface PostureBreakdown {
  label: string;
  points: number;
  maxPoints: number;
  active: boolean;
}

interface WizardPostureScoreProps {
  score: number; // 0 to 100
  controlsArmed: number;
  breakdown?: PostureBreakdown[];
}

export const WizardPostureScore: React.FC<WizardPostureScoreProps> = ({
  score,
  controlsArmed,
  breakdown = [],
}) => {
  // Clamp score
  const clamped = Math.max(0, Math.min(100, Math.round(score)));

  // Determine Grade & Theme Colors
  let grade = 'C';
  let gradeColor = '#ef4444'; // Red
  let gradeSoft = 'rgba(239, 68, 68, 0.12)';
  let gradeLabel = 'Basic Surface';

  if (clamped >= 90) {
    grade = 'A+';
    gradeColor = '#10b981'; // Emerald
    gradeSoft = 'rgba(16, 185, 129, 0.12)';
    gradeLabel = 'Enterprise Hardened';
  } else if (clamped >= 80) {
    grade = 'A';
    gradeColor = '#0284c7'; // Sky / Blue
    gradeSoft = 'rgba(2, 132, 199, 0.12)';
    gradeLabel = 'Strong Protection';
  } else if (clamped >= 70) {
    grade = 'B';
    gradeColor = '#f59e0b'; // Amber
    gradeSoft = 'rgba(245, 158, 11, 0.12)';
    gradeLabel = 'Moderate Defense';
  }

  // SVG Radial circle math
  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (clamped / 100) * circumference;

  return (
    <div
      style={{
        background: 'var(--webcare-bg-panel, #ffffff)',
        border: '1px solid var(--webcare-border, #e2e8f0)',
        borderRadius: '16px',
        padding: '16px',
        boxShadow: '0 4px 12px rgba(0, 0, 0, 0.04)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
        <span
          style={{
            fontSize: '11px',
            fontWeight: 700,
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            color: 'var(--webcare-text-muted, #64748b)',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <Award size={13} style={{ color: gradeColor }} />
          Security Posture Score
        </span>
        <span
          style={{
            fontSize: '10px',
            fontWeight: 700,
            padding: '2px 8px',
            borderRadius: '9999px',
            background: gradeSoft,
            color: gradeColor,
            border: `1px solid ${gradeColor}33`,
          }}
        >
          Grade {grade}
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        {/* Radial SVG Gauge */}
        <div style={{ position: 'relative', width: '92px', height: '92px', flexShrink: 0 }}>
          <svg width="92" height="92" viewBox="0 0 92 92" style={{ transform: 'rotate(-90deg)' }}>
            {/* Background Track */}
            <circle
              cx="46"
              cy="46"
              r={radius}
              stroke="var(--webcare-border, #e2e8f0)"
              strokeWidth="7"
              fill="transparent"
            />
            {/* Animated Score Progress */}
            <circle
              cx="46"
              cy="46"
              r={radius}
              stroke={gradeColor}
              strokeWidth="7"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              fill="transparent"
              style={{
                transition: 'stroke-dashoffset 0.6s cubic-bezier(0.16, 1, 0.3, 1), stroke 0.4s ease',
              }}
            />
          </svg>
          <div
            style={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              pointerEvents: 'none',
            }}
          >
            <span style={{ fontSize: '20px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)', lineHeight: 1 }}>
              {clamped}
            </span>
            <span style={{ fontSize: '9px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
              / 100
            </span>
          </div>
        </div>

        {/* Telemetry Stats */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '3px' }}>
            {gradeLabel}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', marginBottom: '6px' }}>
            {controlsArmed} controls armed
          </div>
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '4px',
              fontSize: '10px',
              fontWeight: 600,
              color: clamped >= 80 ? '#10b981' : '#f59e0b',
            }}
          >
            {clamped >= 80 ? <ShieldCheck size={12} /> : <ShieldAlert size={12} />}
            {clamped >= 90 ? 'SOC Baseline Ready' : clamped >= 80 ? 'Production Ready' : 'Hardening Suggested'}
          </div>
        </div>
      </div>
    </div>
  );
};
