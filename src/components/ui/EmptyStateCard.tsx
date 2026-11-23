import React from '@wordpress/element';
import { LucideIcon } from 'lucide-react';

export interface EmptyStateCardProps {
  icon: LucideIcon;
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
  actionIcon?: LucideIcon;
  badge?: string;
  badgeType?: 'clean' | 'info' | 'warning' | 'muted';
  style?: React.CSSProperties;
}

export const EmptyStateCard: React.FC<EmptyStateCardProps> = ({
  icon: Icon,
  title,
  description,
  actionLabel,
  onAction,
  actionIcon: ActionIcon,
  badge,
  badgeType = 'clean',
  style,
}) => {
  return (
    <div
      className="webcare-firewall-card"
      style={{
        padding: '48px 24px',
        textAlign: 'center',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'var(--webcare-bg-surface, #ffffff)',
        border: '1px dashed var(--webcare-border, #e2e8f0)',
        borderRadius: '12px',
        margin: '16px 0',
        ...style,
      }}
    >
      <div
        style={{
          width: '52px',
          height: '52px',
          borderRadius: '50%',
          background: 'rgba(16, 185, 129, 0.1)',
          color: '#10b981',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          marginBottom: '16px',
        }}
      >
        <Icon size={26} />
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
        <h4
          style={{
            margin: 0,
            fontSize: '16px',
            fontWeight: 700,
            color: 'var(--webcare-text-title, #0f172a)',
          }}
        >
          {title}
        </h4>
        {badge && (
          <span className={`webcare-badge-pill webcare-badge-${badgeType}`} style={{ fontSize: '11px', padding: '1px 7px' }}>
            {badge}
          </span>
        )}
      </div>

      <p
        style={{
          margin: 0,
          maxWidth: '460px',
          fontSize: '13.5px',
          lineHeight: 1.5,
          color: 'var(--webcare-text-secondary, #64748b)',
        }}
      >
        {description}
      </p>

      {actionLabel && onAction && (
        <button
          type="button"
          onClick={onAction}
          className="webcare-btn webcare-btn-primary"
          style={{
            marginTop: '20px',
            fontSize: '13px',
            padding: '8px 18px',
            borderRadius: '6px',
            fontWeight: 600,
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          {ActionIcon && <ActionIcon size={14} />}
          <span>{actionLabel}</span>
        </button>
      )}
    </div>
  );
};
