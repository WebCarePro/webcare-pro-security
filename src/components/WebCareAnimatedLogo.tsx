import React from 'react';

interface WebCareAnimatedLogoProps {
  size?: number;
  className?: string;
  style?: React.CSSProperties;
}

export const WebCareAnimatedLogo: React.FC<WebCareAnimatedLogoProps> = ({
  size = 40,
  className = '',
  style = {},
}) => {
  return (
    <div
      className={`webcare-animated-logo-wrapper ${className}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: size,
        height: size,
        flexShrink: 0,
        position: 'relative',
        ...style,
      }}
    >
      <svg
        viewBox="0 0 100 100"
        width={size}
        height={size}
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="webcare-animated-brand-svg"
      >
        <defs>
          <linearGradient id="webcareShieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#4f46e5" />
            <stop offset="50%" stopColor="#06b6d4" />
            <stop offset="100%" stopColor="#10b981" />
          </linearGradient>

          <linearGradient id="webcareCoreGrad" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#0f172a" />
            <stop offset="100%" stopColor="#020617" />
          </linearGradient>

          <radialGradient id="webcareRadarGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.35" />
            <stop offset="100%" stopColor="#06b6d4" stopOpacity="0" />
          </radialGradient>

          <filter id="webcareGlowFilter" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        {/* Ambient Radar Ambient Field */}
        <circle cx="50" cy="50" r="42" fill="url(#webcareRadarGlow)" />

        {/* Outer Hex/Shield Protective Contour */}
        <path
          d="M 50 8 L 86 23 C 86 62 69 87 50 96 C 31 87 14 62 14 23 Z"
          fill="url(#webcareCoreGrad)"
          stroke="url(#webcareShieldGrad)"
          strokeWidth="3.5"
          strokeLinejoin="round"
          className="webcare-svg-shield-contour"
        />

        {/* Inner Cyber Reticle Grid (Dashed) */}
        <path
          d="M 50 16 L 79 28 C 79 58 64 78 50 87 C 36 78 21 58 21 28 Z"
          fill="none"
          stroke="rgba(56, 189, 248, 0.28)"
          strokeWidth="1.5"
          strokeDasharray="4 3"
        />

        {/* Rotating Circular Radar Sweep Ring */}
        <g className="webcare-svg-radar-sweep-group">
          <circle
            cx="50"
            cy="48"
            r="24"
            fill="none"
            stroke="#06b6d4"
            strokeWidth="1.8"
            strokeDasharray="18 12 6 12"
            opacity="0.85"
          />
          <line
            x1="50"
            y1="48"
            x2="50"
            y2="24"
            stroke="#38bdf8"
            strokeWidth="2"
            strokeLinecap="round"
            filter="url(#webcareGlowFilter)"
          />
        </g>

        {/* Cyber Stylized 'W' Signature Armor Wings */}
        <path
          d="M 28 42 L 38 74 L 50 52 L 62 74 L 72 42"
          fill="none"
          stroke="url(#webcareShieldGrad)"
          strokeWidth="3.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          filter="url(#webcareGlowFilter)"
        />

        {/* Central Pulsing Emerald Sentinel Node */}
        <circle
          cx="50"
          cy="52"
          r="4.5"
          fill="#10b981"
          className="webcare-svg-sentinel-pulse"
        />
        <circle
          cx="50"
          cy="52"
          r="9"
          fill="none"
          stroke="#10b981"
          strokeWidth="1.5"
          className="webcare-svg-sentinel-ring"
        />
      </svg>
    </div>
  );
};

export default WebCareAnimatedLogo;
