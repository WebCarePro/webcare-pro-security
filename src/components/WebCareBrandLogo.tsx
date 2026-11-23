import React from 'react';

interface WebCareBrandLogoProps {
  size?: number;
  className?: string;
  style?: React.CSSProperties;
}

export const WebCareBrandLogo: React.FC<WebCareBrandLogoProps> = ({ size = 28, className = '', style = {} }) => {
  return (
    <svg 
      xmlns="http://www.w3.org/2000/svg" 
      viewBox="0 0 100 100" 
      fill="none" 
      role="img" 
      aria-label="WebCare Pro Logo" 
      width={size} 
      height={size}
      className={className}
      style={{ display: 'inline-block', verticalAlign: 'middle', flexShrink: 0, ...style }}
    >
      <defs>
        <linearGradient id="webcareIconGlow" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#3b82f6" />
          <stop offset="50%" stopColor="#06b6d4" />
          <stop offset="100%" stopColor="#10b581" />
        </linearGradient>
        <linearGradient id="shieldIconBg" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#0f172a" />
          <stop offset="100%" stopColor="#030712" />
        </linearGradient>
      </defs>
      <rect width="100" height="100" rx="20" fill="#030712" />
      <path d="M 50 8 L 88 22 C 88 60 70 86 50 96 C 30 86 12 60 12 22 Z" fill="url(#shieldIconBg)" stroke="url(#webcareIconGlow)" strokeWidth="3.5" strokeLinejoin="round" />
      <path d="M 50 16 L 80 27 C 80 56 65 78 50 88 C 35 78 20 56 20 27 Z" fill="none" stroke="#1e293b" strokeWidth="1.5" strokeDasharray="3 3" />
      <rect x="28" y="30" width="44" height="10" rx="2" fill="#0f172a" stroke="#38bdf8" strokeWidth="1.5" />
      <circle cx="34" cy="35" r="1.5" fill="#10b581" />
      <circle cx="40" cy="35" r="1.5" fill="#38bdf8" />
      <rect x="28" y="46" width="44" height="10" rx="2" fill="#0f172a" stroke="#3b82f6" strokeWidth="1.5" />
      <circle cx="34" cy="51" r="1.5" fill="#10b581" />
      <circle cx="40" cy="51" r="1.5" fill="#10b581" />
      <rect x="28" y="62" width="44" height="10" rx="2" fill="#0f172a" stroke="#2563eb" strokeWidth="1.5" />
      <circle cx="34" cy="67" r="1.5" fill="#10b581" />
      <circle cx="40" cy="67" r="1.5" fill="#f59e0b" />
      <path d="M 26 42 L 36 80 L 50 52 L 64 80 L 74 42" fill="none" stroke="url(#webcareIconGlow)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
};

export default WebCareBrandLogo;
